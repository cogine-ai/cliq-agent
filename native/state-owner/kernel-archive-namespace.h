/* Included by kernel-archive.c after its fixed original-holder helpers.
 * This captures the actual flat installed CAS, including unreferenced and
 * interrupted objects. A filename never grants execution or deletion rights.
 * Each call performs bounded bookkeeping or at most one 64 KiB byte step;
 * real fsync latency and Stop2 still require physical qualification. */
#include <math.h>
#define KANS_MAX_ENTRIES 1048576U
#define KANS_METADATA_BYTES UINT64_C(268435456)
#define KANS_CHUNK 65536U
enum kans_phase { KANS_SCAN, KANS_HEAP, KANS_SORT, KANS_NAMES, KANS_COPY,
    KANS_SOURCE_SCAN, KANS_ARCHIVE_SCAN, KANS_COMPLETE, KANS_MANIFEST_WRITE,
    KANS_MANIFEST_READ_ONE, KANS_MANIFEST_READ_TWO, KANS_MANIFEST_COMPLETE };
enum kans_kind { KANS_PUBLISHED, KANS_TEMPORARY_STREAM, KANS_TEMPORARY_REF };
typedef struct kans_entry {
    char name[104], digest[65];
    uint64_t source_inode, archive_inode, byte_count;
    int64_t mtime_seconds, ctime_seconds, archive_ctime_seconds;
    uint32_t mtime_nanos, ctime_nanos, archive_ctime_nanos;
    uint16_t mode;
    unsigned char kind, seen;
} kans_entry;
_Static_assert(sizeof(kans_entry) * (uint64_t)KANS_MAX_ENTRIES <= KANS_METADATA_BYTES - 2 * KANS_CHUNK,
    "fixed complete CAS entry index exceeds its metadata ceiling");
struct kernel_archive_namespace {
    int source_fd, archive_fd, current_source_fd, current_archive_fd, manifest_fd;
    DIR *scan;
    struct stat source, archive, source_file, archive_file, manifest_file;
    kans_entry *entries;
    size_t count, index, heap_index, heap_end, checked;
    uint64_t byte_count, offset, manifest_size;
    enum kans_phase phase;
    int copy_phase, manifest_readonly;
    struct sha256_context hash, entries_hash;
    char entries_digest[65], manifest_digest[65];
    napi_ref manifest_ref;
    const unsigned char *manifest_bytes;
};
static const char *kans_kind_text(unsigned char kind) {
    return kind == KANS_PUBLISHED ? "published" : kind == KANS_TEMPORARY_STREAM ? "temporary_stream" : "temporary_ref";
}
static int kans_hex(const char *text, size_t count) {
    for (size_t index = 0; index < count; ++index)
        if (!((text[index] >= '0' && text[index] <= '9') || (text[index] >= 'a' && text[index] <= 'f'))) return 0;
    return 1;
}
static int kans_name(const char *name) {
    size_t size = strlen(name);
    if (size == 64 && kans_hex(name, 64)) return KANS_PUBLISHED;
    if (size == 44 && !memcmp(name, ".tmp-stream-", 12) && kans_hex(name + 12, 32)) return KANS_TEMPORARY_STREAM;
    if (size == 102 && !memcmp(name, ".tmp-", 5) && kans_hex(name + 5, 64) && name[69] == '-' && kans_hex(name + 70, 32))
        return KANS_TEMPORARY_REF;
    return -1;
}
static void kans_times(kans_entry *entry, const struct stat *observed) {
#ifdef __APPLE__
    entry->mtime_seconds = observed->st_mtimespec.tv_sec; entry->mtime_nanos = (uint32_t)observed->st_mtimespec.tv_nsec;
    entry->ctime_seconds = observed->st_ctimespec.tv_sec; entry->ctime_nanos = (uint32_t)observed->st_ctimespec.tv_nsec;
#else
    entry->mtime_seconds = observed->st_mtim.tv_sec; entry->mtime_nanos = (uint32_t)observed->st_mtim.tv_nsec;
    entry->ctime_seconds = observed->st_ctim.tv_sec; entry->ctime_nanos = (uint32_t)observed->st_ctim.tv_nsec;
#endif
}
static int kans_source_file(kernel_archive *held, const struct stat *observed, int kind) {
    mode_t mode = observed->st_mode & 07777;
    return S_ISREG(observed->st_mode) && observed->st_dev == held->root.st_dev && observed->st_uid == held->uid &&
        observed->st_gid == held->gid && observed->st_nlink == 1 && observed->st_size >= 0 &&
        (uint64_t)observed->st_size <= KERNEL_ARCHIVE_MAX_BYTES &&
        (mode == 0400 || (kind == KANS_TEMPORARY_STREAM && mode == 0600));
}
static int kans_source_same(kernel_archive *held, const kans_entry *entry, const struct stat *observed) {
    kans_entry current = {0};
    kans_times(&current, observed);
    return kans_source_file(held, observed, entry->kind) && (uint64_t)observed->st_ino == entry->source_inode &&
        (uint64_t)observed->st_size == entry->byte_count && (observed->st_mode & 07777) == entry->mode &&
        current.mtime_seconds == entry->mtime_seconds && current.mtime_nanos == entry->mtime_nanos &&
        current.ctime_seconds == entry->ctime_seconds && current.ctime_nanos == entry->ctime_nanos;
}
static void kans_archive_time(kans_entry *entry, const struct stat *observed) {
#ifdef __APPLE__
    entry->archive_ctime_seconds = observed->st_ctimespec.tv_sec;
    entry->archive_ctime_nanos = (uint32_t)observed->st_ctimespec.tv_nsec;
#else
    entry->archive_ctime_seconds = observed->st_ctim.tv_sec;
    entry->archive_ctime_nanos = (uint32_t)observed->st_ctim.tv_nsec;
#endif
}
static int kans_archive_same(kernel_archive *held, const kans_entry *entry, const struct stat *observed) {
    kans_entry current = {0}; kans_archive_time(&current, observed);
    return ka_regular(held, observed, 0400) && observed->st_dev == held->root.st_dev &&
        (uint64_t)observed->st_ino == entry->archive_inode && (uint64_t)observed->st_size == entry->byte_count &&
        current.archive_ctime_seconds == entry->archive_ctime_seconds && current.archive_ctime_nanos == entry->archive_ctime_nanos;
}
static int kans_custody(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    struct stat observed;
    if (!space) return 0;
    if (space->source_fd >= 0 && (!ka_named_directory(held, held->root_fd, "cas", space->source_fd, &space->source) ||
        fstat(space->source_fd, &observed) != 0 || !source_metadata_same(&observed, &space->source))) return -1;
    if (space->archive_fd >= 0 && !ka_named_directory(held, held->directory_fd, "cas", space->archive_fd, &space->archive)) return -1;
    if (space->phase >= KANS_COMPLETE && space->archive_fd >= 0 &&
        (fstat(space->archive_fd, &observed) != 0 || !source_metadata_same(&observed, &space->archive))) return -1;
    if (space->manifest_fd >= 0 && space->manifest_readonly &&
        !ka_named_file(held, held->directory_fd, "manifest-v1.json", space->manifest_fd, &space->manifest_file, 0400, 1)) return -1;
    return 0;
}
static int kans_close_scan(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    DIR *original = space->scan;
    space->scan = NULL;
    if (!original || closedir(original) == 0) return 0;
    ka_uncertain(held);
    return -1;
}
static int kans_open_scan(kernel_archive *held, int descriptor) {
    kernel_archive_namespace *space = held->cas;
    int fd = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    space->scan = fdopendir(fd);
    if (space->scan) return 0;
    (void)ka_close_fd(held, &fd);
    return -1;
}
static int kans_retire(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    if (!space) return 0;
    int failed = kans_close_scan(held) != 0;
    int *const descriptors[] = {&space->current_source_fd, &space->current_archive_fd,
        &space->manifest_fd, &space->source_fd, &space->archive_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (ka_close_fd(held, descriptors[index]) != 0) failed = 1;
    if (space->manifest_ref) {
        napi_ref original = space->manifest_ref; space->manifest_ref = NULL; space->manifest_bytes = NULL;
        if (napi_delete_reference(held->env, original) != napi_ok) { ka_main_poison(held); failed = 1; }
    }
    if (failed || atomic_load(&held->uncertain)) return -1;
    free(space->entries); free(space); held->cas = NULL;
    return 0;
}
static napi_value kans_begin(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int born = 0;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->cas && held->readonly &&
        !held->failed && !atomic_load(&held->cancelled) && !kernel_archive_active && ka_control_bytes(held, NULL) == 0;
    if (valid) {
        held->cas = calloc(1, sizeof(*held->cas));
        valid = held->cas != NULL; born = valid;
    }
    if (valid) {
        kernel_archive_namespace *space = held->cas;
        space->source_fd = space->archive_fd = space->current_source_fd = space->current_archive_fd = space->manifest_fd = -1;
        space->source_fd = openat(held->root_fd, "cas", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = space->source_fd >= 0 && fstat(space->source_fd, &space->source) == 0 &&
            ka_directory(held, &space->source) && space->source.st_dev == held->root.st_dev &&
            ka_hold_directory(held, held->directory_fd, "cas", &space->archive_fd, &space->archive, 1) == 0 &&
            space->archive.st_dev == held->root.st_dev && !same_inode(&space->source, &space->archive);
        if (valid) { space->entries = calloc(KANS_MAX_ENTRIES, sizeof(*space->entries)); valid = space->entries != NULL; }
        if (valid) valid = kans_open_scan(held, space->source_fd) == 0 && kans_custody(held) == 0;
        if (valid) { space->phase = KANS_SCAN; sha256_init(&space->entries_hash); }
    }
    if (!valid && born) {
        held->failed = 1;
        if (kans_retire(held) != 0) ka_main_poison(held);
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "complete CAS capture requires the original sealed image and unused fixed private destination");
}
static void kans_swap(kans_entry *left, kans_entry *right) { kans_entry temporary = *left; *left = *right; *right = temporary; }
/* One sift is bounded by log2(KANS_MAX_ENTRIES), with no second full index. */
static void kans_sift(kernel_archive_namespace *space, size_t root, size_t count) {
    while (root < count / 2) {
        size_t child = root * 2 + 1;
        if (child + 1 < count && strcmp(space->entries[child].name, space->entries[child + 1].name) < 0) child++;
        if (strcmp(space->entries[root].name, space->entries[child].name) >= 0) break;
        kans_swap(&space->entries[root], &space->entries[child]); root = child;
    }
}
static kans_entry *kans_find(kernel_archive_namespace *space, const char *name) {
    size_t first = 0, end = space->count;
    while (first < end) {
        size_t middle = first + (end - first) / 2;
        int comparison = strcmp(name, space->entries[middle].name);
        if (!comparison) return &space->entries[middle];
        if (comparison < 0) end = middle; else first = middle + 1;
    }
    return NULL;
}
static int kans_scan_step(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    for (size_t step = 0; step < 64; ++step) {
        errno = 0;
        struct dirent *item = readdir(space->scan);
        if (!item) {
            if (errno || kans_close_scan(held) != 0 || kans_custody(held) != 0) return -1;
            space->phase = KANS_HEAP; space->heap_index = space->count / 2; space->heap_end = space->count;
            return 0;
        }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        int kind = kans_name(item->d_name);
        struct stat observed;
        if (kind < 0 || space->count >= KANS_MAX_ENTRIES ||
            fstatat(space->source_fd, item->d_name, &observed, AT_SYMLINK_NOFOLLOW) != 0 ||
            !kans_source_file(held, &observed, kind) ||
            (uint64_t)observed.st_size > KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - space->byte_count) return -1;
        kans_entry *entry = &space->entries[space->count++];
        strcpy(entry->name, item->d_name); entry->kind = (unsigned char)kind;
        entry->source_inode = (uint64_t)observed.st_ino; entry->byte_count = (uint64_t)observed.st_size;
        entry->mode = (uint16_t)(observed.st_mode & 07777); kans_times(entry, &observed);
        space->byte_count += entry->byte_count;
    }
    return 0;
}
static int kans_entry_custody(kernel_archive *held, const kans_entry *entry) {
    kernel_archive_namespace *space = held->cas;
    struct stat observed, named;
    return fstat(space->current_source_fd, &observed) == 0 && kans_source_same(held, entry, &observed) &&
        fstatat(space->source_fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&observed, &named) &&
        fstat(space->current_archive_fd, &observed) == 0 && ka_regular(held, &observed, space->copy_phase ? 0400 : 0600) &&
        observed.st_dev == held->root.st_dev && same_inode(&observed, &space->archive_file) &&
        (!space->copy_phase || kans_archive_same(held, entry, &observed)) &&
        fstatat(space->archive_fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&observed, &named);
}
static int kans_read_step(int descriptor, uint64_t size, uint64_t *offset, struct sha256_context *hash,
                          unsigned char *bytes, size_t *amount) {
    uint64_t remaining = size - *offset;
    *amount = remaining < KANS_CHUNK ? (size_t)remaining : KANS_CHUNK;
    size_t consumed = 0;
    while (consumed < *amount) {
        ssize_t count = pread(descriptor, bytes + consumed, *amount - consumed, (off_t)(*offset + consumed));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > *amount - consumed) return -1;
        consumed += (size_t)count;
    }
    sha256_update(hash, bytes, *amount); *offset += *amount;
    if (*offset != size) return 0;
    ssize_t count;
    do { count = pread(descriptor, bytes, 1, (off_t)*offset); } while (count < 0 && errno == EINTR);
    return count == 0 ? 1 : -1;
}
static int kans_write(int descriptor, const unsigned char *bytes, size_t amount, uint64_t offset) {
    size_t consumed = 0;
    while (consumed < amount) {
        ssize_t count = pwrite(descriptor, bytes + consumed, amount - consumed, (off_t)(offset + consumed));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > amount - consumed) return -1;
        consumed += (size_t)count;
    }
    return 0;
}
static int kans_copy_step(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    if (space->index == space->count) {
        struct sha256_context hash = space->entries_hash;
        publication_hash_hex(&hash, space->entries_digest);
        if (fsync(space->archive_fd) != 0 || fsync(held->directory_fd) != 0 ||
            kans_open_scan(held, space->source_fd) != 0) return -1;
        space->phase = KANS_SOURCE_SCAN; space->checked = 0;
        return 0;
    }
    kans_entry *entry = &space->entries[space->index];
    if (space->current_source_fd < 0) {
        space->current_source_fd = openat(space->source_fd, entry->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (space->current_source_fd < 0 || fstat(space->current_source_fd, &space->source_file) != 0 ||
            !kans_source_same(held, entry, &space->source_file)) return -1;
        space->current_archive_fd = openat(space->archive_fd, entry->name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (space->current_archive_fd < 0 || fstat(space->current_archive_fd, &space->archive_file) != 0 ||
            !ka_regular(held, &space->archive_file, 0600) || space->archive_file.st_size ||
            space->archive_file.st_dev != held->root.st_dev || same_inode(&space->source_file, &space->archive_file)) return -1;
        entry->archive_inode = (uint64_t)space->archive_file.st_ino;
        space->copy_phase = 0; space->offset = 0; sha256_init(&space->hash);
    }
    if (!kans_entry_custody(held, entry)) return -1;
    unsigned char bytes[KANS_CHUNK]; size_t amount;
    uint64_t before = space->offset;
    int complete = kans_read_step(space->copy_phase == 2 ? space->current_archive_fd : space->current_source_fd,
        entry->byte_count, &space->offset, &space->hash, bytes, &amount);
    if (complete < 0 || (!space->copy_phase && kans_write(space->current_archive_fd, bytes, amount, before) != 0) ||
        !kans_entry_custody(held, entry)) return -1;
    if (!complete) return 0;
    char digest[65]; struct sha256_context hash = space->hash; publication_hash_hex(&hash, digest);
    if (!space->copy_phase) {
        if ((entry->kind == KANS_PUBLISHED && memcmp(entry->name, digest, 64)) ||
            (entry->kind == KANS_TEMPORARY_REF && memcmp(entry->name + 5, digest, 64))) return -1;
        strcpy(entry->digest, digest);
        if (fsync(space->current_archive_fd) != 0 || fchmod(space->current_archive_fd, 0400) != 0 ||
            fsync(space->current_archive_fd) != 0 || fsync(space->archive_fd) != 0) return -1;
        int readonly = openat(space->archive_fd, entry->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat observed;
        if (readonly < 0) return -1;
        int valid = fstat(readonly, &observed) == 0 && ka_regular(held, &observed, 0400) &&
            same_inode(&observed, &space->archive_file) && (uint64_t)observed.st_size == entry->byte_count;
        if (!valid) { (void)ka_close_fd(held, &readonly); return -1; }
        int writable = space->current_archive_fd; space->current_archive_fd = readonly; space->archive_file = observed;
        kans_archive_time(entry, &observed);
        if (ka_close_fd(held, &writable) != 0) return -1;
        space->copy_phase = 1;
    } else {
        if (strcmp(digest, entry->digest)) return -1;
        if (space->copy_phase == 1) space->copy_phase = 2;
        else {
            char count[32]; int size = snprintf(count, sizeof(count), "%llu\n", (unsigned long long)entry->byte_count);
            if (size <= 0 || (size_t)size >= sizeof(count)) return -1;
            sha256_update(&space->entries_hash, (const uint8_t *)entry->name, strlen(entry->name) + 1);
            const char *kind = kans_kind_text(entry->kind);
            sha256_update(&space->entries_hash, (const uint8_t *)kind, strlen(kind) + 1);
            sha256_update(&space->entries_hash, (const uint8_t *)entry->digest, 65);
            sha256_update(&space->entries_hash, (const uint8_t *)count, (size_t)size);
            if (ka_close_fd(held, &space->current_source_fd) != 0 || ka_close_fd(held, &space->current_archive_fd) != 0) return -1;
            space->index++;
        }
    }
    space->offset = 0; sha256_init(&space->hash);
    return 0;
}
static int kans_final_scan_step(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    int source = space->phase == KANS_SOURCE_SCAN;
    for (size_t step = 0; step < 64; ++step) {
        errno = 0; struct dirent *item = readdir(space->scan);
        if (!item) {
            if (errno || space->checked != space->count || kans_close_scan(held) != 0) return -1;
            if (source) {
                if (kans_open_scan(held, space->archive_fd) != 0) return -1;
                space->phase = KANS_ARCHIVE_SCAN; space->checked = 0;
            } else {
                if (fsync(space->archive_fd) != 0 || fsync(held->directory_fd) != 0 ||
                    fstat(space->archive_fd, &space->archive) != 0 || kans_custody(held) != 0) return -1;
                space->phase = KANS_COMPLETE;
            }
            return 0;
        }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        kans_entry *entry = kans_find(space, item->d_name);
        struct stat observed;
        unsigned char expected_seen = source ? 0 : 1;
        if (!entry || entry->seen != expected_seen ||
            fstatat(source ? space->source_fd : space->archive_fd, item->d_name, &observed, AT_SYMLINK_NOFOLLOW) != 0 ||
            (source ? !kans_source_same(held, entry, &observed) : !kans_archive_same(held, entry, &observed))) return -1;
        entry->seen++; space->checked++;
    }
    return 0;
}
static napi_value kans_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space &&
        !held->failed && !atomic_load(&held->cancelled) && space->phase <= KANS_COMPLETE;
    if (valid) {
        int result = 0;
        switch (space->phase) {
            case KANS_SCAN: result = kans_scan_step(held); break;
            case KANS_HEAP:
                for (size_t count = 0; count < 64 && space->heap_index; ++count)
                    kans_sift(space, --space->heap_index, space->count);
                if (!space->heap_index) space->phase = KANS_SORT;
                break;
            case KANS_SORT:
                for (size_t count = 0; count < 64 && space->heap_end > 1; ++count) {
                    kans_swap(&space->entries[0], &space->entries[--space->heap_end]); kans_sift(space, 0, space->heap_end);
                }
                if (space->heap_end <= 1) { space->phase = KANS_NAMES; space->index = 0; }
                break;
            case KANS_NAMES:
                for (size_t count = 0; count < 64 && space->index < space->count; ++count, ++space->index)
                    if (space->index && strcmp(space->entries[space->index - 1].name, space->entries[space->index].name) >= 0) result = -1;
                if (space->index == space->count) { space->phase = KANS_COPY; space->index = 0; }
                break;
            case KANS_COPY: result = kans_copy_step(held); break;
            case KANS_SOURCE_SCAN: case KANS_ARCHIVE_SCAN: result = kans_final_scan_step(held); break;
            case KANS_COMPLETE: break;
            default: result = -1; break;
        }
        valid = result == 0 && kans_custody(held) == 0;
    }
    if (!valid) held->failed = 1;
    int complete = valid && space->phase == KANS_COMPLETE;
    pthread_mutex_unlock(&kernel_archive_mutex);
    napi_value result;
    return !valid ? ka_error(env, held, "complete CAS capture changed, exceeded its fixed bounds, or did not join") :
        napi_get_boolean(env, complete != 0, &result) == napi_ok ? result : NULL;
}
static napi_value kans_identity(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space &&
        space->phase >= KANS_COMPLETE && !held->failed && !atomic_load(&held->cancelled);
    napi_value result = NULL;
    if (valid && (napi_create_object(env, &result) != napi_ok ||
        !ka_string_member(env, result, "layout", "cliq-flat-cas-v1") ||
        !identity_member(env, result, "sourceDirectory", &space->source) ||
        !identity_member(env, result, "archiveDirectory", &space->archive) ||
        !ka_count_member(env, result, "entryCount", space->count) ||
        !ka_count_member(env, result, "totalBytes", space->byte_count) ||
        !ka_count_member(env, result, "combinedPayloadBytes", held->byte_count + space->byte_count) ||
        !ka_string_member(env, result, "entriesDigest", space->entries_digest) || napi_object_freeze(env, result) != napi_ok)) result = NULL;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "complete CAS identity requires all-and-only original capture and full joined byte verification");
}
static napi_value kans_entries(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2], self; bool tagged = false; kernel_archive *held = NULL;
    double start;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, &self, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, self, &kernel_archive_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&held) != napi_ok || !ka_main_context(held, env) ||
        napi_get_value_double(env, arguments[0], &start) != napi_ok || !isfinite(start) || start < 0 ||
        start > KANS_MAX_ENTRIES || start != (double)(size_t)start)
        return ka_error(env, NULL, "CAS entry page requires one fixed numeric offset");
    if (ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space && space->phase == KANS_COMPLETE &&
        space->entries && (size_t)start <= space->count && !held->failed && !atomic_load(&held->cancelled);
    napi_value result = NULL;
    if (valid) {
        size_t length = space->count - (size_t)start; if (length > 64) length = 64;
        valid = napi_create_array_with_length(env, length, &result) == napi_ok;
        for (size_t index = 0; valid && index < length; ++index) {
            const kans_entry *entry = &space->entries[(size_t)start + index]; napi_value value;
            valid = napi_create_object(env, &value) == napi_ok && ka_string_member(env, value, "name", entry->name) &&
                ka_string_member(env, value, "kind", kans_kind_text(entry->kind)) && ka_string_member(env, value, "sha256", entry->digest) &&
                ka_count_member(env, value, "byteCount", entry->byte_count) && ka_count_member(env, value, "sourceMode", entry->mode) &&
                decimal_member(env, value, "sourceFileId", entry->source_inode) && decimal_member(env, value, "archiveFileId", entry->archive_inode) &&
                napi_object_freeze(env, value) == napi_ok && napi_set_element(env, result, (uint32_t)index, value) == napi_ok;
        }
        if (valid) valid = napi_object_freeze(env, result) == napi_ok;
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "CAS entry pages require the same complete capture before manifest handoff");
}
static napi_value kans_begin_manifest(napi_env env, napi_callback_info info) {
    size_t count = 2, size = 0; napi_value arguments[2], self; bool tagged = false, buffer = false;
    kernel_archive *held = NULL; void *bytes = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, &self, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, self, &kernel_archive_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&held) != napi_ok || !ka_main_context(held, env) ||
        napi_is_buffer(env, arguments[0], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, arguments[0], &bytes, &size) != napi_ok || !size || size > KANS_METADATA_BYTES)
        return ka_error(env, NULL, "archive manifest requires one complete bounded data buffer");
    if (ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space && space->phase == KANS_COMPLETE &&
        space->entries && !held->failed && !atomic_load(&held->cancelled) &&
        size <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - space->byte_count &&
        ka_control_bytes(held, NULL) == 0;
    if (valid) valid = napi_create_reference(env, arguments[0], 1, &space->manifest_ref) == napi_ok;
    if (valid) {
        space->manifest_bytes = bytes; space->manifest_size = size;
        space->manifest_fd = openat(held->directory_fd, "manifest-v1.json", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        valid = space->manifest_fd >= 0 && fstat(space->manifest_fd, &space->manifest_file) == 0 &&
            ka_regular(held, &space->manifest_file, 0600) && space->manifest_file.st_dev == held->root.st_dev && !space->manifest_file.st_size;
    }
    if (valid) {
        free(space->entries); space->entries = NULL; space->offset = 0;
        sha256_init(&space->hash); space->phase = KANS_MANIFEST_WRITE;
    } else if (space && space->manifest_ref) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "fixed archive manifest cannot exceed the original combined archive ceiling or replace an old birth");
}
static int kans_manifest_step(kernel_archive *held) {
    kernel_archive_namespace *space = held->cas;
    unsigned char bytes[KANS_CHUNK];
    if (space->phase == KANS_MANIFEST_WRITE) {
        uint64_t remaining = space->manifest_size - space->offset;
        size_t amount = remaining < KANS_CHUNK ? (size_t)remaining : KANS_CHUNK;
        struct stat observed, named;
        if (fstat(space->manifest_fd, &observed) != 0 || !ka_regular(held, &observed, 0600) ||
            !same_inode(&observed, &space->manifest_file) || (uint64_t)observed.st_size != space->offset ||
            fstatat(held->directory_fd, "manifest-v1.json", &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&observed, &named)) return -1;
        /* Copy this bounded slice once, then hash exactly the bytes written. */
        memcpy(bytes, space->manifest_bytes + space->offset, amount);
        if (kans_write(space->manifest_fd, bytes, amount, space->offset) != 0) return -1;
        sha256_update(&space->hash, bytes, amount); space->offset += amount;
        if (space->offset != space->manifest_size) return 0;
        struct sha256_context hash = space->hash; publication_hash_hex(&hash, space->manifest_digest);
        if (fsync(space->manifest_fd) != 0 || fchmod(space->manifest_fd, 0400) != 0 ||
            fsync(space->manifest_fd) != 0 || fsync(held->directory_fd) != 0) return -1;
        int readonly = openat(held->directory_fd, "manifest-v1.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (readonly < 0) return -1;
        int valid = fstat(readonly, &observed) == 0 && ka_regular(held, &observed, 0400) &&
            same_inode(&observed, &space->manifest_file) && (uint64_t)observed.st_size == space->manifest_size;
        if (!valid) { (void)ka_close_fd(held, &readonly); return -1; }
        int writable = space->manifest_fd; space->manifest_fd = readonly; space->manifest_file = observed; space->manifest_readonly = 1;
        if (ka_close_fd(held, &writable) != 0) return -1;
        napi_ref original = space->manifest_ref; space->manifest_ref = NULL; space->manifest_bytes = NULL;
        if (napi_delete_reference(held->env, original) != napi_ok) { ka_main_poison(held); return -1; }
        space->phase = KANS_MANIFEST_READ_ONE;
    } else {
        size_t amount;
        int complete = kans_read_step(space->manifest_fd, space->manifest_size, &space->offset, &space->hash, bytes, &amount);
        if (complete < 0) return -1;
        if (!complete) return 0;
        char digest[65]; struct sha256_context hash = space->hash; publication_hash_hex(&hash, digest);
        if (strcmp(digest, space->manifest_digest)) return -1;
        space->phase = space->phase == KANS_MANIFEST_READ_ONE ? KANS_MANIFEST_READ_TWO : KANS_MANIFEST_COMPLETE;
        if (space->phase == KANS_MANIFEST_COMPLETE && (fsync(held->directory_fd) != 0 || ka_control_bytes(held, NULL) != 0)) return -1;
    }
    space->offset = 0; sha256_init(&space->hash);
    return 0;
}
static napi_value kans_manifest_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space &&
        space->phase >= KANS_MANIFEST_WRITE && !held->failed && !atomic_load(&held->cancelled);
    if (valid && space->phase != KANS_MANIFEST_COMPLETE) valid = kans_manifest_step(held) == 0 && kans_custody(held) == 0;
    if (!valid) held->failed = 1;
    int complete = valid && space->phase == KANS_MANIFEST_COMPLETE;
    pthread_mutex_unlock(&kernel_archive_mutex);
    napi_value result;
    return !valid ? ka_error(env, held, "archive manifest full-byte original readonly sealing did not complete") :
        napi_get_boolean(env, complete != 0, &result) == napi_ok ? result : NULL;
}
static napi_value kans_manifest_identity(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && space &&
        space->phase == KANS_MANIFEST_COMPLETE && !held->failed && !atomic_load(&held->cancelled);
    napi_value result = NULL;
    if (valid && (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "file", &space->manifest_file) ||
        !ka_string_member(env, result, "sha256", space->manifest_digest) || !ka_count_member(env, result, "byteCount", space->manifest_size) ||
        napi_object_freeze(env, result) != napi_ok)) result = NULL;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "archive manifest identity requires complete physical readonly sealing");
}
