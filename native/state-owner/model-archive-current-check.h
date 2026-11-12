/* C-private readonly current-checking mechanism shared by the genuine original
 * archive producer and the distinct current migration inspector. Parents own
 * their real binding/Root/archive directory and the genuine model visitor.
 * This helper owns only newly opened readonly target descriptions. It never
 * opens a pager, adopts an old holder, creates a path, or publishes authority. */
#ifndef CLIQ_MODEL_ARCHIVE_CURRENT_CHECK_H
#define CLIQ_MODEL_ARCHIVE_CURRENT_CHECK_H
#include "local-model-store-archive.h"
#define MAC_RECORD_BYTES 192U
#define MAC_HEADER_BYTES 64U
#define MAC_MAX_ENTRIES 1048579U
#define MAC_FIXED_METADATA (1024U * 1024U)
typedef struct ma_model_witness {
    uint64_t source_device, source_inode, source_objects_device, source_objects_inode;
    uint64_t target_device, target_inode, target_objects_device, target_objects_inode;
    uint64_t inventory_device, inventory_inode, count, byte_count, inventory_size;
    uint32_t uid;
    char inventory_digest[65];
} ma_model_witness;
typedef struct ma_model_record {
    char path[96], digest[65];
    uint64_t source_device, source_inode, target_device, target_inode, byte_count;
    int64_t source_ctime_seconds;
    uint32_t source_ctime_nanos, uid, mode;
    unsigned char kind;
} ma_model_record;
enum ma_model_phase { MAC_INVENTORY, MAC_HEADER, MAC_SOURCE, MAC_TARGET_ROOT,
    MAC_TARGET_OBJECTS, MAC_FINAL_SOURCE, MAC_FINAL_ROOT, MAC_FINAL_OBJECTS, MAC_COMPLETE };
typedef struct ma_model_checker {
    napi_env env;
    migration_credential_gate *binding; /* parent guarantees real lifetime */
    cliq_model_store_archive *source;   /* borrowed, no second begin/SH/pager */
    int parent_fd, store_fd, objects_fd, inventory_fd, inventory_reader, current_fd, source_active;
    struct stat parent, store, objects, inventory, current;
    ma_model_witness expected;
    ma_model_record record;
    uint64_t offset, source_count, source_bytes, target_count, target_bytes, final_count, final_source_count;
    size_t record_index;
    struct sha256_context hash;
    enum ma_model_phase phase;
    DIR *scan;
    unsigned char *seen; /* two bits/entry: source, target; final consumes target */
    int64_t *target_ctime_seconds;
    uint32_t *target_ctime_nanos;
    size_t metadata_bytes;
    unsigned int root_seen;
    int uncertain, failed;
} ma_model_checker;
static uint32_t ma_u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t ma_u64(const unsigned char *p) { return (uint64_t)ma_u32(p) | (uint64_t)ma_u32(p + 4) << 32; }
static uint64_t ma_device(const struct stat *identity) {
#ifdef __APPLE__
    return (uint32_t)identity->st_dev;
#else
    return (uint64_t)identity->st_dev;
#endif
}
static void ma_times(const struct stat *identity, int64_t *seconds, uint32_t *nanos) {
#ifdef __APPLE__
    *seconds = identity->st_ctimespec.tv_sec; *nanos = (uint32_t)identity->st_ctimespec.tv_nsec;
#else
    *seconds = identity->st_ctim.tv_sec; *nanos = (uint32_t)identity->st_ctim.tv_nsec;
#endif
}
static int ma_close_fd(ma_model_checker *checker, int *fd) {
    int original = *fd; *fd = -1;
    if (original < 0 || close(original) == 0) return 0;
    checker->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return -1;
}
static int ma_close_scan(ma_model_checker *checker) {
    DIR *original = checker->scan; checker->scan = NULL;
    if (!original || closedir(original) == 0) return 0;
    checker->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return -1;
}
static int ma_regular(const ma_model_checker *checker, const struct stat *identity) {
    return S_ISREG(identity->st_mode) && identity->st_uid == checker->expected.uid && identity->st_gid == getegid() &&
        (identity->st_mode & 07777) == 0400 && identity->st_nlink == 1 && identity->st_size >= 0 &&
        ma_device(identity) == checker->expected.target_device;
}
static int ma_named_directory(int parent, const char *name, int fd, const struct stat *identity, int stable) {
    struct stat actual, named;
    return fd >= 0 && fstat(fd, &actual) == 0 && private_directory(&actual) && same_inode(&actual, identity) &&
        (!stable || source_metadata_same(&actual, identity)) && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        source_metadata_same(&actual, &named);
}
static int ma_named_inventory(const ma_model_checker *checker) {
    struct stat actual, named;
    return checker->inventory_fd >= 0 && fstat(checker->inventory_fd, &actual) == 0 && ma_regular(checker, &actual) &&
        source_metadata_same(&actual, &checker->inventory) &&
        fstatat(checker->store_fd, "inventory-v1.bin", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&actual, &named);
}
/* Worker-safe actual observations only; no NAPI, NSS, clock or mutable Owner
 * authority is inspected here. Parent mutex/lifetime guarantees FD retention. */
static int ma_target_custody(const ma_model_checker *checker) {
    struct stat parent;
    return checker && !checker->uncertain &&
        fstat(checker->parent_fd, &parent) == 0 && private_directory(&parent) && same_inode(&parent, &checker->parent) &&
        ma_named_directory(checker->parent_fd, "local-models", checker->store_fd, &checker->store, 1) &&
        ma_named_directory(checker->store_fd, "objects", checker->objects_fd, &checker->objects, 1) && ma_named_inventory(checker);
}
static int ma_custody(const ma_model_checker *checker) {
    return ma_target_custody(checker) && checker->source && cliq_model_store_archive_assert(checker->source) == 0;
}
static int ma_hex(const char *name, size_t count) {
    for (size_t index = 0; index < count; ++index)
        if (!((name[index] >= '0' && name[index] <= '9') || (name[index] >= 'a' && name[index] <= 'f'))) return 0;
    return 1;
}
static int ma_decode_record(const unsigned char bytes[MAC_RECORD_BYTES], ma_model_record *record) {
    memset(record, 0, sizeof(*record));
    size_t length = 0; while (length < 96 && bytes[length]) { if (bytes[length] > 127) return -1; length++; }
    if (!length || length >= 96 || bytes[99] || ma_u32(bytes + 188)) return -1;
    for (size_t index = length; index < 96; ++index) if (bytes[index]) return -1;
    memcpy(record->path, bytes, length); record->kind = bytes[96]; record->mode = (uint32_t)bytes[97] | (uint32_t)bytes[98] << 8;
    record->uid = ma_u32(bytes + 100); record->source_inode = ma_u64(bytes + 104); record->target_inode = ma_u64(bytes + 112);
    record->byte_count = ma_u64(bytes + 120); record->source_device = ma_u64(bytes + 160); record->target_device = ma_u64(bytes + 168);
    uint64_t raw_seconds = ma_u64(bytes + 176); memcpy(&record->source_ctime_seconds, &raw_seconds, sizeof(raw_seconds));
    record->source_ctime_nanos = ma_u32(bytes + 184);
    if (record->byte_count > UINT64_C(53687091200) || record->source_ctime_nanos >= 1000000000U) return -1;
    for (size_t index = 0; index < 32; ++index) snprintf(record->digest + index * 2, 3, "%02x", bytes[128 + index]);
    if (record->kind <= CLIQ_MODEL_STORE_LOCK) {
        static const char *const names[] = {"local-models/registry.sqlite3", "local-models/registry.sqlite3-journal", "local-models/registry.lock"};
        if (!record->kind || strcmp(record->path, names[record->kind - 1]) || record->mode != 0600) return -1;
    } else if (record->kind == CLIQ_MODEL_STORE_OBJECT) {
        static const char prefix[] = "local-models/objects/";
        const size_t prefix_length = sizeof(prefix) - 1;
        const char *object = record->path + prefix_length;
        if (length != prefix_length + 64 || memcmp(record->path, prefix, prefix_length) ||
            !ma_hex(object, 64) || strcmp(object, record->digest) || record->mode != 0400) return -1;
    } else if (record->kind == CLIQ_MODEL_STORE_TEMPORARY) {
        static const char prefix[] = "local-models/objects/.model-object-v1-";
        const size_t prefix_length = sizeof(prefix) - 1;
        if (length != prefix_length + 32 || memcmp(record->path, prefix, prefix_length) || !ma_hex(record->path + prefix_length, 32) ||
            (record->mode != 0400 && record->mode != 0600)) return -1;
    } else return -1;
    return 0;
}
static int ma_read_record(ma_model_checker *checker, size_t index, ma_model_record *record) {
    if (index >= checker->expected.count || !ma_named_inventory(checker)) return -1;
    unsigned char bytes[MAC_RECORD_BYTES]; size_t offset = 0;
    while (offset < sizeof(bytes)) {
        ssize_t count = pread(checker->inventory_fd, bytes + offset, sizeof(bytes) - offset,
            (off_t)(MAC_HEADER_BYTES + MAC_RECORD_BYTES * (uint64_t)index + offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > sizeof(bytes) - offset) return -1;
        offset += (size_t)count;
    }
    return ma_named_inventory(checker) && ma_decode_record(bytes, record) == 0 &&
        record->byte_count <= checker->expected.byte_count &&
        record->uid == checker->expected.uid && record->source_device == checker->expected.source_device &&
        record->target_device == checker->expected.target_device ? 0 : -1;
}
static int ma_find(ma_model_checker *checker, const char *path, size_t *index, ma_model_record *record) {
    size_t low = 0, high = (size_t)checker->expected.count;
    while (low < high) {
        size_t mid = low + (high - low) / 2; if (ma_read_record(checker, mid, record) != 0) return -1;
        int order = strcmp(path, record->path); if (!order) { *index = mid; return 0; }
        if (order < 0) high = mid; else low = mid + 1;
    }
    return -1;
}
static unsigned char ma_seen(const ma_model_checker *checker, size_t index) {
    return (unsigned char)((checker->seen[index / 4] >> ((index % 4) * 2)) & 3U);
}
static void ma_set_seen(ma_model_checker *checker, size_t index, unsigned char value) {
    unsigned int shift = (unsigned int)((index % 4) * 2);
    checker->seen[index / 4] = (unsigned char)((checker->seen[index / 4] & ~(3U << shift)) | (unsigned int)value << shift);
}
static int ma_open_directory(ma_model_checker *checker, int parent, const char *name, int *fd, struct stat *identity,
                             uint64_t device, uint64_t inode) {
    *fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    return *fd >= 0 && fstat(*fd, identity) == 0 && private_directory(identity) && ma_device(identity) == device &&
        (uint64_t)identity->st_ino == inode && ma_named_directory(parent, name, *fd, identity, 1) &&
        identity->st_uid == checker->expected.uid ? 0 : -1;
}
/* source and parentFD are genuine private parent borrows, not caller arguments.
 * On a partial refusal, output remains owned by that same parent until actual
 * close; this helper never ends or cancels the parent's source visitor. */
static int ma_open_checker(napi_env env, migration_credential_gate *binding, cliq_model_store_archive *source,
                            int parent_fd, const struct stat *parent, const ma_model_witness *expected,
                            size_t available_metadata, ma_model_checker **output) {
    *output = NULL;
    if (!kernel_global_main_thread() || migration_credential_check(binding, env) != 0 || !source ||
        expected->uid != (uint32_t)geteuid() || expected->count < 3 || expected->count > MAC_MAX_ENTRIES ||
        expected->source_device != ma_device(&binding->owner->root) || expected->source_objects_device != expected->source_device ||
        expected->target_device != expected->source_device || expected->target_objects_device != expected->source_device ||
        expected->inventory_device != expected->source_device || expected->source_inode == expected->target_inode ||
        expected->source_objects_inode == expected->target_objects_inode ||
        expected->inventory_size != MAC_HEADER_BYTES + MAC_RECORD_BYTES * expected->count ||
        expected->byte_count > UINT64_C(53687091200) - expected->inventory_size ||
        strlen(expected->inventory_digest) != 64 || !ma_hex(expected->inventory_digest, 64)) return -1;
    size_t count = (size_t)expected->count;
    size_t metadata = MAC_FIXED_METADATA + sizeof(ma_model_checker) + count * sizeof(int64_t) + count * sizeof(uint32_t) +
        (count + 3) / 4 + 2 * 65536U;
    if (metadata > available_metadata) return -1;
    ma_model_checker *checker = calloc(1, sizeof(*checker)); if (!checker) return -1;
    *output = checker; checker->env = env; checker->binding = binding; checker->source = source;
    checker->parent_fd = parent_fd; checker->parent = *parent; checker->expected = *expected; checker->metadata_bytes = metadata;
    checker->store_fd = checker->objects_fd = checker->inventory_fd = checker->inventory_reader = checker->current_fd = -1;
    struct cliq_model_store_archive_directories actual;
    if (cliq_model_store_archive_directories(source, &actual) != 0 ||
        ma_device(&actual.store) != expected->source_device || (uint64_t)actual.store.st_ino != expected->source_inode ||
        ma_device(&actual.objects) != expected->source_objects_device || (uint64_t)actual.objects.st_ino != expected->source_objects_inode ||
        actual.store.st_uid != expected->uid || actual.objects.st_uid != expected->uid ||
        ma_open_directory(checker, parent_fd, "local-models", &checker->store_fd, &checker->store, expected->target_device, expected->target_inode) != 0 ||
        ma_open_directory(checker, checker->store_fd, "objects", &checker->objects_fd, &checker->objects,
            expected->target_objects_device, expected->target_objects_inode) != 0) return -1;
    checker->inventory_fd = openat(checker->store_fd, "inventory-v1.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (checker->inventory_fd < 0 || fstat(checker->inventory_fd, &checker->inventory) != 0 ||
        !ma_regular(checker, &checker->inventory) || ma_device(&checker->inventory) != expected->inventory_device ||
        (uint64_t)checker->inventory.st_ino != expected->inventory_inode ||
        (uint64_t)checker->inventory.st_size != expected->inventory_size || !ma_custody(checker)) return -1;
    checker->seen = calloc((count + 3) / 4, 1);
    checker->target_ctime_seconds = malloc(count * sizeof(*checker->target_ctime_seconds));
    checker->target_ctime_nanos = malloc(count * sizeof(*checker->target_ctime_nanos));
    if (!checker->seen || !checker->target_ctime_seconds || !checker->target_ctime_nanos) return -1;
    checker->inventory_reader = openat(checker->store_fd, "inventory-v1.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat reader;
    if (checker->inventory_reader < 0 || fstat(checker->inventory_reader, &reader) != 0 ||
        !source_metadata_same(&reader, &checker->inventory)) return -1;
    sha256_init(&checker->hash); checker->phase = MAC_INVENTORY; return 0;
}
static int ma_close_checker(napi_env env, ma_model_checker *checker) {
    if (!checker) return 0;
    if (!kernel_global_main_thread() || checker->env != env) return -1;
    int failed = ma_close_scan(checker) != 0;
    int *const descriptors[] = {&checker->current_fd, &checker->inventory_reader, &checker->inventory_fd, &checker->objects_fd, &checker->store_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (ma_close_fd(checker, descriptors[index]) != 0) failed = 1;
    if (failed || checker->uncertain) return -1;
    free(checker->target_ctime_seconds); free(checker->target_ctime_nanos); free(checker->seen); free(checker); return 0;
}
static int ma_pread(int fd, unsigned char *bytes, size_t amount, uint64_t offset) {
    size_t done = 0;
    while (done < amount) {
        ssize_t count = pread(fd, bytes + done, amount - done, (off_t)(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > amount - done) return -1;
        done += (size_t)count;
    }
    return 0;
}
static int ma_hash_read(int fd, uint64_t size, uint64_t *offset, struct sha256_context *hash) {
    if (*offset > size) return -1;
    unsigned char bytes[65536]; size_t amount = size - *offset < sizeof(bytes) ? (size_t)(size - *offset) : sizeof(bytes);
    if (ma_pread(fd, bytes, amount, *offset) != 0) return -1;
    sha256_update(hash, bytes, amount); *offset += amount;
    if (*offset < size) return 0;
    ssize_t count;
    do { count = pread(fd, bytes, 1, (off_t)*offset); } while (count < 0 && errno == EINTR);
    return count == 0 ? 1 : -1;
}
static int ma_source_same(const ma_model_record *record, const struct cliq_model_store_archive_entry *source) {
    int64_t seconds; uint32_t nanos; ma_times(&source->identity, &seconds, &nanos);
    return !strcmp(source->relative_path, record->path) && source->kind == record->kind &&
        S_ISREG(source->identity.st_mode) && ma_device(&source->identity) == record->source_device &&
        (uint64_t)source->identity.st_ino == record->source_inode && source->identity.st_uid == record->uid &&
        source->identity.st_gid == getegid() && source->identity.st_nlink == 1 && source->identity.st_size >= 0 &&
        (uint64_t)source->identity.st_size == record->byte_count && (uint32_t)(source->identity.st_mode & 07777) == record->mode &&
        seconds == record->source_ctime_seconds && nanos == record->source_ctime_nanos;
}
static int ma_source_step(ma_model_checker *checker) {
    int final = checker->phase == MAC_FINAL_SOURCE;
    if (!checker->source_active) {
        struct cliq_model_store_archive_entry actual; int next = cliq_model_store_archive_next(checker->source, &actual);
        if (next < 0) return -1;
        if (!next) {
            if (final ? checker->final_source_count != checker->expected.count :
                checker->source_count != checker->expected.count || checker->source_bytes != checker->expected.byte_count) return -1;
            if (cliq_model_store_archive_rewind(checker->source) != 0) return -1;
            checker->root_seen = 0; checker->phase = final ? MAC_FINAL_ROOT : MAC_TARGET_ROOT; return 0;
        }
        if (ma_find(checker, actual.relative_path, &checker->record_index, &checker->record) != 0 ||
            !ma_source_same(&checker->record, &actual) || ma_seen(checker, checker->record_index) != (final ? 3 : 0)) return -1;
        if (final) {
            if (cliq_model_store_archive_finish_metadata(checker->source) != 0) return -1;
            ma_set_seen(checker, checker->record_index, 2); checker->final_source_count++; return 0;
        }
        checker->source_active = 1; checker->offset = 0; sha256_init(&checker->hash); return 0;
    }
    unsigned char bytes[65536]; size_t amount;
    if (cliq_model_store_archive_read(checker->source, bytes, &amount) != 0 || amount > checker->record.byte_count - checker->offset) return -1;
    if (amount) { sha256_update(&checker->hash, bytes, amount); checker->offset += amount; return 0; }
    char digest[65]; publication_hash_hex(&checker->hash, digest);
    if (checker->offset != checker->record.byte_count || strcmp(digest, checker->record.digest) ||
        checker->source_bytes > checker->expected.byte_count - checker->record.byte_count ||
        cliq_model_store_archive_close_current(checker->source) != 0) return -1;
    ma_set_seen(checker, checker->record_index, 1); checker->source_count++; checker->source_bytes += checker->record.byte_count;
    checker->source_active = 0; return 0;
}
static int ma_target_same(const ma_model_checker *checker, const ma_model_record *record, const struct stat *identity) {
    return ma_regular(checker, identity) && ma_device(identity) == record->target_device &&
        (uint64_t)identity->st_ino == record->target_inode && (uint64_t)identity->st_size == record->byte_count;
}
static int ma_target_parent(const ma_model_checker *checker) {
    return checker->record.kind >= CLIQ_MODEL_STORE_OBJECT ? checker->objects_fd : checker->store_fd;
}
static const char *ma_target_leaf(const ma_model_checker *checker) {
    const char *slash = strrchr(checker->record.path, '/'); return slash ? slash + 1 : NULL;
}
static int ma_target_current(ma_model_checker *checker) {
    struct stat actual, named;
    return checker->current_fd >= 0 && fstat(checker->current_fd, &actual) == 0 &&
        source_metadata_same(&actual, &checker->current) && ma_target_same(checker, &checker->record, &actual) &&
        fstatat(ma_target_parent(checker), ma_target_leaf(checker), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        source_metadata_same(&actual, &named);
}
static int ma_target_read(ma_model_checker *checker) {
    if (!ma_target_current(checker)) return -1;
    int done = ma_hash_read(checker->current_fd, checker->record.byte_count, &checker->offset, &checker->hash);
    if (done < 0 || !ma_target_current(checker)) return -1;
    if (!done) return 0;
    char digest[65]; publication_hash_hex(&checker->hash, digest);
    if (strcmp(digest, checker->record.digest) || fsync(checker->current_fd) != 0 || fsync(ma_target_parent(checker)) != 0 ||
        !ma_target_current(checker) || checker->target_bytes > checker->expected.byte_count - checker->record.byte_count ||
        ma_close_fd(checker, &checker->current_fd) != 0) return -1;
    ma_times(&checker->current, &checker->target_ctime_seconds[checker->record_index], &checker->target_ctime_nanos[checker->record_index]);
    ma_set_seen(checker, checker->record_index, 3); checker->target_count++; checker->target_bytes += checker->record.byte_count; return 0;
}
static int ma_open_scan(ma_model_checker *checker, int parent) {
    int fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    checker->scan = fdopendir(fd); if (checker->scan) return 0;
    (void)ma_close_fd(checker, &fd); return -1;
}
static int ma_target_step(ma_model_checker *checker) {
    int objects = checker->phase == MAC_TARGET_OBJECTS || checker->phase == MAC_FINAL_OBJECTS;
    int final = checker->phase == MAC_FINAL_ROOT || checker->phase == MAC_FINAL_OBJECTS;
    int parent = objects ? checker->objects_fd : checker->store_fd;
    if (checker->current_fd >= 0) return final ? -1 : ma_target_read(checker);
    if (!checker->scan && ma_open_scan(checker, parent) != 0) return -1;
    for (unsigned int step = 0; step < 64; ++step) {
        errno = 0; struct dirent *actual = readdir(checker->scan);
        if (!actual) {
            if (errno || fsync(parent) != 0 || ma_close_scan(checker) != 0 || !ma_custody(checker)) return -1;
            if (!objects) {
                if (checker->root_seen != 3) return -1;
                checker->phase = final ? MAC_FINAL_OBJECTS : MAC_TARGET_OBJECTS; return 0;
            }
            if (final) {
                if (checker->final_count != checker->expected.count) return -1;
                checker->phase = MAC_COMPLETE;
            } else {
                if (checker->target_count != checker->expected.count || checker->target_bytes != checker->expected.byte_count) return -1;
                checker->phase = MAC_FINAL_SOURCE;
            }
            return 0;
        }
        if (!strcmp(actual->d_name, ".") || !strcmp(actual->d_name, "..")) continue;
        struct stat named;
        if (fstatat(parent, actual->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0) return -1;
        if (!objects && !strcmp(actual->d_name, "objects")) {
            if ((checker->root_seen & 1) || !ma_named_directory(checker->store_fd, "objects", checker->objects_fd, &checker->objects, 1) ||
                !source_metadata_same(&named, &checker->objects)) return -1;
            checker->root_seen |= 1; continue;
        }
        if (!objects && !strcmp(actual->d_name, "inventory-v1.bin")) {
            if ((checker->root_seen & 2) || !ma_named_inventory(checker) || !source_metadata_same(&named, &checker->inventory)) return -1;
            checker->root_seen |= 2; continue;
        }
        char path[96]; int length = snprintf(path, sizeof(path), objects ? "local-models/objects/%s" : "local-models/%s", actual->d_name);
        if (length < 0 || (size_t)length >= sizeof(path) || ma_find(checker, path, &checker->record_index, &checker->record) != 0 ||
            (checker->record.kind >= CLIQ_MODEL_STORE_OBJECT) != objects ||
            !ma_target_same(checker, &checker->record, &named) ||
            ma_seen(checker, checker->record_index) != (final ? 2 : 1)) return -1;
        if (final) {
            int64_t seconds; uint32_t nanos; ma_times(&named, &seconds, &nanos);
            if (seconds != checker->target_ctime_seconds[checker->record_index] || nanos != checker->target_ctime_nanos[checker->record_index]) return -1;
            ma_set_seen(checker, checker->record_index, 0); checker->final_count++; continue;
        }
        checker->current_fd = openat(parent, actual->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (checker->current_fd < 0 || fstat(checker->current_fd, &checker->current) != 0 ||
            !source_metadata_same(&named, &checker->current) || !ma_target_current(checker)) return -1;
        checker->offset = 0; sha256_init(&checker->hash); return 0;
    }
    return 0;
}
/* Each step reads at most64KiB, or checks at most64 actual directory entries.
 * Its genuine parent still owns cancellation/join and the original limits. */
static int ma_checker_step(ma_model_checker *checker) {
    if (!checker || checker->failed || checker->uncertain) return -1;
    if (!ma_custody(checker)) { checker->failed = 1; return -1; }
    int status = 0;
    if (checker->phase == MAC_INVENTORY) {
        struct stat actual;
        if (checker->inventory_reader < 0 || fstat(checker->inventory_reader, &actual) != 0 ||
            !source_metadata_same(&actual, &checker->inventory)) status = -1;
        else {
            int done = ma_hash_read(checker->inventory_reader, checker->expected.inventory_size, &checker->offset, &checker->hash);
            if (done < 0 || !ma_named_inventory(checker)) status = -1;
            else if (done) {
                char digest[65]; publication_hash_hex(&checker->hash, digest);
                if (strcmp(digest, checker->expected.inventory_digest) || fsync(checker->inventory_reader) != 0 ||
                    fsync(checker->store_fd) != 0 || ma_close_fd(checker, &checker->inventory_reader) != 0) status = -1;
                else checker->phase = MAC_HEADER;
            }
        }
    } else if (checker->phase == MAC_HEADER) {
        unsigned char header[MAC_HEADER_BYTES];
        if (ma_pread(checker->inventory_fd, header, sizeof(header), 0) != 0 || !ma_named_inventory(checker) ||
            memcmp(header, "CLQMS001", 8) || ma_u64(header + 8) != checker->expected.count ||
            ma_u64(header + 16) != checker->expected.byte_count || ma_u64(header + 24) != checker->expected.source_device ||
            ma_u64(header + 32) != checker->expected.source_inode || ma_u64(header + 40) != checker->expected.source_objects_device ||
            ma_u64(header + 48) != checker->expected.source_objects_inode || ma_u32(header + 56) != checker->expected.uid ||
            ma_u32(header + 60) != MAC_RECORD_BYTES || cliq_model_store_archive_rewind(checker->source) != 0) status = -1;
        else checker->phase = MAC_SOURCE;
    } else if (checker->phase == MAC_SOURCE || checker->phase == MAC_FINAL_SOURCE) status = ma_source_step(checker);
    else if (checker->phase == MAC_TARGET_ROOT || checker->phase == MAC_TARGET_OBJECTS ||
        checker->phase == MAC_FINAL_ROOT || checker->phase == MAC_FINAL_OBJECTS) status = ma_target_step(checker);
    else if (checker->phase != MAC_COMPLETE) status = -1;
    if (status || !ma_custody(checker)) { checker->failed = 1; return -1; }
    return checker->phase == MAC_COMPLETE ? 1 : 0;
}
/* A new full observation of the same immutable inventory and held source.
 * No failed action, nonce, clock, budget or deadline can be reset here. Every
 * previous seen bit is already consumed by the completed all-only final pass. */
static int ma_restart_complete_check(ma_model_checker *checker) {
    if (!checker || checker->failed || checker->uncertain || checker->phase != MAC_COMPLETE ||
        checker->source_active || checker->current_fd >= 0 || checker->inventory_reader >= 0 ||
        checker->scan || !ma_custody(checker)) return -1;
    checker->inventory_reader = openat(checker->store_fd, "inventory-v1.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat actual;
    if (checker->inventory_reader < 0 || fstat(checker->inventory_reader, &actual) != 0 ||
        !source_metadata_same(&actual, &checker->inventory)) return -1;
    checker->offset = checker->source_count = checker->source_bytes = checker->target_count = checker->target_bytes = 0;
    checker->final_count = checker->final_source_count = 0; checker->root_seen = 0;
    sha256_init(&checker->hash); checker->phase = MAC_INVENTORY; return 0;
}
#endif
