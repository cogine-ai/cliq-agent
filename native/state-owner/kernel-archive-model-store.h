/* Same original kernel_archive holder, included after the frozen CAS module.
 * Reuses its byte/time/index primitives, never its authority or live scope.
 * The actual model source is the C-private same-EX visitor. No FD/path/pager/
 * caller callback escapes. Model index is retired before the CAS index exists. */
#define KAM_MAX_ENTRIES (KANS_MAX_ENTRIES + 3U)
#define KAM_RECORD_BYTES 192U
#define KAM_HEADER_BYTES 64U
_Static_assert(sizeof(kans_entry) * (uint64_t)KAM_MAX_ENTRIES <= KANS_METADATA_BYTES - 2 * KANS_CHUNK,
    "complete model index exceeds the original shared metadata budget");
enum kam_phase { KAM_WAIT, KAM_COPY, KAM_HEAP, KAM_SORT, KAM_SOURCE,
    KAM_TARGET_ROOT, KAM_TARGET_OBJECTS, KAM_INDEX_HEADER, KAM_INDEX_ROWS,
    KAM_INDEX_WRITABLE, KAM_INDEX_READONLY, KAM_COMPLETE };
struct kernel_archive_models {
    cliq_model_store_archive *source;
    ma_model_checker *checker;
    struct cliq_model_store_archive_directories original;
    int directory_fd, objects_fd, current_fd, inventory_fd, source_active, copy_stage;
    struct stat directory, objects, current_file, inventory;
    kans_entry *entries, *current;
    size_t count, heap_index, heap_end, index, checked;
    uint64_t byte_count, offset, inventory_size;
    struct sha256_context hash;
    char inventory_digest[65];
    DIR *scan;
    enum kam_phase phase;
};
static void kam_le32(unsigned char *p, uint32_t value) {
    for (unsigned int index = 0; index < 4; ++index) p[index] = (unsigned char)(value >> (index * 8));
}
static void kam_le64(unsigned char *p, uint64_t value) {
    for (unsigned int index = 0; index < 8; ++index) p[index] = (unsigned char)(value >> (index * 8));
}
static uint64_t kam_device(const struct stat *identity) {
#ifdef __APPLE__
    return (uint32_t)identity->st_dev;
#else
    return (uint64_t)identity->st_dev;
#endif
}
static int kam_model_source(kernel_archive *held) {
    return held->models ? cliq_model_store_archive_assert(held->models->source) == 0 : ka_local_model_store_absent(held);
}
static int kam_custody(kernel_archive *held) {
    kernel_archive_models *models = held->models; if (!models) return ka_local_model_store_absent(held) ? 0 : -2;
    struct stat observed;
    if (models->directory_fd >= 0 && !ka_named_directory(held, held->directory_fd, "local-models",
        models->directory_fd, &models->directory)) return -1;
    if (models->objects_fd >= 0 && !ka_named_directory(held, models->directory_fd, "objects", models->objects_fd, &models->objects)) return -1;
    if (models->phase == KAM_COMPLETE && (fstat(models->directory_fd, &observed) != 0 ||
        !source_metadata_same(&observed, &models->directory) || fstat(models->objects_fd, &observed) != 0 ||
        !source_metadata_same(&observed, &models->objects) || !ka_named_file(held, models->directory_fd, "inventory-v1.bin",
            models->inventory_fd, &models->inventory, 0400, 1))) return -1;
    if (models->checker && !ma_target_custody(models->checker)) return -1;
    return kam_model_source(held) ? 0 : -2;
}
static int kam_close_scan(kernel_archive *held) {
    kernel_archive_models *models = held->models; DIR *original = models->scan; models->scan = NULL;
    if (!original || closedir(original) == 0) return 0;
    ka_uncertain(held); return -1;
}
static int kam_retire(kernel_archive *held) {
    kernel_archive_models *models = held->models; if (!models) return 0;
    int failed = kam_close_scan(held) != 0;
    if (models->checker) {
        if (ma_close_checker(held->env, models->checker) != 0) return -1;
        models->checker = NULL;
    }
    int *const descriptors[] = {&models->current_fd, &models->inventory_fd, &models->objects_fd, &models->directory_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (ka_close_fd(held, descriptors[index]) != 0) failed = 1;
    if (failed) return -1;
    int refused = held->failed || atomic_load(&held->cancelled) || models->phase != KAM_COMPLETE;
    if (!held->rollback_source && models->source && (refused ? cliq_model_store_archive_cancel(held->env, models->source) :
        cliq_model_store_archive_end(held->env, models->source)) != 0) return -1;
    models->source = NULL; free(models->entries); models->entries = NULL; free(models); held->models = NULL; return 0;
}
static int kam_attach(kernel_archive *held, napi_value source, cliq_model_store_archive *existing) {
    kernel_archive_models *models = calloc(1, sizeof(*models)); if (!models) return -1;
    held->models = models;
    models->directory_fd = models->objects_fd = models->current_fd = models->inventory_fd = -1;
    models->source = existing;
    if ((!existing && cliq_model_store_archive_begin(held->env, source, held->binding, &models->source) != 0) ||
        cliq_model_store_archive_directories(models->source, &models->original) != 0 ||
        models->original.store.st_dev != held->root.st_dev || models->original.objects.st_dev != held->root.st_dev) return -1;
    models->phase = KAM_WAIT; return 0;
}
static kans_entry *kam_find(kernel_archive_models *models, const char *name) {
    size_t low = 0, high = models->count;
    while (low < high) { size_t mid = low + (high - low) / 2; int order = strcmp(name, models->entries[mid].name);
        if (!order) return &models->entries[mid];
        if (order < 0) high = mid; else low = mid + 1;
    }
    return NULL;
}
static int kam_source_same(kernel_archive *held, const kans_entry *entry, const struct cliq_model_store_archive_entry *actual) {
    kans_entry current = {0}; kans_times(&current, &actual->identity);
    return !strcmp(actual->relative_path, entry->name) && actual->kind == entry->kind &&
        S_ISREG(actual->identity.st_mode) && actual->identity.st_dev == held->root.st_dev &&
        actual->identity.st_uid == held->uid && actual->identity.st_gid == held->gid && actual->identity.st_nlink == 1 &&
        (uint64_t)actual->identity.st_ino == entry->source_inode && actual->identity.st_size >= 0 &&
        (uint64_t)actual->identity.st_size == entry->byte_count && (actual->identity.st_mode & 07777) == entry->mode &&
        current.mtime_seconds == entry->mtime_seconds && current.mtime_nanos == entry->mtime_nanos &&
        current.ctime_seconds == entry->ctime_seconds && current.ctime_nanos == entry->ctime_nanos;
}
static const char *kam_leaf(const kans_entry *entry) {
    const char *part = strrchr(entry->name, '/'); return part ? part + 1 : NULL;
}
static int kam_target_parent(kernel_archive_models *models, const kans_entry *entry) {
    return entry->kind >= CLIQ_MODEL_STORE_OBJECT ? models->objects_fd : models->directory_fd;
}
static int kam_target_current(kernel_archive *held) {
    kernel_archive_models *models = held->models; struct stat current, named;
    int parent = kam_target_parent(models, models->current); mode_t mode = models->copy_stage == 1 ? 0600 : 0400;
    return fstat(models->current_fd, &current) == 0 && ka_regular(held, &current, mode) &&
        current.st_dev == held->root.st_dev && same_inode(&current, &models->current_file) &&
        (models->copy_stage != 2 || kans_archive_same(held, models->current, &current)) &&
        fstatat(parent, kam_leaf(models->current), &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&current, &named);
}
static int kam_copy_step(kernel_archive *held) {
    kernel_archive_models *models = held->models; unsigned char bytes[KANS_CHUNK]; size_t size;
    if (!models->source_active) {
        struct cliq_model_store_archive_entry actual; int next = cliq_model_store_archive_next(models->source, &actual);
        if (next < 0) return -1;
        if (!next) { models->phase = KAM_HEAP; models->heap_index = models->count / 2; models->heap_end = models->count; return 0; }
        if (models->count >= KAM_MAX_ENTRIES || strlen(actual.relative_path) >= 96 ||
            actual.kind < CLIQ_MODEL_STORE_REGISTRY || actual.kind > CLIQ_MODEL_STORE_TEMPORARY ||
            !S_ISREG(actual.identity.st_mode) || actual.identity.st_dev != held->root.st_dev ||
            actual.identity.st_uid != held->uid || actual.identity.st_gid != held->gid || actual.identity.st_nlink != 1 ||
            actual.identity.st_size < 0 || (uint64_t)actual.identity.st_size > KERNEL_ARCHIVE_MAX_BYTES - held->byte_count ||
            models->byte_count > KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - (uint64_t)actual.identity.st_size) return -1;
        uint64_t inventory_bytes = KAM_HEADER_BYTES + KAM_RECORD_BYTES * (uint64_t)(models->count + 1);
        if (inventory_bytes > KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - models->byte_count - (uint64_t)actual.identity.st_size) return -1;
        kans_entry *entry = &models->entries[models->count]; strcpy(entry->name, actual.relative_path);
        entry->source_inode = (uint64_t)actual.identity.st_ino; entry->byte_count = (uint64_t)actual.identity.st_size;
        entry->mode = (uint16_t)(actual.identity.st_mode & 07777); entry->kind = (unsigned char)actual.kind; kans_times(entry, &actual.identity);
        if (entry->kind <= CLIQ_MODEL_STORE_LOCK ? entry->mode != 0600 : entry->mode != 0400 &&
            !(entry->kind == CLIQ_MODEL_STORE_TEMPORARY && entry->mode == 0600)) return -1;
        models->current = entry; models->source_active = 1; models->offset = 0; models->copy_stage = 1; sha256_init(&models->hash);
        int parent = kam_target_parent(models, entry);
        models->current_fd = openat(parent, kam_leaf(entry), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (models->current_fd < 0 || fstat(models->current_fd, &models->current_file) != 0 ||
            !ka_regular(held, &models->current_file, 0600) || models->current_file.st_dev != held->root.st_dev ||
            fsync(models->current_fd) != 0 || fsync(parent) != 0 || !kam_target_current(held)) return -1;
        entry->archive_inode = (uint64_t)models->current_file.st_ino; return 0;
    }
    kans_entry *entry = models->current; int parent = kam_target_parent(models, entry);
    if (!kam_target_current(held)) return -1;
    if (models->copy_stage == 1) {
        if (cliq_model_store_archive_read(models->source, bytes, &size) != 0 || size > entry->byte_count - models->offset) return -1;
        if (size) {
            if (kans_write(models->current_fd, bytes, size, models->offset) != 0) return -1;
            sha256_update(&models->hash, bytes, size); models->offset += size; return kam_target_current(held) ? 0 : -1;
        }
        if (models->offset != entry->byte_count) return -1;
        publication_hash_hex(&models->hash, entry->digest);
        if (entry->kind == CLIQ_MODEL_STORE_OBJECT && strcmp(kam_leaf(entry), entry->digest)) return -1;
        if (cliq_model_store_archive_close_current(models->source) != 0 ||
            fsync(models->current_fd) != 0 || fchmod(models->current_fd, 0400) != 0 || fsync(models->current_fd) != 0 ||
            fstat(models->current_fd, &models->current_file) != 0 || !ka_regular(held, &models->current_file, 0400) ||
            fsync(parent) != 0 || ka_close_fd(held, &models->current_fd) != 0) return -1;
        models->current_fd = openat(parent, kam_leaf(entry), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat readonly;
        if (models->current_fd < 0 || fstat(models->current_fd, &readonly) != 0 ||
            !source_metadata_same(&readonly, &models->current_file)) return -1;
        kans_archive_time(entry, &readonly); models->copy_stage = 2; models->offset = 0; sha256_init(&models->hash); return 0;
    }
    int done = kans_read_step(models->current_fd, entry->byte_count, &models->offset, &models->hash, bytes, &size);
    if (done < 0 || !kam_target_current(held)) return -1;
    if (done) {
        char digest[65]; publication_hash_hex(&models->hash, digest);
        if (strcmp(digest, entry->digest) || fsync(models->current_fd) != 0 || fsync(parent) != 0 ||
            ka_close_fd(held, &models->current_fd) != 0) return -1;
        models->byte_count += entry->byte_count; models->count++; models->source_active = 0; models->current = NULL;
    }
    return 0;
}
static void kam_sift(kernel_archive_models *models, size_t root, size_t count) {
    while (root < count / 2) {
        size_t child = root * 2 + 1;
        if (child + 1 < count && strcmp(models->entries[child].name, models->entries[child + 1].name) < 0) child++;
        if (strcmp(models->entries[root].name, models->entries[child].name) >= 0) break;
        kans_swap(&models->entries[root], &models->entries[child]); root = child;
    }
}
static int kam_source_step(kernel_archive *held) {
    kernel_archive_models *models = held->models; unsigned char bytes[KANS_CHUNK]; size_t size;
    if (!models->source_active) {
        struct cliq_model_store_archive_entry actual; int next = cliq_model_store_archive_next(models->source, &actual);
        if (next < 0) return -1;
        if (!next) {
            if (models->checked != models->count || cliq_model_store_archive_rewind(models->source) != 0) return -1;
            models->phase = KAM_TARGET_ROOT; models->checked = 0; return 0;
        }
        kans_entry *entry = kam_find(models, actual.relative_path);
        if (!entry || entry->seen || !kam_source_same(held, entry, &actual)) return -1;
        models->current = entry; models->source_active = 1; models->offset = 0; sha256_init(&models->hash); return 0;
    }
    if (cliq_model_store_archive_read(models->source, bytes, &size) != 0 || size > models->current->byte_count - models->offset) return -1;
    if (size) { sha256_update(&models->hash, bytes, size); models->offset += size; return 0; }
    char digest[65]; publication_hash_hex(&models->hash, digest);
    if (models->offset != models->current->byte_count || strcmp(digest, models->current->digest) ||
        cliq_model_store_archive_close_current(models->source) != 0) return -1;
    models->current->seen = 1; models->checked++; models->current = NULL; models->source_active = 0; return 0;
}
static int kam_open_scan(kernel_archive *held, int parent) {
    kernel_archive_models *models = held->models; int fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    models->scan = fdopendir(fd); if (models->scan) return 0;
    (void)ka_close_fd(held, &fd); return -1;
}
static int kam_target_step(kernel_archive *held) {
    kernel_archive_models *models = held->models; int objects = models->phase == KAM_TARGET_OBJECTS;
    int parent = objects ? models->objects_fd : models->directory_fd;
    if (!models->scan && kam_open_scan(held, parent) != 0) return -1;
    for (unsigned int step = 0; step < 64; ++step) {
        errno = 0; struct dirent *actual = readdir(models->scan);
        if (!actual) {
            if (errno || fsync(parent) != 0 || kam_close_scan(held) != 0) return -1;
            if (!objects) models->phase = KAM_TARGET_OBJECTS;
            else {
                if (models->checked != models->count) return -1;
                models->phase = KAM_INDEX_HEADER; models->index = 0;
            }
            return 0;
        }
        if (!strcmp(actual->d_name, ".") || !strcmp(actual->d_name, "..")) continue;
        struct stat named;
        if (fstatat(parent, actual->d_name, &named, AT_SYMLINK_NOFOLLOW) != 0) return -1;
        if (!objects && !strcmp(actual->d_name, "objects")) {
            if (!ka_named_directory(held, parent, "objects", models->objects_fd, &models->objects) ||
                !same_inode(&named, &models->objects)) return -1;
            continue;
        }
        char path[104]; int count = snprintf(path, sizeof(path), objects ? "local-models/objects/%s" : "local-models/%s", actual->d_name);
        if (count < 0 || (size_t)count >= sizeof(path)) return -1;
        kans_entry *entry = kam_find(models, path);
        if (!entry || entry->seen != 1 || !kans_archive_same(held, entry, &named)) return -1;
        entry->seen = 3; models->checked++;
    }
    return 0;
}
static void kam_record(kernel_archive *held, const kans_entry *entry, unsigned char bytes[KAM_RECORD_BYTES]) {
    memset(bytes, 0, KAM_RECORD_BYTES); memcpy(bytes, entry->name, strlen(entry->name));
    bytes[96] = entry->kind; bytes[97] = (unsigned char)entry->mode; bytes[98] = (unsigned char)(entry->mode >> 8);
    kam_le32(bytes + 100, held->uid); kam_le64(bytes + 104, entry->source_inode); kam_le64(bytes + 112, entry->archive_inode);
    kam_le64(bytes + 120, entry->byte_count); kam_le64(bytes + 160, kam_device(&held->models->original.store));
    kam_le64(bytes + 168, kam_device(&held->models->directory));
    kam_le64(bytes + 176, (uint64_t)entry->ctime_seconds); kam_le32(bytes + 184, entry->ctime_nanos);
    for (size_t index = 0; index < 32; ++index) {
        unsigned char high = (unsigned char)entry->digest[index * 2], low = (unsigned char)entry->digest[index * 2 + 1];
        high = high >= 'a' ? (unsigned char)(high - 'a' + 10) : (unsigned char)(high - '0');
        low = low >= 'a' ? (unsigned char)(low - 'a' + 10) : (unsigned char)(low - '0'); bytes[128 + index] = (unsigned char)(high * 16 + low);
    }
}
static int kam_inventory_current(kernel_archive *held, mode_t mode) {
    kernel_archive_models *models = held->models; struct stat actual, named;
    return fstat(models->inventory_fd, &actual) == 0 && ka_regular(held, &actual, mode) &&
        actual.st_dev == held->root.st_dev && same_inode(&actual, &models->inventory) &&
        fstatat(models->directory_fd, "inventory-v1.bin", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&actual, &named);
}
static int kam_index_step(kernel_archive *held) {
    kernel_archive_models *models = held->models;
    if (models->phase == KAM_INDEX_HEADER) {
        models->inventory_size = KAM_HEADER_BYTES + KAM_RECORD_BYTES * (uint64_t)models->count;
        if (models->count < 3 || models->inventory_size > KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - models->byte_count) return -1;
        models->inventory_fd = openat(models->directory_fd, "inventory-v1.bin", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (models->inventory_fd < 0 || fstat(models->inventory_fd, &models->inventory) != 0 ||
            !ka_regular(held, &models->inventory, 0600) || models->inventory.st_dev != held->root.st_dev ||
            fsync(models->inventory_fd) != 0 || fsync(models->directory_fd) != 0 || !kam_inventory_current(held, 0600)) return -1;
        unsigned char header[KAM_HEADER_BYTES] = {0}; memcpy(header, "CLQMS001", 8);
        kam_le64(header + 8, models->count); kam_le64(header + 16, models->byte_count);
        kam_le64(header + 24, kam_device(&models->original.store)); kam_le64(header + 32, models->original.store.st_ino);
        kam_le64(header + 40, kam_device(&models->original.objects)); kam_le64(header + 48, models->original.objects.st_ino);
        kam_le32(header + 56, held->uid); kam_le32(header + 60, KAM_RECORD_BYTES);
        if (kans_write(models->inventory_fd, header, sizeof(header), 0) != 0) return -1;
        sha256_init(&models->hash); sha256_update(&models->hash, header, sizeof(header));
        models->offset = sizeof(header); models->phase = KAM_INDEX_ROWS; return 0;
    }
    if (models->phase == KAM_INDEX_ROWS) {
        unsigned char rows[KAM_RECORD_BYTES * 64]; size_t count = models->count - models->index; if (count > 64) count = 64;
        for (size_t index = 0; index < count; ++index) {
            const kans_entry *entry = &models->entries[models->index + index];
            if (entry->seen != 3 || (models->index + index && strcmp(models->entries[models->index + index - 1].name, entry->name) >= 0)) return -1;
            kam_record(held, entry, rows + KAM_RECORD_BYTES * index);
        }
        if (!kam_inventory_current(held, 0600) || kans_write(models->inventory_fd, rows, count * KAM_RECORD_BYTES, models->offset) != 0) return -1;
        sha256_update(&models->hash, rows, count * KAM_RECORD_BYTES); models->offset += count * KAM_RECORD_BYTES; models->index += count;
        if (models->index != models->count) return 0;
        if (models->offset != models->inventory_size || fsync(models->inventory_fd) != 0 || fsync(models->directory_fd) != 0 ||
            fstat(models->inventory_fd, &models->inventory) != 0 || (uint64_t)models->inventory.st_size != models->inventory_size ||
            !kam_inventory_current(held, 0600)) return -1;
        publication_hash_hex(&models->hash, models->inventory_digest); models->offset = 0; sha256_init(&models->hash);
        models->phase = KAM_INDEX_WRITABLE; return 0;
    }
    unsigned char bytes[KANS_CHUNK]; size_t amount; mode_t mode = models->phase == KAM_INDEX_WRITABLE ? 0600 : 0400;
    if (!kam_inventory_current(held, mode)) return -1;
    int done = kans_read_step(models->inventory_fd, models->inventory_size, &models->offset, &models->hash, bytes, &amount);
    if (done < 0 || !kam_inventory_current(held, mode)) return -1;
    if (!done) return 0;
    char digest[65]; publication_hash_hex(&models->hash, digest);
    if (strcmp(digest, models->inventory_digest) || fsync(models->inventory_fd) != 0 || fsync(models->directory_fd) != 0) return -1;
    if (models->phase == KAM_INDEX_WRITABLE) {
        if (fchmod(models->inventory_fd, 0400) != 0 || fsync(models->inventory_fd) != 0 ||
            fstat(models->inventory_fd, &models->inventory) != 0 || !ka_regular(held, &models->inventory, 0400) ||
            fsync(models->directory_fd) != 0 || ka_close_fd(held, &models->inventory_fd) != 0) return -1;
        models->inventory_fd = openat(models->directory_fd, "inventory-v1.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat actual;
        if (models->inventory_fd < 0 || fstat(models->inventory_fd, &actual) != 0 || !source_metadata_same(&actual, &models->inventory)) return -1;
        models->offset = 0; sha256_init(&models->hash); models->phase = KAM_INDEX_READONLY; return 0;
    }
    if (fstat(models->directory_fd, &models->directory) != 0 || fstat(models->objects_fd, &models->objects) != 0 ||
        fsync(models->objects_fd) != 0 || fsync(models->directory_fd) != 0 || fsync(held->directory_fd) != 0 ||
        cliq_model_store_archive_assert(models->source) != 0) return -1;
    /* Only one native namespace index may be held. The complete readonly child
     * is now the fixed bounded source for all later metadata observations. */
    free(models->entries); models->entries = NULL; models->phase = KAM_COMPLETE; return kam_custody(held);
}
static napi_value kam_begin(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_models *models = held->models;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->cas &&
        !held->failed && !atomic_load(&held->cancelled) && !kernel_archive_active;
    if (valid && models) {
        valid = models->phase == KAM_WAIT &&
            ka_hold_directory(held, held->directory_fd, "local-models", &models->directory_fd, &models->directory, 1) == 0 &&
            ka_hold_directory(held, models->directory_fd, "objects", &models->objects_fd, &models->objects, 1) == 0 &&
            models->directory.st_dev == held->root.st_dev && models->objects.st_dev == held->root.st_dev;
        if (valid) { models->entries = calloc(KAM_MAX_ENTRIES, sizeof(*models->entries)); valid = models->entries != NULL; }
        if (valid) models->phase = KAM_COPY;
    }
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "model-store capture requires its original sealed image and genuine existing EX source");
}
static napi_value kam_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_models *models = held->models;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->cas &&
        !held->failed && !atomic_load(&held->cancelled) && (!models || models->phase > KAM_WAIT);
    if (valid && models) {
        int status = 0;
        switch (models->phase) {
            case KAM_COPY: status = kam_copy_step(held); break;
            case KAM_HEAP:
                for (unsigned int step = 0; step < 64 && models->heap_index; ++step) kam_sift(models, --models->heap_index, models->count);
                if (!models->heap_index) models->phase = KAM_SORT;
                break;
            case KAM_SORT:
                for (unsigned int step = 0; step < 64 && models->heap_end > 1; ++step) {
                    kans_swap(&models->entries[0], &models->entries[--models->heap_end]); kam_sift(models, 0, models->heap_end);
                }
                if (models->heap_end <= 1) {
                    status = cliq_model_store_archive_rewind(models->source); models->checked = 0; models->phase = KAM_SOURCE;
                }
                break;
            case KAM_SOURCE: status = kam_source_step(held); break;
            case KAM_TARGET_ROOT: case KAM_TARGET_OBJECTS: status = kam_target_step(held); break;
            case KAM_INDEX_HEADER: case KAM_INDEX_ROWS: case KAM_INDEX_WRITABLE: case KAM_INDEX_READONLY:
                status = kam_index_step(held); break;
            case KAM_COMPLETE: break;
            default: status = -1; break;
        }
        valid = status == 0 && kam_custody(held) == 0;
    }
    if (!valid) held->failed = 1;
    int complete = valid && (!models || models->phase == KAM_COMPLETE);
    pthread_mutex_unlock(&kernel_archive_mutex);
    napi_value result;
    if (!valid) return ka_error(env, held, "complete model-store capture changed, exceeded its original bound or failed a real close");
    return napi_get_boolean(env, complete != 0, &result) == napi_ok ? result : NULL;
}
static napi_value kam_identity(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_models *models = held->models; napi_value result = NULL, inventory = NULL;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->failed &&
        !atomic_load(&held->cancelled) && (!models || models->phase == KAM_COMPLETE);
    if (valid && napi_create_object(env, &result) != napi_ok) valid = 0;
    if (valid && !models) valid = ka_string_member(env, result, "kind", "absent");
    else if (valid) {
        valid = napi_create_object(env, &inventory) == napi_ok && ka_string_member(env, result, "kind", "captured") &&
            ka_string_member(env, result, "layout", "cliq-local-model-store-v1") &&
            identity_member(env, result, "sourceDirectory", &models->original.store) &&
            identity_member(env, result, "sourceObjectsDirectory", &models->original.objects) &&
            identity_member(env, result, "archiveDirectory", &models->directory) &&
            identity_member(env, result, "archiveObjectsDirectory", &models->objects) &&
            ka_count_member(env, result, "entryCount", models->count) && ka_count_member(env, result, "totalBytes", models->byte_count) &&
            identity_member(env, inventory, "file", &models->inventory) && ka_count_member(env, inventory, "byteCount", models->inventory_size) &&
            ka_string_member(env, inventory, "sha256", models->inventory_digest) &&
            napi_object_freeze(env, inventory) == napi_ok && napi_set_named_property(env, result, "inventory", inventory) == napi_ok;
    }
    if (valid) valid = napi_object_freeze(env, result) == napi_ok;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "model-store identity lacks a complete original readonly inventory and full source/target closure");
}
_Static_assert(sizeof(kans_entry) * (uint64_t)KANS_MAX_ENTRIES +
    (uint64_t)MAC_MAX_ENTRIES * (sizeof(int64_t) + sizeof(uint32_t)) + (MAC_MAX_ENTRIES + 3U) / 4U +
    sizeof(ma_model_checker) + MAC_FIXED_METADATA + 2 * KANS_CHUNK <= KANS_METADATA_BYTES,
    "CAS index and current model checker exceed the original shared metadata ceiling");
static napi_value kam_begin_verify(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_models *models = held->models;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->failed &&
        !atomic_load(&held->cancelled) && (!models || (models->phase == KAM_COMPLETE && !models->entries));
    if (valid && models && models->checker) valid = ma_restart_complete_check(models->checker) == 0;
    else if (valid && models) {
        ma_model_witness expected = {
            .source_device = kam_device(&models->original.store), .source_inode = (uint64_t)models->original.store.st_ino,
            .source_objects_device = kam_device(&models->original.objects), .source_objects_inode = (uint64_t)models->original.objects.st_ino,
            .target_device = kam_device(&models->directory), .target_inode = (uint64_t)models->directory.st_ino,
            .target_objects_device = kam_device(&models->objects), .target_objects_inode = (uint64_t)models->objects.st_ino,
            .inventory_device = kam_device(&models->inventory), .inventory_inode = (uint64_t)models->inventory.st_ino,
            .count = models->count, .byte_count = models->byte_count, .inventory_size = models->inventory_size, .uid = held->uid
        };
        strcpy(expected.inventory_digest, models->inventory_digest);
        valid = ma_open_checker(env, held->binding, models->source, held->directory_fd, &held->directory, &expected,
            KANS_METADATA_BYTES - sizeof(kans_entry) * KANS_MAX_ENTRIES, &models->checker) == 0;
    }
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "current model validation requires the same fully sealed original store and shared bounded index");
}
static napi_value kam_verify_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    kernel_archive_models *models = held->models;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->failed && !atomic_load(&held->cancelled);
    int result = valid && models ? models->checker ? ma_checker_step(models->checker) : -1 : valid ? 1 : -1;
    if (result < 0) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    if (result < 0) return ka_error(env, held, "complete current model source, target bytes or final census changed");
    napi_value value; return napi_get_boolean(env, result != 0, &value) == napi_ok ? value : NULL;
}
static int kam_verified(kernel_archive *held) {
    return !held->models || (held->models->phase == KAM_COMPLETE && !held->models->entries && held->models->checker &&
        !held->models->checker->failed && held->models->checker->phase == MAC_COMPLETE && ma_custody(held->models->checker));
}
static int kam_capture_complete(kernel_archive *held) {
    return !held->models || held->models->phase == KAM_COMPLETE;
}
static int ka_all_sidecars_verified(kernel_archive *held) {
    return kam_verified(held) && (!held->runtime_witnesses || held->runtime_witnesses->phase == RW_COMPLETE);
}
static uint64_t kam_payload_bytes(kernel_archive *held) {
    return (held->models ? held->models->byte_count + held->models->inventory_size : 0) +
        (held->runtime_witnesses ? held->runtime_witnesses->pack_size : 0);
}
static napi_value kam_begin_cas(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && ka_all_sidecars_verified(held);
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? kans_begin(env, info) : ka_error(env, held, "CAS cannot overlap a model index or precede complete current model verification");
}
static napi_value kam_cas_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    uint64_t models = kam_payload_bytes(held); kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && ka_all_sidecars_verified(held) && models <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count &&
        (!space || space->phase <= KANS_SCAN || space->byte_count <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - models);
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    /* KANS_NAMES only transitions to COPY. Before its first actual copy,
     * byte_count is complete, so this wrapper rejects total overflow before
     * any CAS payload birth. The frozen CAS implementation is unchanged. */
    return valid ? kans_next(env, info) : ka_error(env, held, "complete model, SQLite and CAS payload exceeds the original shared bound");
}
static napi_value kam_begin_manifest(napi_env env, napi_callback_info info) {
    napi_value args[2]; size_t count = 2; napi_value self; bool tagged = false, buffer = false; kernel_archive *held = NULL;
    void *bytes = NULL; size_t size = 0;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, args, &self, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, self, &kernel_archive_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&held) != napi_ok || !ka_main_context(held, env) ||
        napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok)
        return ka_error(env, NULL, "complete root manifest requires its original archive receiver and bounded bytes");
    if (ka_main_lock(env, held) != 0) return NULL;
    uint64_t models = kam_payload_bytes(held); kernel_archive_namespace *space = held->cas;
    int valid = ka_main_check(held, env) == 0 && ka_all_sidecars_verified(held) && space && space->phase == KANS_COMPLETE &&
        models <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count &&
        space->byte_count <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - models &&
        size <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - models - space->byte_count;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? kans_begin_manifest(env, info) : ka_error(env, held, "full root manifest must include its complete original model-store payload and current checks");
}
