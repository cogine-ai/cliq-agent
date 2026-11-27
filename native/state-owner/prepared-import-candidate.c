/* Read-only original-FD VFS for one genuine sealed owned-import preview.
 * The parent owns the image and its fixed directory chain. This child cannot
 * choose a path/FD/SQL or turn candidate data into StateOwner/Run authority. */
typedef struct prepared_import_candidate {
    migration_filesystem *parent;
    migration_candidate_borrow image;
    napi_env env;
    napi_ref parent_ref, owner_ref;
    pid_t pid;
    pthread_t thread;
    uint64_t generation, offset;
    struct sha256_context hash;
    int phase, lease, uncertain, retired;
} prepared_import_candidate;
enum { PREVIEW_OPEN_HASH, PREVIEW_READY, PREVIEW_READING, PREVIEW_CLOSE_HASH, PREVIEW_VERIFIED };
static const napi_type_tag prepared_import_candidate_tag = {0x9b817d2f3a580c44ULL, 0xbd708e1963cf52a1ULL};
static struct {
    _Atomic(prepared_import_candidate *) active;
    uint64_t generation;
    int registered;
    sqlite3_vfs *base;
    sqlite3_vfs vfs;
} prepared_import_process;
static const char prepared_import_name[] = "/cliq-owned-import-preview";
static const char prepared_import_vfs_name[] = "cliq-owned-import-preview-v1";

static void prepared_import_poison(prepared_import_candidate *held) {
    held->uncertain = 1;
    migrate_scope_poison(held->parent);
}
static int prepared_import_context(prepared_import_candidate *held) {
    /* Reject foreign threads independently before touching a live pointer. */
    return kernel_global_main_thread() && held && held->pid == getpid() &&
        pthread_equal(held->thread, pthread_self());
}
static int prepared_import_check(prepared_import_candidate *held) {
    if (!prepared_import_context(held) || held->retired || held->uncertain) return -1;
    struct stat actual;
    if (migrate_scope_check_candidate(held->parent, held->env, &held->image) != 0 ||
        fstat(held->image.image_fd, &actual) != 0 || !source_metadata_same(&actual, &held->image.image) ||
        !S_ISREG(actual.st_mode) || actual.st_uid != geteuid() || actual.st_gid != getegid() ||
        (actual.st_mode & 07777) != 0400 || actual.st_nlink != 1 || actual.st_size < 100 ||
        (uint64_t)actual.st_size != held->image.byte_count) {
        prepared_import_poison(held); return -1;
    }
    return 0;
}
static napi_value prepared_import_error(napi_env env, const char *message) {
    return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", message);
}
static prepared_import_candidate *prepared_import_receiver(napi_env env, napi_callback_info info) {
    size_t count = 1; napi_value self, argument; bool tagged = false;
    prepared_import_candidate *held = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
        napi_check_object_type_tag(env, self, &prepared_import_candidate_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&held) != napi_ok || !prepared_import_context(held) || held->env != env) {
        kernel_global_error(env, "ERR_CLIQ_PREPARED_IMPORT_CANDIDATE", "invalid original prepared candidate receiver"); return NULL;
    }
    return held;
}
static napi_value prepared_import_assert(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (prepared_import_check(held) != 0) return prepared_import_error(env, "prepared import candidate binding changed or retired");
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value prepared_import_verify_next(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (prepared_import_check(held) != 0 || held->lease ||
        (held->phase != PREVIEW_OPEN_HASH && held->phase != PREVIEW_CLOSE_HASH))
        return prepared_import_error(env, "candidate full-byte verification requires its original joined verification phase");
    unsigned char bytes[65536];
    uint64_t remaining = held->image.byte_count - held->offset;
    size_t amount = remaining < sizeof(bytes) ? (size_t)remaining : sizeof(bytes), consumed = 0;
    if (amount) {
        ssize_t read_count;
        do { read_count = pread(held->image.image_fd, bytes, amount, (off_t)held->offset); } while (read_count < 0 && errno == EINTR);
        if (read_count <= 0 || (size_t)read_count > amount) {
            prepared_import_poison(held); return prepared_import_error(env, "candidate full-byte read failed");
        }
        consumed = (size_t)read_count;
    }
    if (prepared_import_check(held) != 0) return prepared_import_error(env, "candidate changed during full-byte verification");
    sha256_update(&held->hash, bytes, consumed);
    held->offset += consumed;
    int done = held->offset == held->image.byte_count;
    if (done) {
        struct sha256_context hash = held->hash;
        char digest[65]; publication_hash_hex(&hash, digest);
        if (strcmp(digest, held->image.full_digest) != 0) {
            prepared_import_poison(held); return prepared_import_error(env, "candidate complete bytes differ from the original sealed image");
        }
        held->phase = held->phase == PREVIEW_OPEN_HASH ? PREVIEW_READY : PREVIEW_VERIFIED;
    }
    napi_value result; return napi_get_boolean(env, done != 0, &result) == napi_ok ? result : NULL;
}
static napi_value prepared_import_begin_read(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (prepared_import_check(held) != 0 || held->phase != PREVIEW_READY || held->lease)
        return prepared_import_error(env, "candidate reader requires its complete opening hash and original unused lease");
    prepared_import_candidate *expected = NULL;
    if (!atomic_compare_exchange_strong(&prepared_import_process.active, &expected, held))
        return kernel_global_error(env, "ERR_CLIQ_PREPARED_IMPORT_CANDIDATE", "another prepared candidate reader is active");
    held->phase = PREVIEW_READING;
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value prepared_import_end_read(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (prepared_import_check(held) != 0 || held->phase != PREVIEW_READING || held->lease ||
        atomic_load(&prepared_import_process.active) != held)
        return prepared_import_error(env, "candidate SQLite lease has not actually joined");
    atomic_store(&prepared_import_process.active, NULL);
    held->phase = PREVIEW_CLOSE_HASH; held->offset = 0; sha256_init(&held->hash);
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value prepared_import_identity(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (prepared_import_check(held) != 0) return prepared_import_error(env, "candidate image identity is no longer held");
    napi_value result, digest, bytes, mode, migration;
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "file", &held->image.image) ||
        !identity_member(env, result, "stateRoot", &held->parent->binding->owner->root) ||
        !identity_member(env, result, "migrationDirectory", &held->parent->migration) ||
        !identity_member(env, result, "collectionDirectory", &held->parent->collection) ||
        !identity_member(env, result, "packageDirectory", &held->parent->package) ||
        !identity_member(env, result, "candidateDirectory", &held->parent->candidate_dir) ||
        !identity_member(env, result, "legacyRoot", &held->parent->legacy) ||
        napi_create_string_utf8(env, held->parent->migration_id, 43, &migration) != napi_ok ||
        napi_set_named_property(env, result, "migrationId", migration) != napi_ok ||
        napi_create_string_utf8(env, held->image.full_digest, 64, &digest) != napi_ok ||
        napi_set_named_property(env, result, "sha256", digest) != napi_ok ||
        napi_create_double(env, (double)held->image.byte_count, &bytes) != napi_ok ||
        napi_set_named_property(env, result, "byteCount", bytes) != napi_ok ||
        napi_create_uint32(env, 0400, &mode) != napi_ok || napi_set_named_property(env, result, "mode", mode) != napi_ok)
        return NULL;
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
static napi_value prepared_import_close(napi_env env, napi_callback_info info) {
    prepared_import_candidate *held = prepared_import_receiver(env, info);
    if (!held) return NULL;
    if (held->retired) { napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL; }
    if (held->lease || atomic_load(&prepared_import_process.active) == held || prepared_import_check(held) != 0)
        return prepared_import_error(env, "candidate has a live/uncertain original SQLite or parent lease");
    /* Keep actual parent/self local handles while retiring strong references;
     * a reference failure must retain the parent's original child custody. */
    napi_value parent;
    if (napi_get_reference_value(env, held->parent_ref, &parent) != napi_ok) {
        prepared_import_poison(held); return prepared_import_error(env, "candidate parent reference is unavailable");
    }
    napi_ref parent_ref = held->parent_ref, owner_ref = held->owner_ref;
    held->parent_ref = held->owner_ref = NULL;
    if (napi_delete_reference(env, parent_ref) != napi_ok || napi_delete_reference(env, owner_ref) != napi_ok ||
        migrate_scope_release_candidate(held->parent, env, &held->image) != 0) {
        prepared_import_poison(held); return prepared_import_error(env, "candidate reference or parent borrow did not retire");
    }
    (void)parent;
    held->retired = 1;
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void prepared_import_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    prepared_import_candidate *held = data;
    if (held->retired && !held->lease && !held->uncertain && !held->parent_ref && !held->owner_ref) free(held);
}
static napi_value open_prepared_import_candidate(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; bool tagged = false;
    migration_filesystem *parent = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, arguments[0], &migration_filesystem_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&parent) != napi_ok || !parent || parent->env != env ||
        prepared_import_process.generation == UINT64_MAX)
        return kernel_global_error(env, "ERR_CLIQ_PREPARED_IMPORT_CANDIDATE", "candidate requires its original migration filesystem, no path or descriptor");
    prepared_import_candidate *held = calloc(1, sizeof(*held));
    if (!held) return kernel_global_error(env, "ERR_CLIQ_PREPARED_IMPORT_CANDIDATE", "candidate allocation failed");
    held->parent = parent; held->env = env; held->pid = getpid(); held->thread = pthread_self();
    held->generation = ++prepared_import_process.generation;
    if (migrate_scope_borrow_candidate(parent, env, &held->image) != 0) {
        free(held); return kernel_global_error(env, "ERR_CLIQ_PREPARED_IMPORT_CANDIDATE", "candidate is not the original sealed fixed image");
    }
    sha256_init(&held->hash);
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, prepared_import_assert, NULL, NULL, NULL, napi_default, NULL},
        {"verifyNext", NULL, prepared_import_verify_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginRead", NULL, prepared_import_begin_read, NULL, NULL, NULL, napi_default, NULL},
        {"endRead", NULL, prepared_import_end_read, NULL, NULL, NULL, napi_default, NULL},
        {"identity", NULL, prepared_import_identity, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, prepared_import_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (prepared_import_check(held) != 0 || held->image.byte_count > UINT64_C(9007199254740991) ||
        held->image.byte_count > INT64_MAX || (uint64_t)(off_t)held->image.byte_count != held->image.byte_count ||
        napi_create_reference(env, arguments[0], 1, &held->parent_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &prepared_import_candidate_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_wrap(env, result, held, prepared_import_finalize, NULL, NULL) != napi_ok ||
        napi_create_reference(env, result, 1, &held->owner_ref) != napi_ok) {
        prepared_import_poison(held);
        return prepared_import_error(env, "candidate construction did not retain its original parent/owner");
    }
    return result;
}

typedef struct { sqlite3_file base; prepared_import_candidate *held; uint64_t generation; int alive, lock; } prepared_import_file;
static int prepared_import_file_ready(prepared_import_file *file) {
    return kernel_global_main_thread() && file && file->alive && file->held &&
        file->generation == file->held->generation && file->held->lease == 1 &&
        file->held->phase == PREVIEW_READING && atomic_load(&prepared_import_process.active) == file->held &&
        prepared_import_check(file->held) == 0;
}
static int prepared_import_io_close(sqlite3_file *base) {
    prepared_import_file *file = (prepared_import_file *)base;
    if (!prepared_import_file_ready(file)) return SQLITE_IOERR_CLOSE;
    file->held->lease = 0; file->alive = 0; file->held = NULL; base->pMethods = NULL;
    return SQLITE_OK;
}
static int prepared_import_io_read(sqlite3_file *base, void *output, int amount, sqlite3_int64 offset) {
    prepared_import_file *file = (prepared_import_file *)base;
    if (!prepared_import_file_ready(file) || amount < 0 || offset < 0 || offset > INT64_MAX - amount ||
        (sqlite3_int64)(off_t)offset != offset || (sqlite3_int64)(off_t)(offset + amount) != offset + amount) return SQLITE_IOERR_READ;
    int consumed = 0;
    while (consumed < amount) {
        ssize_t count = pread(file->held->image.image_fd, (char *)output + consumed,
            (size_t)(amount - consumed), (off_t)(offset + consumed));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (count == 0 && (uint64_t)(offset + consumed) < file->held->image.byte_count)) {
            prepared_import_poison(file->held); return SQLITE_IOERR_READ;
        }
        if (!count) { memset((char *)output + consumed, 0, (size_t)(amount - consumed));
            return prepared_import_file_ready(file) ? SQLITE_IOERR_SHORT_READ : SQLITE_IOERR_READ; }
        consumed += (int)count;
    }
    return prepared_import_file_ready(file) ? SQLITE_OK : SQLITE_IOERR_READ;
}
static int prepared_import_io_write(sqlite3_file *base, const void *bytes, int amount, sqlite3_int64 offset) {
    (void)base; (void)bytes; (void)amount; (void)offset; return SQLITE_READONLY;
}
static int prepared_import_io_truncate(sqlite3_file *base, sqlite3_int64 amount) { (void)base; (void)amount; return SQLITE_READONLY; }
static int prepared_import_io_sync(sqlite3_file *base, int flags) { (void)base; (void)flags; return SQLITE_READONLY; }
static int prepared_import_io_size(sqlite3_file *base, sqlite3_int64 *size) {
    prepared_import_file *file = (prepared_import_file *)base;
    if (!prepared_import_file_ready(file)) return SQLITE_IOERR_FSTAT;
    *size = (sqlite3_int64)file->held->image.byte_count; return SQLITE_OK;
}
static int prepared_import_io_lock(sqlite3_file *base, int level) {
    prepared_import_file *file = (prepared_import_file *)base;
    if (!prepared_import_file_ready(file)) return SQLITE_IOERR_LOCK;
    if (level != SQLITE_LOCK_NONE && level != SQLITE_LOCK_SHARED) return SQLITE_READONLY;
    file->lock = level; return SQLITE_OK;
}
static int prepared_import_io_unlock(sqlite3_file *base, int level) { return prepared_import_io_lock(base, level); }
static int prepared_import_io_reserved(sqlite3_file *base, int *result) {
    if (!prepared_import_file_ready((prepared_import_file *)base)) return SQLITE_IOERR_CHECKRESERVEDLOCK;
    *result = 0; return SQLITE_OK;
}
static int prepared_import_io_control(sqlite3_file *base, int operation, void *argument) {
    prepared_import_file *file = (prepared_import_file *)base;
    if (!prepared_import_file_ready(file)) return SQLITE_IOERR;
    if (operation == SQLITE_FCNTL_LOCKSTATE) { *(int *)argument = file->lock; return SQLITE_OK; }
    if (operation == SQLITE_FCNTL_HAS_MOVED) { *(int *)argument = 0; return SQLITE_OK; }
    if (operation == SQLITE_FCNTL_MMAP_SIZE) { *(sqlite3_int64 *)argument = 0; return SQLITE_OK; }
    return SQLITE_NOTFOUND;
}
static int prepared_import_io_sector(sqlite3_file *base) { (void)base; return 4096; }
static int prepared_import_io_characteristics(sqlite3_file *base) { (void)base; return SQLITE_IOCAP_IMMUTABLE; }
static const sqlite3_io_methods prepared_import_io_methods = {
    .iVersion = 1, .xClose = prepared_import_io_close, .xRead = prepared_import_io_read,
    .xWrite = prepared_import_io_write, .xTruncate = prepared_import_io_truncate, .xSync = prepared_import_io_sync,
    .xFileSize = prepared_import_io_size, .xLock = prepared_import_io_lock, .xUnlock = prepared_import_io_unlock,
    .xCheckReservedLock = prepared_import_io_reserved, .xFileControl = prepared_import_io_control,
    .xSectorSize = prepared_import_io_sector, .xDeviceCharacteristics = prepared_import_io_characteristics
};
static int prepared_import_filename(const char *name) {
    if (!name) return -1;
    if (strcmp(name, prepared_import_name) == 0) return 0;
    if (strcmp(name, "/cliq-owned-import-preview-wal") == 0 || strcmp(name, "/cliq-owned-import-preview-shm") == 0 ||
        strcmp(name, "/cliq-owned-import-preview-journal") == 0) return 1;
    return -1;
}
static int prepared_import_vfs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *base, int flags, int *out_flags) {
    (void)vfs; base->pMethods = NULL;
    if (!kernel_global_main_thread() || prepared_import_filename(name) != 0 ||
        (flags & SQLITE_OPEN_MAIN_DB) == 0 || (flags & SQLITE_OPEN_READONLY) == 0 ||
        (flags & (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_MEMORY |
        SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_WAL |
        SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL)) != 0) return SQLITE_CANTOPEN;
    prepared_import_candidate *held = atomic_load(&prepared_import_process.active);
    if (!held || held->phase != PREVIEW_READING || prepared_import_check(held) != 0) return SQLITE_CANTOPEN;
    if (held->lease) return SQLITE_BUSY;
    prepared_import_file *file = (prepared_import_file *)base;
    file->held = held; file->generation = held->generation; file->alive = 1; file->lock = SQLITE_LOCK_NONE;
    held->lease = 1; base->pMethods = &prepared_import_io_methods;
    if (out_flags) *out_flags = flags;
    return SQLITE_OK;
}
static int prepared_import_vfs_delete(sqlite3_vfs *vfs, const char *name, int sync) { (void)vfs; (void)name; (void)sync; return SQLITE_READONLY; }
static int prepared_import_vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
    (void)vfs; *result = 0;
    if (!kernel_global_main_thread() || prepared_import_filename(name) < 0 ||
        (flags != SQLITE_ACCESS_EXISTS && flags != SQLITE_ACCESS_READ && flags != SQLITE_ACCESS_READWRITE)) return SQLITE_IOERR_ACCESS;
    prepared_import_candidate *held = atomic_load(&prepared_import_process.active);
    if (!held || held->phase != PREVIEW_READING || prepared_import_check(held) != 0) return SQLITE_IOERR_ACCESS;
    *result = prepared_import_filename(name) == 0 && flags != SQLITE_ACCESS_READWRITE;
    return SQLITE_OK;
}
static int prepared_import_vfs_path(sqlite3_vfs *vfs, const char *name, int length, char *output) {
    (void)vfs;
    if (!name || (strcmp(name, "cliq-owned-import-preview") != 0 && strcmp(name, prepared_import_name) != 0) ||
        length < (int)sizeof(prepared_import_name)) return SQLITE_CANTOPEN;
    memcpy(output, prepared_import_name, sizeof(prepared_import_name)); return SQLITE_OK;
}
static void *prepared_import_vfs_dl_open(sqlite3_vfs *vfs, const char *name) { (void)vfs; (void)name; return NULL; }
static void prepared_import_vfs_dl_error(sqlite3_vfs *vfs, int size, char *output) {
    (void)vfs; if (size > 0) snprintf(output, (size_t)size, "%s", "prepared import VFS cannot load extensions");
}
static void (*prepared_import_vfs_dl_sym(sqlite3_vfs *vfs, void *image, const char *name))(void) { (void)vfs; (void)image; (void)name; return NULL; }
static void prepared_import_vfs_dl_close(sqlite3_vfs *vfs, void *image) { (void)vfs; (void)image; }
static int prepared_import_vfs_random(sqlite3_vfs *vfs, int count, char *output) { (void)vfs; return prepared_import_process.base->xRandomness(prepared_import_process.base, count, output); }
static int prepared_import_vfs_sleep(sqlite3_vfs *vfs, int micros) { (void)vfs; return prepared_import_process.base->xSleep(prepared_import_process.base, micros); }
static int prepared_import_vfs_time(sqlite3_vfs *vfs, double *time) { (void)vfs; return prepared_import_process.base->xCurrentTime(prepared_import_process.base, time); }
static int prepared_import_vfs_time64(sqlite3_vfs *vfs, sqlite3_int64 *time) {
    (void)vfs; sqlite3_vfs *base = prepared_import_process.base;
    if (base->iVersion >= 2 && base->xCurrentTimeInt64) return base->xCurrentTimeInt64(base, time);
    double original; int result = base->xCurrentTime(base, &original);
    if (result == SQLITE_OK) *time = (sqlite3_int64)(original * 86400000.0);
    return result;
}
__attribute__((visibility("default"))) int sqlite3_cliqownedimportpreview_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
    (void)database; (void)error;
    if (!kernel_global_main_thread()) return SQLITE_ERROR;
    prepared_import_candidate *held = atomic_load(&prepared_import_process.active);
    if (!held || held->phase != PREVIEW_READING || prepared_import_check(held) != 0 || !api ||
        !api->sourceid || !api->vfs_find || !api->vfs_register || (sqlite3_api && sqlite3_api != api)) return SQLITE_ERROR;
    SQLITE_EXTENSION_INIT2(api);
    if (prepared_import_process.registered)
        return sqlite3_vfs_find(prepared_import_vfs_name) == &prepared_import_process.vfs ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
    sqlite3_vfs *base = sqlite3_vfs_find(NULL);
    if (!base || !base->xRandomness || !base->xSleep || !base->xCurrentTime || sqlite3_vfs_find(prepared_import_vfs_name)) return SQLITE_ERROR;
    prepared_import_process.base = base;
    prepared_import_process.vfs = (sqlite3_vfs) {
        .iVersion = 2, .szOsFile = sizeof(prepared_import_file), .mxPathname = 128,
        .zName = prepared_import_vfs_name, .xOpen = prepared_import_vfs_open, .xDelete = prepared_import_vfs_delete,
        .xAccess = prepared_import_vfs_access, .xFullPathname = prepared_import_vfs_path,
        .xDlOpen = prepared_import_vfs_dl_open, .xDlError = prepared_import_vfs_dl_error,
        .xDlSym = prepared_import_vfs_dl_sym, .xDlClose = prepared_import_vfs_dl_close,
        .xRandomness = prepared_import_vfs_random, .xSleep = prepared_import_vfs_sleep,
        .xCurrentTime = prepared_import_vfs_time, .xCurrentTimeInt64 = prepared_import_vfs_time64
    };
    if (sqlite3_vfs_register(&prepared_import_process.vfs, 0) != SQLITE_OK) return SQLITE_ERROR;
    prepared_import_process.registered = 1;
    return SQLITE_OK_LOAD_PERMANENTLY;
}
