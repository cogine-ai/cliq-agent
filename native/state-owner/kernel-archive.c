/* Fixed original-FD destination for the original live connection's online
 * backup. Included after kernel-global-gate.c, source-walk.c and publication.c.
 * The caller's closed rollback decoder authenticates the exact control bytes;
 * native independently holds and completely compares the fixed control file.
 * No caller path/FD/SQL, replacement connection, default VFS or old creator's
 * scope is accepted. Real Linux qualification (including Stop2) is separate. */
#ifdef __APPLE__
#include <sys/random.h>
#endif
#define KERNEL_ARCHIVE_CONTROL_BYTES 1048576U
#define KERNEL_ARCHIVE_MAX_BYTES UINT64_C(53687091200)
enum kernel_archive_phase {
    KA_BORN, KA_BACKUP, KA_JOINED, KA_HASH_WRITABLE, KA_HASH_READONLY,
    KA_SEALED, KA_READING, KA_RECHECK, KA_FAILED, KA_RETIRED
};
enum kernel_archive_role { KA_MAIN, KA_JOURNAL };
typedef struct kernel_archive kernel_archive;
typedef struct kernel_archive_namespace kernel_archive_namespace;
typedef struct kernel_archive_models kernel_archive_models;
typedef struct kernel_archive_file {
    sqlite3_file base;
    kernel_archive *held;
    uint64_t generation;
    int role, alive, lock;
} kernel_archive_file;
struct kernel_archive {
    migration_credential_gate *binding;
    napi_env env;
    napi_ref binding_ref, self_ref;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    pthread_t main_thread;
    uint64_t generation;
    int root_fd, runtime_fd, migration_fd, collection_fd, directory_fd, control_fd;
    int rejection_parent_fd, rejection_fd, read_rejection_fd, image_fd, journal_fd;
    struct stat root, runtime, migration, collection, directory, control;
    struct stat rejection_parent, rejection, read_rejection, birth, image, journal, hash_before;
    int gate_fd, owner_lock_fd;
    struct stat gate, owner_lock;
    char migration_id[44], archive_id[44], nonce[65], uri[256], rejection_leaf[NAME_MAX + 1];
    char read_rejection_leaf[NAME_MAX + 1];
    char control_content_digest[65], image_digest[65];
    size_t control_size;
    uint64_t offset, byte_count;
    struct sha256_context hash;
    enum kernel_archive_phase phase;
    atomic_int cancelled, uncertain, opens_closed;
    int failed, borrowed, wrapped, journal_present, main_live, journal_live;
    int readonly, commit_phase_two_observed;
    mode_t image_mode;
    uint64_t main_opens, main_closes, journal_opens, journal_closes;
    uint64_t journal_births, journal_deletions, read_opens, read_closes, read_open_cut;
    kernel_archive_file *main_file;
    kernel_archive_namespace *cas;
    kernel_archive_models *models;
    rw_archive *runtime_witnesses;
    migration_filesystem *rollback_source;
    napi_ref rollback_reference;
};
static int kans_custody(kernel_archive *held);
static int kans_retire(kernel_archive *held);
static int kam_custody(kernel_archive *held);
static int kam_retire(kernel_archive *held);
static int kam_capture_complete(kernel_archive *held);
static const napi_type_tag kernel_archive_tag = {0xc079250a64b3391fULL, 0xb0e72c63178d95abULL};
/* One mutex protects the active pointer and every SQLite lease/FD operation.
 * It deliberately does not identify a persistent libuv worker pthread. */
static pthread_mutex_t kernel_archive_mutex = PTHREAD_MUTEX_INITIALIZER;
static kernel_archive *kernel_archive_active;
static uint64_t kernel_archive_generation;
static struct { int registered; sqlite3_vfs *base; sqlite3_vfs vfs; } kernel_archive_process;
static const char kernel_archive_name[] = "/cliq-owned-archive";
static const char kernel_archive_journal_name[] = "/cliq-owned-archive-journal";
static const char kernel_archive_vfs_name[] = "cliq-owned-archive-target-v1";

static int ka_process(const kernel_archive *held) {
    return held && held->pid == getpid() && held->uid == getuid() && held->uid == geteuid() &&
        held->gid == getgid() && held->gid == getegid();
}
static int ka_directory(const kernel_archive *held, const struct stat *observed) {
    return S_ISDIR(observed->st_mode) && observed->st_uid == held->uid &&
        observed->st_gid == held->gid && (observed->st_mode & 07777) == 0700;
}
static int ka_regular(const kernel_archive *held, const struct stat *observed, mode_t mode) {
    return S_ISREG(observed->st_mode) && observed->st_uid == held->uid && observed->st_gid == held->gid &&
        (observed->st_mode & 07777) == mode && observed->st_nlink == 1 && observed->st_size >= 0;
}
static void ka_uncertain(kernel_archive *held) {
    atomic_store(&held->uncertain, 1);
    atomic_store(&kernel_global_poisoned, 1);
}
static void ka_main_poison(kernel_archive *held) {
    ka_uncertain(held);
    held->binding->uncertain = 1;
    held->binding->owner->migration_retirement_error = 1;
}
static int ka_close_fd(kernel_archive *held, int *descriptor) {
    int original = *descriptor;
    *descriptor = -1; /* Never retry a consumed number, even on close error. */
    if (original < 0 || close(original) == 0) return 0;
    ka_uncertain(held);
    return -1;
}
static int ka_named_directory(kernel_archive *held, int parent, const char *leaf,
                              int descriptor, const struct stat *identity) {
    struct stat opened, named;
    return descriptor >= 0 && fstat(descriptor, &opened) == 0 && ka_directory(held, &opened) &&
        same_inode(&opened, identity) && fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        ka_directory(held, &named) && same_inode(&opened, &named);
}
static int ka_named_file(kernel_archive *held, int parent, const char *leaf, int descriptor,
                         const struct stat *identity, mode_t mode, int exact) {
    struct stat opened, named;
    return descriptor >= 0 && fstat(descriptor, &opened) == 0 && ka_regular(held, &opened, mode) &&
        same_inode(&opened, identity) && (!exact || source_metadata_same(&opened, identity)) &&
        fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&opened, &named);
}
/* Until the complete separately locked local-model store is archived, its
 * exact descriptor-relative absence is mandatory. Empty rows or a missing
 * path string cannot substitute; present, symlink or inaccessible refuses. */
static int ka_local_model_store_absent(const kernel_archive *held) {
    struct stat observed;
    return fstatat(held->root_fd, "local-models", &observed, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
/* Retained native service witnesses need their original-claim visitor too.
 * Until that complete namespace is captured, even an empty present directory
 * is not silently called an absent/archived service resource domain. */
static int ka_local_inference_runtime_absent(const kernel_archive *held) {
    struct stat observed;
    return fstatat(held->runtime_fd, "local-inference", &observed, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
/* Worker-safe custody observation only: no NAPI, main-thread guard, NSS lookup,
 * clock or mutable StateOwner bookkeeping is read on a SQLite worker thread.
 * Strong parent references and the original borrower count prevent retirement. */
static int ka_custody(kernel_archive *held) {
    struct stat observed, cwd;
    if (!ka_process(held) || held->phase == KA_RETIRED || atomic_load(&held->uncertain) ||
        atomic_load(&kernel_global_poisoned) || atomic_load(&current_process_retirement_failed) ||
        fstat(held->root_fd, &observed) != 0 || !same_inode(&observed, &held->root) ||
        observed.st_uid != held->root.st_uid || observed.st_gid != held->root.st_gid ||
        observed.st_mode != held->root.st_mode || stat(".", &cwd) != 0 || !same_inode(&observed, &cwd) ||
        fstat(held->gate_fd, &observed) != 0 || !same_inode(&observed, &held->gate) ||
        observed.st_uid != held->uid || (observed.st_mode & 07777) != 0600 || observed.st_nlink != 1 ||
        fstat(held->owner_lock_fd, &observed) != 0 || !same_inode(&observed, &held->owner_lock) ||
        observed.st_uid != held->uid || (observed.st_mode & 07777) != 0600 || observed.st_nlink != 1 ||
        !ka_named_directory(held, held->root_fd, "runtime", held->runtime_fd, &held->runtime) ||
        !ka_named_directory(held, held->root_fd, "migration", held->migration_fd, &held->migration) ||
        !ka_named_directory(held, held->migration_fd, "kernel-archives", held->collection_fd, &held->collection) ||
        !ka_named_directory(held, held->collection_fd, held->archive_id, held->directory_fd, &held->directory) ||
        !ka_named_directory(held, held->root_fd, "file:", held->rejection_parent_fd, &held->rejection_parent) ||
        !ka_named_directory(held, held->rejection_parent_fd, held->rejection_leaf, held->rejection_fd, &held->rejection) ||
        !ka_named_file(held, held->migration_fd, "control-v1.json", held->control_fd, &held->control, 0600, 1) ||
        !ka_named_file(held, held->directory_fd, "kernel.sqlite3", held->image_fd, held->readonly ? &held->image : &held->birth,
            held->image_mode, held->readonly)) return -1;
    if (held->journal_present) {
        if (!ka_named_file(held, held->directory_fd, "kernel.sqlite3-journal", held->journal_fd,
            &held->journal, 0600, 0)) return -1;
    } else if (fstatat(held->directory_fd, "kernel.sqlite3-journal", &observed, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1;
    if (held->read_rejection_fd >= 0 && !ka_named_directory(held, held->rejection_parent_fd,
        held->read_rejection_leaf, held->read_rejection_fd, &held->read_rejection)) return -1;
    static const char *const forbidden[] = {"kernel.sqlite3-wal", "kernel.sqlite3-shm"};
    for (size_t index = 0; index < sizeof(forbidden) / sizeof(forbidden[0]); ++index)
        if (fstatat(held->directory_fd, forbidden[index], &observed, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return -1;
    if (kans_custody(held) != 0) return -1;
    if (held->runtime_witnesses) {
        if (!rw_source_custody(held->runtime_witnesses)) return -2;
        if (rw_custody(held->runtime_witnesses) != 0) return -1;
    } else if (!ka_local_inference_runtime_absent(held)) return -2;
    return kam_custody(held);
}
static int ka_main_context(kernel_archive *held, napi_env env) {
    return kernel_global_main_thread() && ka_process(held) && held->env == env &&
        pthread_equal(held->main_thread, pthread_self());
}
static int ka_main_check(kernel_archive *held, napi_env env) {
    if (!ka_main_context(held, env) || held->phase == KA_RETIRED || atomic_load(&held->uncertain)) return -1;
    if (migration_credential_check(held->binding, env) != 0) {
        ka_main_poison(held);
        return -1;
    }
    int custody = ka_custody(held);
    if (custody != 0) {
        if (custody == -2) held->failed = 1; /* source data refusal, not a fake FD close failure */
        else ka_main_poison(held);
        return -1;
    }
    return 0;
}
static int ka_control_bytes(kernel_archive *held, const unsigned char *expected) {
    unsigned char bytes[65536];
    struct stat before, after;
    struct sha256_context hash;
    sha256_init(&hash);
    if (fstat(held->control_fd, &before) != 0 || !source_metadata_same(&before, &held->control)) return -1;
    size_t offset = 0;
    while (offset < held->control_size) {
        size_t amount = held->control_size - offset;
        if (amount > sizeof(bytes)) amount = sizeof(bytes);
        ssize_t count;
        do { count = pread(held->control_fd, bytes, amount, (off_t)offset); } while (count < 0 && errno == EINTR);
        if (count <= 0 || (size_t)count > amount || (expected && memcmp(bytes, expected + offset, (size_t)count))) return -1;
        sha256_update(&hash, bytes, (size_t)count);
        offset += (size_t)count;
    }
    ssize_t end;
    do { end = pread(held->control_fd, bytes, 1, (off_t)offset); } while (end < 0 && errno == EINTR);
    char digest[65];
    publication_hash_hex(&hash, digest);
    return end == 0 && strcmp(digest, held->control_content_digest) == 0 &&
        fstat(held->control_fd, &after) == 0 && source_metadata_same(&before, &after) ? 0 : -1;
}
static napi_value ka_error(napi_env env, kernel_archive *held, const char *message) {
    if (held && atomic_load(&held->uncertain)) ka_main_poison(held);
    return kernel_global_error(env, held && atomic_load(&held->uncertain) ?
        "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_KERNEL_ARCHIVE", message);
}
static kernel_archive *ka_receiver(napi_env env, napi_callback_info info) {
    size_t count = 1;
    napi_value self, argument;
    bool tagged = false;
    kernel_archive *held = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
        napi_check_object_type_tag(env, self, &kernel_archive_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&held) != napi_ok || !ka_main_context(held, env)) {
        ka_error(env, NULL, "invalid original archive receiver or arguments");
        return NULL;
    }
    return held;
}
static int ka_main_lock(napi_env env, kernel_archive *held) {
    if (pthread_mutex_trylock(&kernel_archive_mutex) == 0) return 0;
    ka_error(env, held, "archive SQLite I/O has not joined");
    return -1;
}
static napi_value ka_undefined(napi_env env) {
    napi_value value;
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static int ka_string_member(napi_env env, napi_value object, const char *key, const char *text) {
    napi_value value;
    return napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &value) == napi_ok &&
        napi_set_named_property(env, object, key, value) == napi_ok;
}
static int ka_count_member(napi_env env, napi_value object, const char *key, uint64_t count) {
    napi_value value;
    return count <= UINT64_C(9007199254740991) && napi_create_double(env, (double)count, &value) == napi_ok &&
        napi_set_named_property(env, object, key, value) == napi_ok;
}
static napi_value ka_observation(napi_env env, kernel_archive *held, int sealed) {
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok ||
        !identity_member(env, result, "stateRoot", &held->root) ||
        !identity_member(env, result, "migrationDirectory", &held->migration) ||
        !identity_member(env, result, "archiveCollection", &held->collection) ||
        !identity_member(env, result, "archiveDirectory", &held->directory) ||
        !identity_member(env, result, "controlFile", &held->control) ||
        !identity_member(env, result, "file", sealed ? &held->image : &held->birth) ||
        !ka_string_member(env, result, "migrationId", held->migration_id) ||
        !ka_string_member(env, result, "archiveId", held->archive_id) ||
        !ka_string_member(env, result, "controlContentDigest", held->control_content_digest) ||
        !ka_string_member(env, result, "localInferenceRuntime", held->runtime_witnesses ? "present" : "absent") ||
        !ka_string_member(env, result, "localModelStore", held->models ? "present" : "absent") ||
        !ka_count_member(env, result, "mode", (uint64_t)((sealed ? held->image.st_mode : held->birth.st_mode) & 07777)) ||
        !ka_count_member(env, result, "linkCount", (uint64_t)(sealed ? held->image.st_nlink : held->birth.st_nlink))) return NULL;
    if (sealed && (!ka_string_member(env, result, "sha256", held->image_digest) ||
        !ka_count_member(env, result, "byteCount", held->byte_count))) return NULL;
    return napi_object_freeze(env, result) == napi_ok ? result : NULL;
}
static napi_value ka_assert(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "archive original custody changed or retired");
}
static napi_value ka_birth(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0;
    napi_value result = valid ? ka_observation(env, held, 0) : NULL;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "archive birth requires its original held objects");
}
static napi_value ka_begin_backup(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_BORN && !held->failed &&
        !atomic_load(&held->cancelled) && !kernel_archive_active && ka_control_bytes(held, NULL) == 0;
    napi_value result = NULL;
    if (valid) {
        kernel_archive_active = held;
        held->phase = KA_BACKUP;
        if (napi_create_string_utf8(env, held->uri, NAPI_AUTO_LENGTH, &result) != napi_ok) {
            held->failed = 1;
            atomic_store(&held->cancelled, 1);
        }
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "archive backup requires its original unused lease and exact durable control");
}
static napi_value ka_cancel(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held) return NULL;
    /* Revocation cannot wait behind a worker's real blocking fsync. It is not
     * a successful close, rollback, join or proof of an unchanged image. */
    atomic_store(&held->cancelled, 1);
    atomic_store(&held->opens_closed, 1);
    return ka_undefined(env);
}
static int ka_retire_journal(kernel_archive *held) {
    if (!held->journal_present) return held->journal_fd < 0 ? 0 : -1;
    if (held->journal_live || !ka_named_file(held, held->directory_fd, "kernel.sqlite3-journal",
        held->journal_fd, &held->journal, 0600, 0)) return -1;
    if (unlinkat(held->directory_fd, "kernel.sqlite3-journal", 0) != 0) return -1;
    held->journal_present = 0;
    held->journal_deletions++;
    if (fsync(held->directory_fd) != 0 || ka_close_fd(held, &held->journal_fd) != 0) return -1;
    return 0;
}
static napi_value ka_join(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held) return NULL;
    /* This is a post-Node-settlement assertion, not an asynchronous wait. A
     * premature caller cannot authorize a future open after this cut. Holding
     * the mutex below then proves no SQLite callback is still in flight. */
    atomic_store(&held->opens_closed, 1);
    if (ka_main_lock(env, held) != 0) return NULL;
    int valid = held->phase == KA_BACKUP && kernel_archive_active == held &&
        ka_main_check(held, env) == 0 && !held->main_live && !held->journal_live &&
        held->main_opens == held->main_closes && held->journal_opens == held->journal_closes &&
        ka_control_bytes(held, NULL) == 0;
    if (valid && held->journal_present) {
        /* Only this holder's actual journal birth may be retired. A cancelled
         * destination is never reused as an archive, even if cleanup succeeds. */
        if (!held->failed && !atomic_load(&held->cancelled)) valid = 0;
        else if (ka_retire_journal(held) != 0) { ka_main_poison(held); valid = 0; }
    }
    napi_value result = NULL;
    if (valid) {
        const char *outcome = atomic_load(&held->cancelled) ? "cancelled" : held->failed ? "failed" :
            held->main_opens != 1 ? "not_selected" : held->commit_phase_two_observed ? "commit_phase_two_observed" : "no_commit_phase_two";
        held->phase = !strcmp(outcome, "commit_phase_two_observed") ? KA_JOINED : KA_FAILED;
        kernel_archive_active = NULL;
        if (napi_create_object(env, &result) != napi_ok || !ka_string_member(env, result, "outcome", outcome) ||
            !ka_count_member(env, result, "mainOpens", held->main_opens) || !ka_count_member(env, result, "mainCloses", held->main_closes) ||
            !ka_count_member(env, result, "journalOpens", held->journal_opens) || !ka_count_member(env, result, "journalCloses", held->journal_closes) ||
            !ka_count_member(env, result, "journalBirths", held->journal_births) || !ka_count_member(env, result, "journalDeletions", held->journal_deletions) ||
            napi_object_freeze(env, result) != napi_ok) result = NULL;
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "original Node operation and every archive file lease must actually join");
}
static int ka_read_hash_chunk(kernel_archive *held, int compare) {
    unsigned char bytes[65536];
    struct stat observed;
    if (fstat(held->image_fd, &observed) != 0 || !source_metadata_same(&observed, &held->hash_before)) return -1;
    uint64_t remaining = held->byte_count - held->offset;
    size_t amount = remaining < sizeof(bytes) ? (size_t)remaining : sizeof(bytes), consumed = 0;
    if (amount) {
        ssize_t count;
        do { count = pread(held->image_fd, bytes, amount, (off_t)held->offset); } while (count < 0 && errno == EINTR);
        if (count <= 0 || (size_t)count > amount) return -1;
        consumed = (size_t)count;
    }
    sha256_update(&held->hash, bytes, consumed);
    held->offset += consumed;
    if (fstat(held->image_fd, &observed) != 0 || !source_metadata_same(&observed, &held->hash_before)) return -1;
    if (held->offset != held->byte_count) return 0;
    ssize_t end;
    do { end = pread(held->image_fd, bytes, 1, (off_t)held->offset); } while (end < 0 && errno == EINTR);
    char digest[65];
    struct sha256_context hash = held->hash;
    publication_hash_hex(&hash, digest);
    if (end != 0 || (compare && strcmp(digest, held->image_digest))) return -1;
    if (!compare) memcpy(held->image_digest, digest, sizeof(digest));
    return 1;
}
static napi_value ka_seal_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && !held->failed && !atomic_load(&held->cancelled) &&
        !kernel_archive_active && !held->main_live && !held->journal_live && !held->journal_present;
    if (valid && held->phase == KA_JOINED) {
        valid = held->commit_phase_two_observed && ka_control_bytes(held, NULL) == 0 &&
            fsync(held->image_fd) == 0 && fsync(held->directory_fd) == 0 &&
            fstat(held->image_fd, &held->hash_before) == 0 && held->hash_before.st_size >= 100 &&
            (uint64_t)held->hash_before.st_size <= KERNEL_ARCHIVE_MAX_BYTES;
        if (valid) {
            held->byte_count = (uint64_t)held->hash_before.st_size;
            held->offset = 0;
            sha256_init(&held->hash);
            held->phase = KA_HASH_WRITABLE;
        }
    }
    if (valid && (held->phase == KA_HASH_WRITABLE || held->phase == KA_HASH_READONLY || held->phase == KA_RECHECK)) {
        int complete = ka_read_hash_chunk(held, held->phase != KA_HASH_WRITABLE);
        if (complete < 0) valid = 0;
        else if (complete && held->phase == KA_HASH_WRITABLE) {
            int readonly = -1;
            struct stat observed;
            valid = fchmod(held->image_fd, 0400) == 0;
            /* Record our real chmod even if a later seal sync fails. That
             * partial image is not an archive, but its original writable FD
             * must still be able to retire under its actual current mode. */
            if (valid) held->image_mode = 0400;
            valid = valid && fsync(held->image_fd) == 0 &&
                fsync(held->directory_fd) == 0 && fstat(held->image_fd, &observed) == 0 &&
                ka_regular(held, &observed, 0400) && same_inode(&observed, &held->birth) &&
                (uint64_t)observed.st_size == held->byte_count;
            if (valid) {
                readonly = openat(held->directory_fd, "kernel.sqlite3", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                valid = readonly >= 0 && fstat(readonly, &held->image) == 0 && source_metadata_same(&observed, &held->image);
            }
            if (valid) {
                /* The readonly description exists before consuming the one
                 * original writable description. A failed close retains the
                 * readonly custody and original EX, never retries the number. */
                int writable = held->image_fd;
                held->image_fd = readonly;
                readonly = -1;
                held->readonly = 1;
                if (ka_close_fd(held, &writable) != 0) valid = 0;
                held->hash_before = held->image;
                held->offset = 0;
                sha256_init(&held->hash);
                held->phase = KA_HASH_READONLY;
            }
            if (readonly >= 0 && ka_close_fd(held, &readonly) != 0) valid = 0;
        } else if (complete) {
            valid = ka_control_bytes(held, NULL) == 0;
            if (valid) held->phase = KA_SEALED;
        }
    } else if (valid && held->phase != KA_SEALED) valid = 0;
    if (!valid) held->failed = 1;
    int done = valid && held->phase == KA_SEALED;
    pthread_mutex_unlock(&kernel_archive_mutex);
    if (!valid) return ka_error(env, held, "archive seal requires complete original bytes and every writable description closed");
    napi_value result;
    return napi_get_boolean(env, done != 0, &result) == napi_ok ? result : NULL;
}
static napi_value ka_identity(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && held->readonly &&
        !held->failed && !atomic_load(&held->cancelled);
    napi_value result = valid ? ka_observation(env, held, 1) : NULL;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "archive identity requires complete joined readonly verification");
}
static napi_value ka_begin_read(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !kernel_archive_active && !held->read_opens &&
        !held->failed && !atomic_load(&held->cancelled) && ka_control_bytes(held, NULL) == 0;
    napi_value result = NULL;
    if (valid) {
        char uri[256];
        int length = snprintf(uri, sizeof(uri), "file:%s?mode=ro&vfs=%s&cliq_archive_lease=%s", kernel_archive_name, kernel_archive_vfs_name, held->nonce);
        /* Readonly URI must also have a complete literal rejection directory.
         * Reuse the backup literal only for backup; no path fallback is allowed. */
        valid = length > 0 && (size_t)length < sizeof(uri);
        if (valid) {
            /* The fixed read URI differs only in mode. Its literal directory
             * is born before the caller can receive it, under the held parent. */
            const char *leaf = uri + sizeof("file:/") - 1;
            struct stat before, after;
            int fd = -1;
            valid = mkdirat(held->rejection_parent_fd, leaf, 0700) == 0;
            if (valid) fd = openat(held->rejection_parent_fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            valid = valid && fd >= 0 && fstat(fd, &before) == 0 && ka_directory(held, &before) &&
                fsync(fd) == 0 && fsync(held->rejection_parent_fd) == 0 &&
                fstatat(held->rejection_parent_fd, leaf, &after, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&before, &after);
            /* Keep both actually born rejection directories through final
             * close. A name alone cannot stand in for the old directory FD. */
            if (valid) {
                held->read_rejection_fd = fd;
                fd = -1;
                held->read_rejection = before;
                strcpy(held->read_rejection_leaf, leaf);
            } else valid = 0;
            if (fd >= 0 && ka_close_fd(held, &fd) != 0) valid = 0;
        }
        if (valid) {
            kernel_archive_active = held;
            held->phase = KA_READING;
            atomic_store(&held->opens_closed, 0);
            held->read_open_cut = held->read_opens;
            if (napi_create_string_utf8(env, uri, NAPI_AUTO_LENGTH, &result) != napi_ok) held->failed = 1;
        }
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "archive readonly projection requires its complete original sealed image");
}
static napi_value ka_end_read(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held) return NULL;
    atomic_store(&held->opens_closed, 1);
    if (ka_main_lock(env, held) != 0) return NULL;
    int valid = ka_main_check(held, env) == 0 && held->phase == KA_READING && kernel_archive_active == held &&
        !held->main_live && !held->journal_live && held->read_opens <= held->read_open_cut + 1 &&
        held->read_opens == held->read_closes && ka_control_bytes(held, NULL) == 0;
    if (valid) {
        kernel_archive_active = NULL;
        held->phase = held->read_opens == held->read_open_cut + 1 ? KA_RECHECK : KA_FAILED;
        if (held->phase == KA_FAILED) held->failed = 1;
        held->offset = 0;
        held->hash_before = held->image;
        sha256_init(&held->hash);
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "archive readonly projection has not actually closed its original lease");
}
static int ka_retire(kernel_archive *held) {
    if (atomic_load(&held->uncertain) || kernel_archive_active == held || held->main_live || held->journal_live) return -1;
    int incomplete_models = !kam_capture_complete(held);
    if (ka_retire_journal(held) != 0 || kans_retire(held) != 0 || kam_retire(held) != 0) return -1;
    int incomplete_runtime = held->runtime_witnesses && held->runtime_witnesses->phase != RW_COMPLETE;
    if (rw_retire(held->runtime_witnesses) != 0) return -1;
    held->runtime_witnesses = NULL;
    /* Only exact original, empty, private rejection directories are removed.
     * They are not persistent archive data and do not accumulate per attempt.
     * A partial/failed removal is never relabelled as a joined clean scope. */
    int *const rejection_descriptors[] = {&held->read_rejection_fd, &held->rejection_fd};
    const char *const rejection_names[] = {held->read_rejection_leaf, held->rejection_leaf};
    const struct stat *const rejection_ids[] = {&held->read_rejection, &held->rejection};
    for (size_t index = 0; index < sizeof(rejection_descriptors) / sizeof(rejection_descriptors[0]); ++index) {
        int descriptor = *rejection_descriptors[index];
        if (descriptor < 0) continue;
        struct stat observed;
        if (!ka_named_directory(held, held->rejection_parent_fd, rejection_names[index], descriptor, rejection_ids[index]) ||
            unlinkat(held->rejection_parent_fd, rejection_names[index], AT_REMOVEDIR) != 0 ||
            fstat(descriptor, &observed) != 0 || !same_inode(&observed, rejection_ids[index]) || observed.st_nlink != 0 ||
            fsync(held->rejection_parent_fd) != 0 || ka_close_fd(held, rejection_descriptors[index]) != 0) {
            ka_uncertain(held);
            return -1;
        }
    }
    int *const descriptors[] = {&held->image_fd, &held->control_fd, &held->rejection_parent_fd,
        &held->directory_fd, &held->collection_fd, &held->migration_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (ka_close_fd(held, descriptors[index]) != 0) return -1;
    if (held->self_ref) {
        napi_ref self_ref = held->self_ref;
        held->self_ref = NULL;
        if (napi_delete_reference(held->env, self_ref) != napi_ok) { ka_main_poison(held); return -1; }
    }
    if (held->borrowed) {
        napi_ref binding_ref = held->binding_ref;
        held->binding_ref = NULL;
        if (!binding_ref || napi_delete_reference(held->env, binding_ref) != napi_ok) { ka_main_poison(held); return -1; }
        held->binding->borrowers--;
        held->borrowed = 0;
    }
    if (held->rollback_source) {
        if (ci_return_original_archive_loan(held->env, held->rollback_source, held->rollback_reference,
            held->failed || atomic_load(&held->cancelled) || incomplete_runtime || incomplete_models || !held->readonly) != 0) return -1;
        held->rollback_source = NULL; held->rollback_reference = NULL;
    }
    held->phase = KA_RETIRED;
    return 0;
}
static napi_value ka_close(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info);
    if (!held) return NULL;
    if (held->phase == KA_RETIRED) return ka_undefined(env);
    if (ka_main_lock(env, held) != 0) return NULL;
    int custody = ka_custody(held);
    int observed = ka_main_context(held, env) && migration_credential_check(held->binding, env) == 0 &&
        !atomic_load(&held->uncertain) && (custody == 0 || (custody == -2 && (held->failed || atomic_load(&held->cancelled))));
    /* Namespace descriptors are ours to consume even after custody drift.
     * Consume all of them once, while retaining poisoned Owner/EX rather than
     * confusing a descriptor join with successful archive qualification. */
    int namespace_joined = kans_retire(held) == 0;
    int valid = observed && namespace_joined && ka_control_bytes(held, NULL) == 0 && ka_retire(held) == 0;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "archive original resources did not retire; original owner retained");
}
static void ka_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    kernel_archive *held = data;
    /* No finalizer performs an unobserved close or retries consumed numbers. */
    if (held->phase == KA_RETIRED && !atomic_load(&held->uncertain) && !held->binding_ref && !held->self_ref) free(held);
}
static int ka_hold_directory(kernel_archive *held, int parent, const char *leaf, int *descriptor,
                              struct stat *identity, int exclusive) {
    int created = mkdirat(parent, leaf, 0700) == 0;
    if (!created && (exclusive || errno != EEXIST)) return -1;
    *descriptor = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*descriptor < 0 || fstat(*descriptor, identity) != 0 || !ka_directory(held, identity) ||
        !ka_named_directory(held, parent, leaf, *descriptor, identity)) return -1;
    return !created || (fsync(*descriptor) == 0 && fsync(parent) == 0) ? 0 : -1;
}
#include "kernel-archive-namespace.h"
#include "kernel-archive-model-store.h"
#include "kernel-archive-runtime-witness-bindings.h"

static int ka_make_nonce(kernel_archive *held) {
    unsigned char bytes[32];
    if (getentropy(bytes, sizeof(bytes)) != 0) return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof(bytes); ++index) {
        held->nonce[index * 2] = hex[bytes[index] >> 4];
        held->nonce[index * 2 + 1] = hex[bytes[index] & 15];
    }
    held->nonce[64] = '\0';
    int length = snprintf(held->uri, sizeof(held->uri), "file:%s?mode=rw&vfs=%s&cliq_archive_lease=%s",
        kernel_archive_name, kernel_archive_vfs_name, held->nonce);
    if (length <= 0 || (size_t)length >= sizeof(held->uri)) return -1;
    const char *leaf = held->uri + sizeof("file:/") - 1;
    if (strlen(leaf) > NAME_MAX) return -1;
    strcpy(held->rejection_leaf, leaf);
    return 0;
}
static napi_value create_kernel_archive(napi_env env, napi_callback_info info) {
    size_t count = 6;
    napi_value arguments[6];
    bool tagged = false, buffer = false;
    migration_credential_gate *binding = NULL;
    void *control = NULL;
    size_t control_size;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || (count != 4 && count != 5) ||
        napi_check_object_type_tag(env, arguments[0], &migration_credential_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&binding) != napi_ok || migration_credential_check(binding, env) != 0 ||
        binding->borrowers == UINT_MAX || kernel_archive_generation == UINT64_MAX ||
        napi_is_buffer(env, arguments[3], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, arguments[3], &control, &control_size) != napi_ok ||
        !control_size || control_size > KERNEL_ARCHIVE_CONTROL_BYTES)
        return ka_error(env, NULL, "archive requires original root-bound EX and complete closed rollback control");
    kernel_archive *held = calloc(1, sizeof(*held));
    if (!held) return ka_error(env, NULL, "archive allocation failed");
    held->binding = binding;
    atomic_init(&held->cancelled, 0);
    atomic_init(&held->uncertain, 0);
    atomic_init(&held->opens_closed, 0);
    held->env = env;
    held->pid = getpid(); held->uid = geteuid(); held->gid = getegid(); held->main_thread = pthread_self();
    held->generation = ++kernel_archive_generation;
    held->root_fd = binding->owner->root_fd; held->root = binding->owner->root;
    held->runtime_fd = binding->owner->runtime_fd; held->runtime = binding->owner->runtime;
    held->gate_fd = binding->gate->gate_fd; held->gate = binding->gate->file;
    held->owner_lock_fd = binding->owner->lock_fd; held->owner_lock = binding->owner->lock;
    held->migration_fd = held->collection_fd = held->directory_fd = held->control_fd = -1;
    held->rejection_parent_fd = held->rejection_fd = held->read_rejection_fd = held->image_fd = held->journal_fd = -1;
    if (!read_component(env, arguments[1], held->migration_id, sizeof(held->migration_id), 43) ||
        !read_component(env, arguments[2], held->archive_id, sizeof(held->archive_id), 43)) goto failed;
    struct stat cwd;
    if (stat(".", &cwd) != 0 || !same_inode(&cwd, &held->root) ||
        !ka_named_directory(held, held->root_fd, "runtime", held->runtime_fd, &held->runtime)) goto failed;
    napi_valuetype model_type = napi_null;
    if (count == 5 && napi_typeof(env, arguments[4], &model_type) != napi_ok) goto failed;
    if (model_type != napi_null) {
        int loan = ci_take_original_archive_loan(env, arguments[4], binding, &held->rollback_source, &held->rollback_reference);
        if (loan < 0) goto failed;
        if (loan == 0) {
            current_migration_inspection *source = held->rollback_source->inspection;
            if (strcmp(held->migration_id, held->rollback_source->migration_id) || strcmp(held->archive_id, source->archive_id)) goto failed;
            if (source->model_source && kam_attach(held, NULL, source->model_source) != 0) goto failed;
            if (source->runtime_witnesses && (rw_open_source(env, binding, &held->runtime_witnesses) != 0 ||
                !source_metadata_same(&source->runtime_witnesses->source, &held->runtime_witnesses->source))) goto failed;
        } else if (kam_attach(held, arguments[4], NULL) != 0) goto failed;
    }
    if ((!held->models && !ka_local_model_store_absent(held)) ||
        (!held->runtime_witnesses && !ka_local_inference_runtime_absent(held))) goto failed;
    if (napi_create_reference(env, arguments[0], 1, &held->binding_ref) != napi_ok) {
        ka_main_poison(held);
        return ka_error(env, held, "archive parent reference was not retained");
    }
    binding->borrowers++;
    held->borrowed = 1;
    /* Open, fully compare and EOF-check the current fixed control before any
     * new archive/rejection resource birth. No past creator is adopted here. */
    held->migration_fd = openat(held->root_fd, "migration", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (held->migration_fd < 0 || fstat(held->migration_fd, &held->migration) != 0 || !ka_directory(held, &held->migration)) goto failed;
    held->control_fd = openat(held->migration_fd, "control-v1.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (held->control_fd < 0 || fstat(held->control_fd, &held->control) != 0 ||
        !ka_regular(held, &held->control, 0600) || (uint64_t)held->control.st_size != control_size ||
        !ka_named_file(held, held->migration_fd, "control-v1.json", held->control_fd, &held->control, 0600, 1)) goto failed;
    held->control_size = control_size;
    struct sha256_context hash;
    sha256_init(&hash); sha256_update(&hash, control, control_size); publication_hash_hex(&hash, held->control_content_digest);
    if (ka_control_bytes(held, control) != 0 || ka_make_nonce(held) != 0 ||
        ka_hold_directory(held, held->root_fd, "file:", &held->rejection_parent_fd, &held->rejection_parent, 0) != 0 ||
        ka_hold_directory(held, held->rejection_parent_fd, held->rejection_leaf, &held->rejection_fd, &held->rejection, 1) != 0 ||
        ka_hold_directory(held, held->migration_fd, "kernel-archives", &held->collection_fd, &held->collection, 0) != 0 ||
        ka_hold_directory(held, held->collection_fd, held->archive_id, &held->directory_fd, &held->directory, 1) != 0 ||
        (held->runtime_witnesses && rw_bind_archive(held->runtime_witnesses, held->directory_fd, &held->directory) != 0)) goto failed;
    held->image_fd = openat(held->directory_fd, "kernel.sqlite3", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (held->image_fd < 0 || fstat(held->image_fd, &held->birth) != 0 || !ka_regular(held, &held->birth, 0600) ||
        held->birth.st_size != 0 || held->birth.st_dev != held->root.st_dev) goto failed;
    held->image_mode = held->birth.st_mode & 07777;
    /* This guard covers ordinary SQLite's pending/reserved/shared byte range.
     * Internal pager locks use the sole leased file, not another opened FD. */
    struct flock guard = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0x40000000, .l_len = 512};
    int locked;
    do { locked = fcntl(held->image_fd, F_SETLK, &guard); } while (locked < 0 && errno == EINTR);
    if (locked != 0 || fsync(held->image_fd) != 0 || fsync(held->directory_fd) != 0 || ka_main_check(held, env) != 0) goto failed;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, ka_assert, NULL, NULL, NULL, napi_default, NULL},
        {"describeBirth", NULL, ka_birth, NULL, NULL, NULL, napi_default, NULL},
        {"beginBackup", NULL, ka_begin_backup, NULL, NULL, NULL, napi_default, NULL},
        {"requestCancel", NULL, ka_cancel, NULL, NULL, NULL, napi_default, NULL},
        {"joinBackup", NULL, ka_join, NULL, NULL, NULL, napi_default, NULL},
        {"sealNext", NULL, ka_seal_next, NULL, NULL, NULL, napi_default, NULL},
        {"identity", NULL, ka_identity, NULL, NULL, NULL, napi_default, NULL},
        {"beginRead", NULL, ka_begin_read, NULL, NULL, NULL, napi_default, NULL},
        {"endRead", NULL, ka_end_read, NULL, NULL, NULL, napi_default, NULL},
        {"beginModelCapture", NULL, kam_begin, NULL, NULL, NULL, napi_default, NULL},
        {"captureModelNext", NULL, kam_next, NULL, NULL, NULL, napi_default, NULL},
        {"modelCaptureIdentity", NULL, kam_identity, NULL, NULL, NULL, napi_default, NULL},
        {"beginModelVerification", NULL, kam_begin_verify, NULL, NULL, NULL, napi_default, NULL},
        {"verifyModelNext", NULL, kam_verify_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginRuntimeWitnessCapture", NULL, karw_begin, NULL, NULL, NULL, napi_default, NULL},
        {"beginRetiredRuntimeWitnessObservation", NULL, karw_begin_observe, NULL, NULL, NULL, napi_default, NULL},
        {"observeRetiredRuntimeWitnessNext", NULL, karw_observe_next, NULL, NULL, NULL, napi_default, NULL},
        {"retiredRuntimeWitnessObservation", NULL, karw_observation, NULL, NULL, NULL, napi_default, NULL},
        {"beginRuntimeWitnessEntry", NULL, karw_begin_entry, NULL, NULL, NULL, napi_default, NULL},
        {"captureRuntimeWitnessEntryNext", NULL, karw_copy_next, NULL, NULL, NULL, napi_default, NULL},
        {"beginRuntimeWitnessSeal", NULL, karw_seal, NULL, NULL, NULL, napi_default, NULL},
        {"verifyRuntimeWitnessPackNext", NULL, karw_verify_next, NULL, NULL, NULL, napi_default, NULL},
        {"runtimeWitnessCaptureIdentity", NULL, karw_identity, NULL, NULL, NULL, napi_default, NULL},
        {"beginRuntimeWitnessRecheck", NULL, karw_recheck, NULL, NULL, NULL, napi_default, NULL},
        {"beginCasCapture", NULL, kam_begin_cas, NULL, NULL, NULL, napi_default, NULL},
        {"captureCasNext", NULL, kam_cas_next, NULL, NULL, NULL, napi_default, NULL},
        {"casCaptureIdentity", NULL, kans_identity, NULL, NULL, NULL, napi_default, NULL},
        {"readCasCaptureEntries", NULL, kans_entries, NULL, NULL, NULL, napi_default, NULL},
        {"beginManifest", NULL, kam_begin_manifest, NULL, NULL, NULL, napi_default, NULL},
        {"sealManifestNext", NULL, kans_manifest_next, NULL, NULL, NULL, napi_default, NULL},
        {"manifestIdentity", NULL, kans_manifest_identity, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, ka_close, NULL, NULL, NULL, napi_default, NULL}
    };
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &kernel_archive_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_wrap(env, result, held, ka_finalize, NULL, NULL) != napi_ok) goto failed;
    held->wrapped = 1;
    if (napi_create_reference(env, result, 1, &held->self_ref) != napi_ok) {
        ka_main_poison(held);
        return ka_error(env, held, "archive self reference was not retained");
    }
    return result;
failed:
    held->failed = 1;
    if (ka_retire(held) != 0) {
        ka_main_poison(held);
        return ka_error(env, held, "archive creation failed with original custody unresolved");
    }
    if (!held->wrapped) free(held);
    return ka_error(env, NULL, "archive creation refused; existing attempt is not a new birth");
}

/* All callbacks below may execute on real libuv workers or the main source
 * connection's thread. Only the actual file lease is shared; no NAPI or
 * main-thread-only authority assertion appears in the SQLite callbacks. */
static int ka_file_ready(kernel_archive_file *file) {
    kernel_archive *held = file->held;
    return file->alive && held && file->generation == held->generation && kernel_archive_active == held &&
        (held->phase == KA_BACKUP || held->phase == KA_READING) && ka_custody(held) == 0 &&
        (file->role == KA_MAIN ? held->main_live && held->main_file == file : held->journal_live);
}
static int ka_io_close(sqlite3_file *base) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    kernel_archive *held = file->held;
    int valid = file->alive && held && ka_process(held) && file->generation == held->generation;
    int custody = valid && ka_custody(held) == 0;
    if (valid) {
        if (file->role == KA_MAIN) {
            if (held->phase == KA_READING) held->read_closes++; else held->main_closes++;
            held->main_live = 0; held->main_file = NULL;
        } else { held->journal_closes++; held->journal_live = 0; }
        /* Logical SQLite xClose really ends this lease. The original OS FD
         * remains held until journal retirement or full readonly sealing. */
        file->alive = 0; file->held = NULL; base->pMethods = NULL;
        if (!custody) ka_uncertain(held);
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid && custody ? SQLITE_OK : SQLITE_IOERR_CLOSE;
}
static int ka_io_read(sqlite3_file *base, void *output, int amount, sqlite3_int64 offset) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int result = SQLITE_IOERR_READ;
    if (ka_file_ready(file) && amount >= 0 && offset >= 0 && offset <= INT64_MAX - amount &&
        (sqlite3_int64)(off_t)(offset + amount) == offset + amount) {
        int fd = file->role == KA_MAIN ? file->held->image_fd : file->held->journal_fd;
        int consumed = 0;
        result = SQLITE_OK;
        while (consumed < amount) {
            ssize_t count = pread(fd, (char *)output + consumed, (size_t)(amount - consumed), (off_t)(offset + consumed));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) { result = SQLITE_IOERR_READ; break; }
            if (!count) { memset((char *)output + consumed, 0, (size_t)(amount - consumed)); result = SQLITE_IOERR_SHORT_READ; break; }
            consumed += (int)count;
        }
        if (ka_custody(file->held) != 0) { ka_uncertain(file->held); result = SQLITE_IOERR_READ; }
        if (result != SQLITE_OK && result != SQLITE_IOERR_SHORT_READ) file->held->failed = 1;
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result;
}
static int ka_io_write(sqlite3_file *base, const void *bytes, int amount, sqlite3_int64 offset) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int result = SQLITE_IOERR_WRITE;
    if (ka_file_ready(file) && file->held->phase == KA_BACKUP && !file->held->readonly &&
        !atomic_load(&file->held->cancelled) && !file->held->failed && amount >= 0 && offset >= 0 &&
        (uint64_t)offset <= KERNEL_ARCHIVE_MAX_BYTES && (uint64_t)amount <= KERNEL_ARCHIVE_MAX_BYTES - (uint64_t)offset &&
        (sqlite3_int64)(off_t)(offset + amount) == offset + amount) {
        int fd = file->role == KA_MAIN ? file->held->image_fd : file->held->journal_fd;
        int consumed = 0;
        while (consumed < amount) {
            ssize_t count = pwrite(fd, (const char *)bytes + consumed, (size_t)(amount - consumed), (off_t)(offset + consumed));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            consumed += (int)count;
        }
        if (consumed == amount && ka_custody(file->held) == 0) result = SQLITE_OK;
        else if (ka_custody(file->held) != 0) ka_uncertain(file->held);
    }
    if (result != SQLITE_OK && file->held) file->held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result;
}
static int ka_io_truncate(sqlite3_file *base, sqlite3_int64 amount) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int result = SQLITE_IOERR_TRUNCATE;
    if (ka_file_ready(file) && file->held->phase == KA_BACKUP && !file->held->readonly &&
        !atomic_load(&file->held->cancelled) && !file->held->failed && amount >= 0 &&
        (uint64_t)amount <= KERNEL_ARCHIVE_MAX_BYTES && (sqlite3_int64)(off_t)amount == amount) {
        int fd = file->role == KA_MAIN ? file->held->image_fd : file->held->journal_fd;
        if (ftruncate(fd, (off_t)amount) == 0 && ka_custody(file->held) == 0) result = SQLITE_OK;
    }
    if (result != SQLITE_OK && file->held) file->held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result;
}
static int ka_io_sync(sqlite3_file *base, int flags) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int result = SQLITE_IOERR_FSYNC;
    if (ka_file_ready(file) && file->held->phase == KA_BACKUP && !atomic_load(&file->held->cancelled) &&
        !file->held->failed && (flags & ~(SQLITE_SYNC_FULL | SQLITE_SYNC_NORMAL | SQLITE_SYNC_DATAONLY)) == 0) {
        int fd = file->role == KA_MAIN ? file->held->image_fd : file->held->journal_fd;
        if (fsync(fd) == 0 && ka_custody(file->held) == 0) result = SQLITE_OK;
    }
    if (result != SQLITE_OK && file->held) file->held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result;
}
static int ka_io_size(sqlite3_file *base, sqlite3_int64 *size) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    struct stat observed;
    int valid = ka_file_ready(file);
    int fd = valid ? (file->role == KA_MAIN ? file->held->image_fd : file->held->journal_fd) : -1;
    valid = valid && fstat(fd, &observed) == 0 && observed.st_size >= 0;
    if (valid) *size = (sqlite3_int64)observed.st_size;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_IOERR_FSTAT;
}
static int ka_io_lock(sqlite3_file *base, int level) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int valid = ka_file_ready(file) && level >= SQLITE_LOCK_NONE && level <= SQLITE_LOCK_EXCLUSIVE &&
        (file->held->phase != KA_READING || level <= SQLITE_LOCK_SHARED);
    if (valid) file->lock = level;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_IOERR_LOCK;
}
static int ka_io_unlock(sqlite3_file *base, int level) { return ka_io_lock(base, level); }
static int ka_io_reserved(sqlite3_file *base, int *result) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int valid = ka_file_ready(file);
    if (valid) *result = file->lock >= SQLITE_LOCK_RESERVED;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_IOERR_CHECKRESERVEDLOCK;
}
static int ka_io_control(sqlite3_file *base, int operation, void *argument) {
    kernel_archive_file *file = (kernel_archive_file *)base;
    pthread_mutex_lock(&kernel_archive_mutex);
    int result = SQLITE_NOTFOUND;
    if (!ka_file_ready(file)) result = SQLITE_IOERR;
    else if (operation == SQLITE_FCNTL_LOCKSTATE) { *(int *)argument = file->lock; result = SQLITE_OK; }
    else if (operation == SQLITE_FCNTL_MMAP_SIZE) { *(sqlite3_int64 *)argument = 0; result = SQLITE_OK; }
    else if (operation == SQLITE_FCNTL_SIZE_HINT) result = SQLITE_OK; /* no speculative allocation */
    else if (operation == SQLITE_FCNTL_COMMIT_PHASETWO) {
        if (file->role == KA_MAIN && file->held->phase == KA_BACKUP && file->lock == SQLITE_LOCK_EXCLUSIVE &&
            !file->held->failed && !atomic_load(&file->held->cancelled) && !file->held->journal_present) {
            file->held->commit_phase_two_observed = 1;
            result = SQLITE_OK;
        } else result = SQLITE_IOERR;
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result;
}
static int ka_io_sector(sqlite3_file *base) { (void)base; return 4096; }
static int ka_io_characteristics(sqlite3_file *base) { (void)base; return 0; }
static const sqlite3_io_methods ka_io_methods = {
    .iVersion = 1, .xClose = ka_io_close, .xRead = ka_io_read, .xWrite = ka_io_write,
    .xTruncate = ka_io_truncate, .xSync = ka_io_sync, .xFileSize = ka_io_size,
    .xLock = ka_io_lock, .xUnlock = ka_io_unlock, .xCheckReservedLock = ka_io_reserved,
    .xFileControl = ka_io_control, .xSectorSize = ka_io_sector, .xDeviceCharacteristics = ka_io_characteristics
};
static int ka_filename(const char *name) {
    if (!name) return -1;
    if (!strcmp(name, kernel_archive_name)) return KA_MAIN;
    if (!strcmp(name, kernel_archive_journal_name)) return KA_JOURNAL;
    return -1;
}
static int ka_vfs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *base, int flags, int *out_flags) {
    (void)vfs;
    base->pMethods = NULL;
    int role = ka_filename(name);
    if (role < 0) return SQLITE_CANTOPEN;
    pthread_mutex_lock(&kernel_archive_mutex);
    kernel_archive *held = kernel_archive_active;
    int valid = held && !atomic_load(&held->opens_closed) && !atomic_load(&held->cancelled) && ka_custody(held) == 0 &&
        (flags & (SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_MEMORY | SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL |
        SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL | SQLITE_OPEN_WAL)) == 0;
    if (valid && role == KA_MAIN) {
        const char *nonce = sqlite3_uri_parameter(name, "cliq_archive_lease");
        valid = nonce && !strcmp(nonce, held->nonce) && !held->main_live && !held->main_file &&
            (flags & SQLITE_OPEN_MAIN_DB) && !(flags & SQLITE_OPEN_MAIN_JOURNAL) &&
            (held->phase == KA_BACKUP ? !held->failed && !atomic_load(&held->cancelled) && !held->main_opens &&
                (flags & SQLITE_OPEN_READWRITE) && !(flags & SQLITE_OPEN_READONLY) :
                held->phase == KA_READING && held->readonly && held->read_opens == held->read_open_cut &&
                (flags & SQLITE_OPEN_READONLY) && !(flags & (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)));
    } else if (valid && role == KA_JOURNAL) {
        /* SQLite itself supplies the journal-to-main association. Never call
         * database_file_object on an arbitrary/non-journal filename. */
        valid = held->phase == KA_BACKUP && !held->failed && !atomic_load(&held->cancelled) &&
            held->main_live && held->main_file && !held->journal_live && !held->journal_present &&
            (flags & SQLITE_OPEN_MAIN_JOURNAL) && !(flags & SQLITE_OPEN_MAIN_DB) &&
            (flags & SQLITE_OPEN_READWRITE) && (flags & SQLITE_OPEN_CREATE) && !(flags & SQLITE_OPEN_READONLY) &&
            sqlite3_database_file_object(name) == &held->main_file->base;
        if (valid) {
            held->journal_fd = openat(held->directory_fd, "kernel.sqlite3-journal",
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            valid = held->journal_fd >= 0 && fstat(held->journal_fd, &held->journal) == 0 &&
                ka_regular(held, &held->journal, 0600) && held->journal.st_size == 0;
            if (held->journal_fd >= 0) {
                held->journal_present = 1;
                held->journal_births++;
            }
            valid = valid && fsync(held->journal_fd) == 0 && fsync(held->directory_fd) == 0 && ka_custody(held) == 0;
            if (!valid) held->failed = 1;
        }
    }
    if (valid) {
        kernel_archive_file *file = (kernel_archive_file *)base;
        file->held = held; file->generation = held->generation; file->role = role; file->alive = 1; file->lock = SQLITE_LOCK_NONE;
        if (role == KA_MAIN) {
            held->main_live = 1; held->main_file = file;
            if (held->phase == KA_READING) held->read_opens++; else held->main_opens++;
        } else { held->journal_live = 1; held->journal_opens++; }
        base->pMethods = &ka_io_methods;
        if (out_flags) *out_flags = flags;
    }
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_CANTOPEN;
}
static int ka_vfs_delete(sqlite3_vfs *vfs, const char *name, int sync) {
    (void)vfs;
    (void)sync;
    if (ka_filename(name) != KA_JOURNAL) return SQLITE_IOERR_DELETE;
    pthread_mutex_lock(&kernel_archive_mutex);
    kernel_archive *held = kernel_archive_active;
    int valid = held && held->phase == KA_BACKUP && ka_custody(held) == 0 &&
        held->journal_present && !held->journal_live && ka_retire_journal(held) == 0;
    if (held && !valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_IOERR_DELETE;
}
static int ka_vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
    (void)vfs;
    *result = 0;
    int role = ka_filename(name);
    int absent_sidecar = name && (!strcmp(name, "/cliq-owned-archive-wal") || !strcmp(name, "/cliq-owned-archive-shm"));
    if ((role < 0 && !absent_sidecar) ||
        (flags != SQLITE_ACCESS_EXISTS && flags != SQLITE_ACCESS_READ && flags != SQLITE_ACCESS_READWRITE)) return SQLITE_IOERR_ACCESS;
    pthread_mutex_lock(&kernel_archive_mutex);
    kernel_archive *held = kernel_archive_active;
    int valid = held && ka_custody(held) == 0;
    if (valid) *result = !absent_sidecar && (role == KA_MAIN || held->journal_present) &&
        (flags != SQLITE_ACCESS_READWRITE || held->phase == KA_BACKUP);
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? SQLITE_OK : SQLITE_IOERR_ACCESS;
}
static int ka_vfs_path(sqlite3_vfs *vfs, const char *name, int length, char *output) {
    (void)vfs;
    if (!name || strcmp(name, kernel_archive_name) || length < (int)sizeof(kernel_archive_name)) return SQLITE_CANTOPEN;
    memcpy(output, kernel_archive_name, sizeof(kernel_archive_name));
    return SQLITE_OK;
}
static void *ka_vfs_dl_open(sqlite3_vfs *vfs, const char *name) { (void)vfs; (void)name; return NULL; }
static void ka_vfs_dl_error(sqlite3_vfs *vfs, int size, char *output) {
    (void)vfs;
    if (size > 0) snprintf(output, (size_t)size, "%s", "archive VFS cannot load extensions");
}
static void (*ka_vfs_dl_sym(sqlite3_vfs *vfs, void *image, const char *name))(void) { (void)vfs; (void)image; (void)name; return NULL; }
static void ka_vfs_dl_close(sqlite3_vfs *vfs, void *image) { (void)vfs; (void)image; }
static int ka_vfs_random(sqlite3_vfs *vfs, int count, char *output) {
    (void)vfs;
    return kernel_archive_process.base->xRandomness(kernel_archive_process.base, count, output);
}
static int ka_vfs_sleep(sqlite3_vfs *vfs, int micros) {
    (void)vfs;
    return kernel_archive_process.base->xSleep(kernel_archive_process.base, micros);
}
static int ka_vfs_time(sqlite3_vfs *vfs, double *time) {
    (void)vfs;
    return kernel_archive_process.base->xCurrentTime(kernel_archive_process.base, time);
}
static int ka_vfs_time64(sqlite3_vfs *vfs, sqlite3_int64 *time) {
    (void)vfs;
    sqlite3_vfs *base = kernel_archive_process.base;
    if (base->iVersion >= 2 && base->xCurrentTimeInt64) return base->xCurrentTimeInt64(base, time);
    double original;
    int result = base->xCurrentTime(base, &original);
    if (result == SQLITE_OK) *time = (sqlite3_int64)(original * 86400000.0);
    return result;
}
__attribute__((visibility("default"))) int sqlite3_cliqownedarchive_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
    (void)database;
    (void)error;
    if (!kernel_global_main_thread() || !api || !api->sourceid || !api->vfs_find || !api->vfs_register ||
        !api->uri_parameter || !api->database_file_object || (sqlite3_api && sqlite3_api != api)) return SQLITE_ERROR;
    if (pthread_mutex_trylock(&kernel_archive_mutex) != 0) return SQLITE_BUSY;
    kernel_archive *held = kernel_archive_active;
    int valid = held && held->phase == KA_BACKUP && ka_main_check(held, held->env) == 0;
    if (!valid) { pthread_mutex_unlock(&kernel_archive_mutex); return SQLITE_ERROR; }
    SQLITE_EXTENSION_INIT2(api);
    if (kernel_archive_process.registered) {
        int result = sqlite3_vfs_find(kernel_archive_vfs_name) == &kernel_archive_process.vfs ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
        pthread_mutex_unlock(&kernel_archive_mutex);
        return result;
    }
    sqlite3_vfs *base = sqlite3_vfs_find(NULL);
    if (!base || !base->xRandomness || !base->xSleep || !base->xCurrentTime || sqlite3_vfs_find(kernel_archive_vfs_name)) {
        pthread_mutex_unlock(&kernel_archive_mutex);
        return SQLITE_ERROR;
    }
    kernel_archive_process.base = base;
    kernel_archive_process.vfs = (sqlite3_vfs) {
        .iVersion = 2, .szOsFile = sizeof(kernel_archive_file), .mxPathname = 256,
        .zName = kernel_archive_vfs_name, .xOpen = ka_vfs_open, .xDelete = ka_vfs_delete,
        .xAccess = ka_vfs_access, .xFullPathname = ka_vfs_path, .xDlOpen = ka_vfs_dl_open,
        .xDlError = ka_vfs_dl_error, .xDlSym = ka_vfs_dl_sym, .xDlClose = ka_vfs_dl_close,
        .xRandomness = ka_vfs_random, .xSleep = ka_vfs_sleep, .xCurrentTime = ka_vfs_time, .xCurrentTimeInt64 = ka_vfs_time64
    };
    int result = sqlite3_vfs_register(&kernel_archive_process.vfs, 0);
    if (result == SQLITE_OK) kernel_archive_process.registered = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result == SQLITE_OK ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
}
