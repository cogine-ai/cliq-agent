#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#elif defined(__linux__)
#include <linux/magic.h>
#include <sys/vfs.h>
#endif

static napi_value native_error(napi_env env, const char *message) {
    napi_throw_error(env, "ERR_CLIQ_STATE_OWNER_NATIVE", message);
    return NULL;
}

typedef struct {
    int root_fd, runtime_fd, lock_fd;
    struct stat root, runtime, lock;
    char *path;
} state_lock;

static const napi_type_tag lock_tag = {0x3d641bc705864cfbULL, 0xab53499f3ee988c4ULL};

static napi_value assert_prior_process_dead(napi_env env, napi_callback_info info);
static napi_value move_generation(napi_env env, napi_callback_info info);

/* Reopening a path is only a locator check. Authority stays on these held
 * descriptors, and flock is released solely by closing the lock descriptor. */
static void close_lock(state_lock *lock) {
    if (lock->lock_fd >= 0) close(lock->lock_fd);
    if (lock->runtime_fd >= 0) close(lock->runtime_fd);
    if (lock->root_fd >= 0) close(lock->root_fd);
    lock->root_fd = lock->runtime_fd = lock->lock_fd = -1;
}

static void finalize_lock(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    state_lock *lock = data;
    close_lock(lock);
    free(lock->path);
    free(lock);
}

static int same_inode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int private_directory(const struct stat *info) {
    return S_ISDIR(info->st_mode) && info->st_uid == geteuid() && (info->st_mode & 07777) == 0700;
}

static int private_lock_file(const struct stat *info) {
    return S_ISREG(info->st_mode) && info->st_uid == geteuid() &&
           (info->st_mode & 07777) == 0600 && info->st_nlink == 1;
}

/* No pathname component may be a symlink, including ancestors of StateRoot. */
static int open_root(const char *path) {
    if (path[0] != '/' || path[1] == '\0') { errno = EINVAL; return -1; }
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (size == 0 || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, size); name[size] = '\0';
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int failure = errno;
        close(current);
        if (next < 0) { errno = failure; return -1; }
        current = next;
        if (!end) break;
        part = end + 1;
        if (*part == '\0') { close(current); errno = EINVAL; return -1; }
    }
    return current;
}

static int lock_is_held(state_lock *lock) {
    if (lock->lock_fd < 0) return 0;
    struct stat root, runtime, file, named;
    int reopened = open_root(lock->path);
    if (reopened < 0) return 0;
    int valid = fstat(reopened, &named) == 0 && same_inode(&named, &lock->root);
    close(reopened);
    return valid && fstat(lock->root_fd, &root) == 0 && private_directory(&root) && same_inode(&root, &lock->root) &&
        fstat(lock->runtime_fd, &runtime) == 0 && private_directory(&runtime) && same_inode(&runtime, &lock->runtime) &&
        fstatat(lock->root_fd, "runtime", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &runtime) &&
        fstat(lock->lock_fd, &file) == 0 && private_lock_file(&file) && same_inode(&file, &lock->lock) &&
        fstatat(lock->runtime_fd, "state-owner.lock", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &file);
}

static state_lock *unwrap_lock(napi_env env, napi_callback_info info) {
    napi_value self;
    bool matches = false;
    state_lock *lock = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &lock_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&lock) != napi_ok || !lock) {
        native_error(env, "invalid StateOwner lock handle");
        return NULL;
    }
    return lock;
}

static napi_value assert_held(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static napi_value release_lock(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    close_lock(lock);
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static int decimal_member(napi_env env, napi_value object, const char *key, unsigned long long number) {
    char text[32];
    snprintf(text, sizeof(text), "%llu", number);
    napi_value value;
    return napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &value) == napi_ok &&
           napi_set_named_property(env, object, key, value) == napi_ok;
}

static int identity_member(napi_env env, napi_value object, const char *key, const struct stat *info) {
    napi_value value, uid;
#ifdef __APPLE__
    unsigned long long device = (uint32_t)info->st_dev;
#else
    unsigned long long device = info->st_dev;
#endif
    return napi_create_object(env, &value) == napi_ok &&
        decimal_member(env, value, "deviceId", device) && decimal_member(env, value, "fileId", info->st_ino) &&
        napi_create_uint32(env, info->st_uid, &uid) == napi_ok && napi_set_named_property(env, value, "ownerUid", uid) == napi_ok &&
        napi_object_freeze(env, value) == napi_ok && napi_set_named_property(env, object, key, value) == napi_ok;
}

static napi_value acquire_lock(napi_env env, napi_callback_info info) {
    size_t argc = 2, length;
    napi_value argv[2];
    bool create;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok || length == 0 || length >= PATH_MAX ||
        napi_get_value_bool(env, argv[1], &create) != napi_ok) return native_error(env, "invalid StateOwner lock input");
    state_lock *lock = calloc(1, sizeof(*lock));
    if (!lock) return native_error(env, "StateOwner lock allocation failed");
    lock->root_fd = lock->runtime_fd = lock->lock_fd = -1;
    lock->path = malloc(length + 1);
    const char *error = "cannot open StateOwner root without following symlinks";
    if (!lock->path || napi_get_value_string_utf8(env, argv[0], lock->path, length + 1, &length) != napi_ok ||
        strlen(lock->path) != length) goto fail;
    lock->root_fd = open_root(lock->path);
    if (lock->root_fd < 0 || fstat(lock->root_fd, &lock->root) < 0 || !private_directory(&lock->root)) goto fail;
    error = "StateOwner runtime must be an existing private 0700 directory";
    if (create && mkdirat(lock->root_fd, "runtime", 0700) < 0 && errno != EEXIST) goto fail;
    lock->runtime_fd = openat(lock->root_fd, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lock->runtime_fd < 0 || fstat(lock->runtime_fd, &lock->runtime) < 0 || !private_directory(&lock->runtime)) goto fail;
    error = "StateOwner lock must be an existing private 0600 regular file with link count 1";
    int flags = O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
    /* Separate exclusive creation from opening the winning inode. Concurrent
     * plain O_CREAT opens can fail with ENOENT on macOS during initial creation. */
    lock->lock_fd = openat(lock->runtime_fd, "state-owner.lock", flags | (create ? O_CREAT | O_EXCL : 0), 0600);
    if (create && lock->lock_fd < 0 && errno == EEXIST) {
        lock->lock_fd = openat(lock->runtime_fd, "state-owner.lock", flags);
    }
    if (lock->lock_fd < 0 || fstat(lock->lock_fd, &lock->lock) < 0 || !private_lock_file(&lock->lock)) goto fail;
    int status;
    do { status = flock(lock->lock_fd, LOCK_EX | LOCK_NB); } while (status < 0 && errno == EINTR);
    if (status < 0) {
        error = (errno == EWOULDBLOCK || errno == EAGAIN) ? "StateOwner OS lock is already held" : "StateOwner OS lock acquisition failed";
        goto fail;
    }
    error = "StateOwner descriptor identity changed during acquisition";
    if (!lock_is_held(lock) || fsync(lock->lock_fd) < 0 || fsync(lock->runtime_fd) < 0 || fsync(lock->root_fd) < 0) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, assert_held, NULL, NULL, NULL, napi_default, NULL},
        {"assertPriorProcessDead", NULL, assert_prior_process_dead, NULL, NULL, NULL, napi_default, NULL},
        {"moveGeneration", NULL, move_generation, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, release_lock, NULL, NULL, NULL, napi_default, NULL}
    };
    error = "StateOwner lock handle creation failed";
    if (napi_create_object(env, &result) != napi_ok ||
        !identity_member(env, result, "root", &lock->root) || !identity_member(env, result, "runtime", &lock->runtime) ||
        !identity_member(env, result, "lock", &lock->lock) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &lock_tag) != napi_ok ||
        napi_wrap(env, result, lock, finalize_lock, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    finalize_lock(env, lock, NULL);
    return native_error(env, error);
}

static int read_component(napi_env env, napi_value value, char *text, size_t capacity, size_t exact_length) {
    size_t length;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length == 0 || length >= capacity ||
        (exact_length && length != exact_length) ||
        napi_get_value_string_utf8(env, value, text, capacity, &length) != napi_ok) return 0;
    for (size_t i = 0; i < length; i++) {
        char c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int read_unsigned_id(napi_env env, napi_value value, unsigned long long *number) {
    char text[21], canonical[21], *end;
    size_t length;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length == 0 || length >= sizeof(text) ||
        napi_get_value_string_utf8(env, value, text, sizeof(text), &length) != napi_ok || strlen(text) != length ||
        text[0] < '0' || text[0] > '9') return 0;
    errno = 0;
    *number = strtoull(text, &end, 10);
    if (errno || *end) return 0;
    snprintf(canonical, sizeof(canonical), "%llu", *number);
    return strcmp(text, canonical) == 0;
}

static int sync_directory(int fd) {
    int status;
    do { status = fsync(fd); } while (status < 0 && errno == EINTR);
    return status == 0;
}

static int open_private_child(int parent, const char *name, int create, struct stat *identity, dev_t device) {
    if (create && mkdirat(parent, name, 0700) < 0 && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, identity) < 0 || !private_directory(identity) || identity->st_dev != device) { close(fd); return -1; }
    return fd;
}

static int generation_identity(const struct stat *info, unsigned long long device, unsigned long long file) {
#ifdef __APPLE__
    int protected = private_lock_file(info); /* private, single-link 0600 backing image */
    unsigned long long observed_device = (uint32_t)info->st_dev;
#else
    /* Directory link counts include child '..' entries; they are not file
     * hardlink counts and are not immutable generation identity. */
    int protected = private_directory(info);
    unsigned long long observed_device = info->st_dev;
#endif
    return protected && observed_device == device && (unsigned long long)info->st_ino == file;
}

/* 0 is positive ENOENT only; wrong type/identity and other I/O errors fail. */
static int generation_at(int parent, const char *name, unsigned long long device, unsigned long long file, struct stat *identity) {
    if (fstatat(parent, name, identity, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT ? 0 : -1;
    return generation_identity(identity, device, file) ? 1 : -1;
}

static int quarantine_parents_valid(state_lock *lock, int parents[5], struct stat identities[5], const char *names[5]) {
    if (!lock_is_held(lock)) return 0;
    for (int i = 0; i < 5; i++) {
        struct stat held, named;
        int parent = (i == 0 || i == 3) ? lock->root_fd : parents[i - 1];
        if (fstat(parents[i], &held) < 0 || !private_directory(&held) || !same_inode(&held, &identities[i]) ||
            fstatat(parent, names[i], &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&named, &held)) return 0;
    }
    return 1;
}

/* A fixed descriptor-relative relocation, never execution/death authority.
 * No directory scan, overwrite, copy/unlink fallback, rollback or deletion. */
static napi_value move_generation(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    size_t argc = 6;
    napi_value argv[6];
    char run[129], generation[44], target[44], source[48];
    unsigned long long device, file;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 5 ||
        !read_component(env, argv[0], run, sizeof(run), 0) || !read_component(env, argv[1], generation, sizeof(generation), 43) ||
        !read_component(env, argv[2], target, sizeof(target), 43) ||
        !read_unsigned_id(env, argv[3], &device) || !read_unsigned_id(env, argv[4], &file)) {
        return native_error(env, "invalid generation quarantine identity");
    }
#ifdef __APPLE__
    snprintf(source, sizeof(source), "%s.img", generation);
#else
    snprintf(source, sizeof(source), "%s", generation);
#endif
    int parents[5] = {-1, -1, -1, -1, -1}, generation_fd = -1;
    struct stat identities[5], original, destination, opened;
    const char *names[5] = {"runs", run, "generations", "quarantine", "workspace-generations"};
    const char *error = "generation quarantine requires private same-device no-follow parent descriptors";
    for (int i = 0; i < 3; i++) {
        parents[i] = open_private_child(i == 0 ? lock->root_fd : parents[i - 1], names[i], 0, &identities[i], lock->root.st_dev);
        if (parents[i] < 0) goto done;
    }
    error = "generation quarantine source identity differs or is unreadable";
    int source_exists = generation_at(parents[2], source, device, file, &original);
    if (source_exists < 0) goto done;
    error = "generation quarantine target requires private same-device no-follow parent descriptors";
    for (int i = 3; i < 5; i++) {
        parents[i] = open_private_child(i == 3 ? lock->root_fd : parents[i - 1], names[i], source_exists, &identities[i], lock->root.st_dev);
        if (parents[i] < 0) goto done;
    }
    error = "generation quarantine requires exactly one original or exact target; refusing conflict or identity drift";
    int target_exists = generation_at(parents[4], target, device, file, &destination);
    if (target_exists < 0 || source_exists + target_exists != 1) goto done;
    int flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
#ifndef __APPLE__
    flags |= O_DIRECTORY;
#endif
    generation_fd = openat(source_exists ? parents[2] : parents[4], source_exists ? source : target, flags);
    if (generation_fd < 0 || fstat(generation_fd, &opened) < 0 || !generation_identity(&opened, device, file) ||
        opened.st_dev != lock->root.st_dev) goto done;
    error = "generation quarantine parent or source descriptor identity changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) ||
        generation_at(parents[2], source, device, file, &original) != source_exists ||
        generation_at(parents[4], target, device, file, &destination) != target_exists) goto done;
    /* Persist newly created quarantine ancestors before moving. Retry also
     * repeats these syncs: an earlier crash may have interrupted any one. */
    error = "generation quarantine parent fsync failed; retry the exact locator pair";
    if (!sync_directory(lock->root_fd)) goto done;
    for (int i = 0; i < 5; i++) if (!sync_directory(parents[i])) goto done;
    error = "generation quarantine parent or source descriptor identity changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) ||
        generation_at(parents[2], source, device, file, &original) != source_exists ||
        generation_at(parents[4], target, device, file, &destination) != target_exists) goto done;
    if (source_exists) {
        error = "generation quarantine no-replace rename failed; no overwrite or copy fallback is allowed";
#ifdef __APPLE__
        if (renameatx_np(parents[2], source, parents[4], target, RENAME_EXCL) < 0) goto done;
#else
        if (renameat2(parents[2], source, parents[4], target, RENAME_NOREPLACE) < 0) goto done;
#endif
    }
    error = "generation quarantine parent fsync failed; retry the exact locator pair";
    if (!sync_directory(parents[2]) || !sync_directory(parents[4])) goto done;
    error = "generation quarantine post-move descriptor identity or original absence changed";
    if (!quarantine_parents_valid(lock, parents, identities, names) || fstat(generation_fd, &opened) < 0 ||
        !generation_identity(&opened, device, file) ||
        generation_at(parents[2], source, device, file, &original) != 0 ||
        generation_at(parents[4], target, device, file, &destination) != 1) goto done;
    error = NULL;
done:
    if (generation_fd >= 0) close(generation_fd);
    for (int i = 4; i >= 0; i--) if (parents[i] >= 0) close(parents[i]);
    if (error) return native_error(env, error);
    napi_value result, identity;
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "identity", &destination) ||
        napi_get_named_property(env, result, "identity", &identity) != napi_ok) return NULL;
    return identity;
}

/* 1 = observed identity, 0 = positively absent, -1 = unavailable/invalid.
 * Permission failures and hidden procfs entries are never death evidence. */
static int observe_process(pid_t pid, char token[128]) {
#ifdef __APPLE__
    struct proc_bsdinfo process;
    memset(&process, 0, sizeof(process));
    errno = 0;
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &process, sizeof(process));
    if (size == 0 && errno == ESRCH) return 0;
    if (size != sizeof(process) || process.pbi_pid != (uint32_t)pid ||
        process.pbi_start_tvsec == 0 || process.pbi_start_tvusec >= 1000000) {
        return -1;
    }
    snprintf(token, 128, "darwin-proc-start-time:%llu:%06llu",
             (unsigned long long)process.pbi_start_tvsec, (unsigned long long)process.pbi_start_tvusec);
#elif defined(__linux__)
    char stat[4096], path[64];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* hidepid can also produce ENOENT. Require a separate kernel PID
         * absence observation; no signal is sent and EPERM is indeterminate. */
        return (errno == ENOENT || errno == ESRCH) && kill(pid, 0) < 0 && errno == ESRCH ? 0 : -1;
    }
    struct statfs filesystem;
    if (fstatfs(fd, &filesystem) < 0 || filesystem.f_type != PROC_SUPER_MAGIC) { close(fd); return -1; }
    FILE *file = fdopen(fd, "r");
    if (file == NULL) { close(fd); return -1; }
    size_t size = fread(stat, 1, sizeof(stat) - 1, file);
    int failed = ferror(file);
    fclose(file);
    if (failed || size == 0 || size == sizeof(stat) - 1) return -1;
    stat[size] = '\0';
    char *pid_end;
    errno = 0;
    long observed_pid = strtol(stat, &pid_end, 10);
    if (errno != 0 || observed_pid != pid || pid_end[0] != ' ' || pid_end[1] != '(') return -1;
    char *field = strrchr(stat, ')');
    if (field == NULL || field[1] != ' ') return -1;
    field += 2;
    for (int index = 3; index < 22; index++) {
        field = strchr(field, ' ');
        if (field == NULL) return -1;
        field++;
    }
    if (*field < '0' || *field > '9') return -1;
    char *end;
    errno = 0;
    unsigned long long ticks = strtoull(field, &end, 10);
    if (errno != 0 || *end != ' ' || ticks == 0) return -1;
    snprintf(token, 128, "linux-proc-start-ticks:%llu", ticks);
#else
#error StateOwner supports only macOS and Linux
#endif
    return 1;
}

static napi_value process_start_token(napi_env env, napi_callback_info info) {
    (void)info;
    char token[128];
    if (observe_process(getpid(), token) != 1) return native_error(env, "cannot observe the current process start token");
    napi_value result;
    if (napi_create_string_utf8(env, token, NAPI_AUTO_LENGTH, &result) != napi_ok) return NULL;
    return result;
}

static napi_value assert_prior_process_dead(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    size_t argc = 2, length;
    napi_value argv[2];
    double number;
    char prior[128], observed[128];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        napi_get_value_double(env, argv[0], &number) != napi_ok || !(number >= 1 && number <= INT_MAX) || number != (pid_t)number ||
        napi_get_value_string_utf8(env, argv[1], NULL, 0, &length) != napi_ok || length == 0 || length >= sizeof(prior) ||
        napi_get_value_string_utf8(env, argv[1], prior, sizeof(prior), &length) != napi_ok || strlen(prior) != length) {
        return native_error(env, "invalid prior StateOwner process identity");
    }
    /* Only the helper's exact canonical token syntax is comparable. Unknown
     * versions or arbitrary strings cannot be treated as a positive mismatch. */
    unsigned long long first, second;
    int end = 0;
#ifdef __APPLE__
    if (sscanf(prior, "darwin-proc-start-time:%llu:%llu%n", &first, &second, &end) != 2 ||
        first == 0 || second >= 1000000 || (size_t)end != length) return native_error(env, "invalid prior StateOwner process start token");
    snprintf(observed, sizeof(observed), "darwin-proc-start-time:%llu:%06llu", first, second);
#else
    (void)second;
    if (sscanf(prior, "linux-proc-start-ticks:%llu%n", &first, &end) != 1 ||
        first == 0 || (size_t)end != length) return native_error(env, "invalid prior StateOwner process start token");
    snprintf(observed, sizeof(observed), "linux-proc-start-ticks:%llu", first);
#endif
    if (strcmp(prior, observed) != 0) return native_error(env, "invalid prior StateOwner process start token");
    int status = observe_process((pid_t)number, observed);
    if (status < 0) return native_error(env, "prior StateOwner process observation is unavailable");
    if (status == 1 && strcmp(prior, observed) == 0) return native_error(env, "prior StateOwner process is still present");
    if (!lock_is_held(lock)) return native_error(env, "StateOwner root/runtime/lock descriptor identity changed or closed");
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return NULL;
    return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
    const napi_property_descriptor methods[] = {
        {"acquireLock", NULL, acquire_lock, NULL, NULL, NULL, napi_default, NULL},
        {"processStartToken", NULL, process_start_token, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return NULL;
    return exports;
}

NAPI_MODULE(cliq_state_owner, initialize)
