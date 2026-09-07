#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
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

static napi_value process_start_token(napi_env env, napi_callback_info info) {
    (void)info;
    char token[128];
#ifdef __APPLE__
    struct proc_bsdinfo process;
    memset(&process, 0, sizeof(process));
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &process, sizeof(process)) != sizeof(process) ||
        process.pbi_pid != (uint32_t)getpid() || process.pbi_start_tvusec >= 1000000) {
        return native_error(env, "cannot observe the current macOS process start time");
    }
    snprintf(token, sizeof(token), "darwin-proc-start-time:%llu:%06llu",
             (unsigned long long)process.pbi_start_tvsec, (unsigned long long)process.pbi_start_tvusec);
#elif defined(__linux__)
    char stat[4096];
    FILE *file = fopen("/proc/self/stat", "re");
    if (file == NULL) return native_error(env, "cannot open the current Linux process identity");
    size_t size = fread(stat, 1, sizeof(stat) - 1, file);
    int failed = ferror(file);
    fclose(file);
    if (failed || size == 0 || size == sizeof(stat) - 1) return native_error(env, "invalid Linux process identity");
    stat[size] = '\0';
    char *field = strrchr(stat, ')');
    if (field == NULL || field[1] != ' ') return native_error(env, "invalid Linux process identity");
    field += 2;
    for (int index = 3; index < 22; index++) {
        field = strchr(field, ' ');
        if (field == NULL) return native_error(env, "Linux process identity has no start token");
        field++;
    }
    if (*field < '0' || *field > '9') return native_error(env, "invalid Linux process start token");
    char *end;
    errno = 0;
    unsigned long long ticks = strtoull(field, &end, 10);
    if (errno != 0 || *end != ' ') return native_error(env, "invalid Linux process start token");
    snprintf(token, sizeof(token), "linux-proc-start-ticks:%llu", ticks);
#else
#error StateOwner supports only macOS and Linux
#endif
    napi_value result;
    if (napi_create_string_utf8(env, token, NAPI_AUTO_LENGTH, &result) != napi_ok) return NULL;
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
