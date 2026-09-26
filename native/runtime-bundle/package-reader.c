#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_RELATIVE_PATH 4096
#define MAX_CHUNK (1024 * 1024)
#define MAX_MANIFEST_BYTES (1024 * 1024)
#define MANIFEST_NAME "runtime-bundle.json"

#ifdef __APPLE__
#define FILE_MTIME(info) ((info).st_mtimespec)
#define FILE_CTIME(info) ((info).st_ctimespec)
#else
#define FILE_MTIME(info) ((info).st_mtim)
#define FILE_CTIME(info) ((info).st_ctim)
#endif

typedef struct {
    int fd;
    char *path;
    struct stat identity;
} package_root;

typedef struct {
    int fd, root_fd;
    char *root_path, *relative_path;
    struct stat root_identity, before;
    off_t consumed;
    int executable;
} package_entry;

typedef struct {
    int fd;
    char *path;
    struct stat identity;
} cas_root;

typedef struct {
    int fd, root_fd;
    char *root_path, *name, *ref;
    struct stat root_identity, sealed;
    off_t expected, written, read_offset;
    int state;
} cas_stage;

typedef struct {
    int fd, root_fd;
    char *root_path, *ref;
    struct stat root_identity, before;
    off_t read_offset;
} cas_artifact;

static const napi_type_tag root_tag = {0x12a0e10b838f440dULL, 0x9459f3ea39bd8ae1ULL};
static const napi_type_tag entry_tag = {0xc1d86f628b20d4a3ULL, 0x0ed79c3a8f7de527ULL};
static const napi_type_tag cas_root_tag = {0x02848456d04b4b21ULL, 0x8ce46e8f34443e72ULL};
static const napi_type_tag cas_stage_tag = {0x88976e33d2f24b6dULL, 0xa21bca928baf7672ULL};
static const napi_type_tag cas_artifact_tag = {0xd2579527e5db4dc0ULL, 0xb30a60112ab6e73fULL};

static napi_value native_error(napi_env env, const char *message) {
    napi_throw_error(env, "ERR_CLIQ_PACKAGE_READER", message);
    return NULL;
}

static int same_inode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int same_file_metadata(const struct stat *left, const struct stat *right) {
    struct timespec lm = FILE_MTIME(*left), rm = FILE_MTIME(*right);
    struct timespec lc = FILE_CTIME(*left), rc = FILE_CTIME(*right);
    return same_inode(left, right) && left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
        left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
        left->st_size == right->st_size && lm.tv_sec == rm.tv_sec && lm.tv_nsec == rm.tv_nsec &&
        lc.tv_sec == rc.tv_sec && lc.tv_nsec == rc.tv_nsec;
}

static int safe_directory(const struct stat *info, uid_t owner) {
    return S_ISDIR(info->st_mode) && info->st_uid == owner && (info->st_mode & 07022) == 0;
}

static int safe_file(const struct stat *info, uid_t owner, off_t size, int executable) {
    return S_ISREG(info->st_mode) && info->st_uid == owner && info->st_nlink == 1 &&
        (info->st_mode & 07022) == 0 && info->st_size == size &&
        (executable ? (info->st_mode & 0100) != 0 : (info->st_mode & 0111) == 0);
}

static int safe_ancestor(const struct stat *info) {
    if (!S_ISDIR(info->st_mode) || !(info->st_uid == geteuid() || info->st_uid == 0)) return 0;
    if ((info->st_mode & 0022) == 0) return 1;
    /* A root-owned 1777 directory protects another user's named child. */
    return info->st_uid == 0 && (info->st_mode & 07777) == 01777;
}

/* Reopen from / so even an ancestor symlink is rejected. The held descriptor,
 * not the reopened locator, remains the authority for entry reads. */
static int open_absolute_directory(const char *path) {
    if (path[0] != '/' || path[1] == '\0') { errno = EINVAL; return -1; }
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    struct stat held;
    if (fstat(current, &held) < 0 || !safe_ancestor(&held)) {
        close(current); errno = EINVAL; return -1;
    }
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || length > NAME_MAX || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, length); name[length] = '\0';
        struct stat named;
        if (fstatat(current, name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !safe_ancestor(&named)) {
            close(current); errno = EINVAL; return -1;
        }
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        close(current);
        if (next < 0) { errno = saved; return -1; }
        if (fstat(next, &held) < 0 || !same_inode(&named, &held) || !safe_ancestor(&held)) {
            close(next); errno = EINVAL; return -1;
        }
        current = next;
        if (!end) break;
        part = end + 1;
        if (*part == '\0') { close(current); errno = EINVAL; return -1; }
    }
    return current;
}

static int root_is_current(const char *path, const struct stat *identity) {
    int locator = open_absolute_directory(path);
    if (locator < 0) return 0;
    struct stat current;
    int valid = fstat(locator, &current) == 0 && same_file_metadata(identity, &current);
    close(locator);
    return valid;
}

/* Open each component relative to a held directory, comparing the name with
 * the new descriptor. O_NONBLOCK prevents a malicious FIFO from hanging us. */
static int open_relative_file(int root_fd, const char *path, uid_t owner, off_t size,
                              int executable, struct stat *out) {
    if (!path[0] || strlen(path) > MAX_RELATIVE_PATH || strchr(path, '\\')) {
        errno = EINVAL; return -1;
    }
    int current = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current < 0) return -1;
    const char *part = path;
    for (;;) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        if (!length || length > NAME_MAX || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, length); name[length] = '\0';
        struct stat named, held;
        if (fstatat(current, name, &named, AT_SYMLINK_NOFOLLOW) < 0) {
            int saved = errno; close(current); errno = saved; return -1;
        }
        int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        int next = openat(current, name, flags | (end ? O_DIRECTORY : 0));
        int saved = errno;
        close(current);
        if (next < 0) { errno = saved; return -1; }
        if (fstat(next, &held) < 0 || !same_inode(&named, &held) ||
            (end ? !safe_directory(&held, owner) : !safe_file(&held, owner, size, executable))) {
            close(next); errno = EINVAL; return -1;
        }
        if (!end) { *out = held; return next; }
        current = next;
        part = end + 1;
    }
}

static void close_root(package_root *root) {
    if (root->fd >= 0) close(root->fd);
    root->fd = -1;
}

static void close_entry(package_entry *entry) {
    if (entry->fd >= 0) close(entry->fd);
    if (entry->root_fd >= 0) close(entry->root_fd);
    entry->fd = entry->root_fd = -1;
}

static void finalize_root(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    package_root *root = data;
    close_root(root); free(root->path); free(root);
}

static void finalize_entry(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    package_entry *entry = data;
    close_entry(entry); free(entry->root_path); free(entry->relative_path); free(entry);
}

static package_root *unwrap_root(napi_env env, napi_callback_info info) {
    napi_value self;
    package_root *root = NULL;
    bool matches = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &root_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&root) != napi_ok || !root) {
        native_error(env, "invalid package root handle"); return NULL;
    }
    return root;
}

static package_entry *unwrap_entry(napi_env env, napi_callback_info info) {
    napi_value self;
    package_entry *entry = NULL;
    bool matches = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &entry_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&entry) != napi_ok || !entry) {
        native_error(env, "invalid package entry handle"); return NULL;
    }
    return entry;
}

static napi_value undefined_value(napi_env env) {
    napi_value value;
    if (napi_get_undefined(env, &value) != napi_ok) return NULL;
    return value;
}

static napi_value root_close(napi_env env, napi_callback_info info) {
    package_root *root = unwrap_root(env, info);
    if (!root) return NULL;
    close_root(root);
    return undefined_value(env);
}

/* A size hint for the fixed manifest name only. openEntry rechecks it through
 * a held no-follow descriptor, so this observation grants no file authority. */
static napi_value root_manifest_byte_count(napi_env env, napi_callback_info info) {
    package_root *root = unwrap_root(env, info);
    if (!root) return NULL;
    struct stat named;
    if (root->fd < 0 || !root_is_current(root->path, &root->identity) ||
        fstatat(root->fd, MANIFEST_NAME, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        named.st_size <= 0 || named.st_size > MAX_MANIFEST_BYTES ||
        !safe_file(&named, root->identity.st_uid, named.st_size, 0)) {
        return native_error(env, "fixed package manifest is unsafe or missing");
    }
    napi_value result;
    if (napi_create_double(env, (double)named.st_size, &result) != napi_ok) return NULL;
    return result;
}

static napi_value entry_close(napi_env env, napi_callback_info info) {
    package_entry *entry = unwrap_entry(env, info);
    if (!entry) return NULL;
    close_entry(entry);
    return undefined_value(env);
}

static napi_value entry_read_chunk(napi_env env, napi_callback_info info) {
    package_entry *entry = unwrap_entry(env, info);
    if (!entry) return NULL;
    size_t argc = 1;
    napi_value argv[1];
    double requested;
    if (entry->fd < 0 || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok ||
        argc != 1 || napi_get_value_double(env, argv[0], &requested) != napi_ok ||
        !(requested >= 1 && requested <= MAX_CHUNK) ||
        requested != (double)(uint32_t)requested) return native_error(env, "invalid package read chunk");
    uint32_t length = (uint32_t)requested;
    char *bytes = malloc(length);
    if (!bytes) return native_error(env, "package read allocation failed");
    ssize_t count;
    do { count = read(entry->fd, bytes, length); } while (count < 0 && errno == EINTR);
    if (count < 0 || entry->consumed + count > entry->before.st_size) {
        free(bytes); return native_error(env, "package entry changed during read");
    }
    entry->consumed += count;
    napi_value result;
    napi_status status = napi_create_buffer_copy(env, (size_t)count, bytes, NULL, &result);
    free(bytes);
    return status == napi_ok ? result : NULL;
}

static napi_value entry_assert_stable(napi_env env, napi_callback_info info) {
    package_entry *entry = unwrap_entry(env, info);
    if (!entry) return NULL;
    struct stat after, located;
    if (entry->fd < 0 || entry->consumed != entry->before.st_size ||
        fstat(entry->fd, &after) < 0 || !same_file_metadata(&entry->before, &after) ||
        !root_is_current(entry->root_path, &entry->root_identity)) {
        return native_error(env, "package entry is incomplete or changed");
    }
    int locator = open_relative_file(entry->root_fd, entry->relative_path,
        entry->root_identity.st_uid, entry->before.st_size, entry->executable, &located);
    if (locator < 0) return native_error(env, "package entry path changed");
    close(locator);
    if (!same_file_metadata(&entry->before, &located)) {
        return native_error(env, "package entry path changed");
    }
    return undefined_value(env);
}

static napi_value root_open_entry(napi_env env, napi_callback_info info) {
    package_root *root = unwrap_root(env, info);
    if (!root) return NULL;
    size_t argc = 3, length;
    napi_value argv[3];
    double byte_count;
    bool executable;
    if (root->fd < 0 || !root_is_current(root->path, &root->identity) ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 3 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok ||
        length == 0 || length > MAX_RELATIVE_PATH ||
        napi_get_value_double(env, argv[1], &byte_count) != napi_ok ||
        !(byte_count >= 0 && byte_count <= 9007199254740991.0) ||
        byte_count != (double)(int64_t)byte_count ||
        napi_get_value_bool(env, argv[2], &executable) != napi_ok) {
        return native_error(env, "invalid package entry request");
    }
    package_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) return native_error(env, "package entry allocation failed");
    entry->fd = entry->root_fd = -1;
    entry->relative_path = malloc(length + 1);
    entry->root_path = strdup(root->path);
    if (!entry->relative_path || !entry->root_path ||
        napi_get_value_string_utf8(env, argv[0], entry->relative_path, length + 1, &length) != napi_ok ||
        strlen(entry->relative_path) != length) goto fail;
    entry->root_fd = fcntl(root->fd, F_DUPFD_CLOEXEC, 0);
    entry->root_identity = root->identity;
    entry->executable = executable;
    if (entry->root_fd < 0) goto fail;
    entry->fd = open_relative_file(entry->root_fd, entry->relative_path,
        root->identity.st_uid, (off_t)byte_count, executable, &entry->before);
    if (entry->fd < 0 || !root_is_current(root->path, &root->identity)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"readChunk", NULL, entry_read_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertStable", NULL, entry_assert_stable, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, entry_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok) goto fail;
    if (napi_wrap(env, result, entry, finalize_entry, NULL, NULL) != napi_ok) goto fail;
    if (napi_type_tag_object(env, result, &entry_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) goto fail_wrapped;
    return result;
fail_wrapped:
    /* The wrapped object owns entry after napi_wrap; let its finalizer close it. */
    return native_error(env, "package entry handle initialization failed");
fail:
    close_entry(entry); free(entry->relative_path); free(entry->root_path); free(entry);
    return native_error(env, "package entry is unsafe or changed");
}

static napi_value open_package_root(napi_env env, napi_callback_info info) {
    size_t argc = 1, length;
    napi_value argv[1];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok ||
        length == 0 || length >= PATH_MAX) return native_error(env, "invalid package root path");
    package_root *root = calloc(1, sizeof(*root));
    if (!root) return native_error(env, "package root allocation failed");
    root->fd = -1;
    root->path = malloc(length + 1);
    if (!root->path || napi_get_value_string_utf8(env, argv[0], root->path, length + 1, &length) != napi_ok ||
        strlen(root->path) != length) goto fail;
    root->fd = open_absolute_directory(root->path);
    if (root->fd < 0 || fstat(root->fd, &root->identity) < 0 ||
        !(root->identity.st_uid == geteuid() || root->identity.st_uid == 0) ||
        !safe_directory(&root->identity, root->identity.st_uid) ||
        !root_is_current(root->path, &root->identity)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"openEntry", NULL, root_open_entry, NULL, NULL, NULL, napi_default, NULL},
        {"manifestByteCount", NULL, root_manifest_byte_count, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, root_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok) goto fail;
    if (napi_wrap(env, result, root, finalize_root, NULL, NULL) != napi_ok) goto fail;
    if (napi_type_tag_object(env, result, &root_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) goto fail_wrapped;
    return result;
fail_wrapped:
    return native_error(env, "package root handle initialization failed");
fail:
    close_root(root); free(root->path); free(root);
    return native_error(env, "package root is unsafe or changed");
}

/* CAS roots are mutable 0700 directories. Their locator and authority metadata
 * stay fixed, while ordinary file publication changes directory timestamps. */
static int cas_root_is_current(const char *path, const struct stat *identity) {
    int locator = open_absolute_directory(path);
    if (locator < 0) return 0;
    struct stat current;
    int valid = fstat(locator, &current) == 0 && same_inode(identity, &current) &&
        current.st_uid == identity->st_uid && current.st_gid == identity->st_gid &&
        current.st_mode == identity->st_mode &&
        S_ISDIR(current.st_mode) && (current.st_mode & 07777) == 0700;
    close(locator);
    return valid;
}

static int exact_hex(const char *value, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    }
    return value[length] == '\0';
}

static int read_hex(napi_env env, napi_value value, char *result, size_t digits) {
    size_t length;
    return napi_get_value_string_utf8(env, value, NULL, 0, &length) == napi_ok &&
        length == digits &&
        napi_get_value_string_utf8(env, value, result, digits + 1, &length) == napi_ok &&
        length == digits && exact_hex(result, digits);
}

static int cas_file_safe(const struct stat *info, uid_t owner, off_t size, mode_t mode) {
    return S_ISREG(info->st_mode) && info->st_uid == owner && info->st_nlink == 1 &&
        (info->st_mode & 07777) == mode && info->st_size == size;
}

static void close_cas_root(cas_root *root) {
    if (root->fd >= 0) close(root->fd);
    root->fd = -1;
}

static void finalize_cas_root(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    cas_root *root = data;
    close_cas_root(root); free(root->path); free(root);
}

static cas_root *unwrap_cas_root(napi_env env, napi_callback_info info) {
    napi_value self;
    cas_root *root = NULL;
    bool matches = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &cas_root_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&root) != napi_ok || !root) {
        native_error(env, "invalid CAS root handle"); return NULL;
    }
    return root;
}

static napi_value cas_root_close(napi_env env, napi_callback_info info) {
    cas_root *root = unwrap_cas_root(env, info);
    if (!root) return NULL;
    close_cas_root(root);
    return undefined_value(env);
}

static napi_value cas_root_begin_stage(napi_env env, napi_callback_info info);
static napi_value cas_root_open_artifact(napi_env env, napi_callback_info info);

static napi_value open_cas_root(napi_env env, napi_callback_info info) {
    size_t argc = 1, length;
    napi_value argv[1];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, argv[0], NULL, 0, &length) != napi_ok ||
        length == 0 || length >= PATH_MAX) return native_error(env, "invalid CAS root path");
    cas_root *root = calloc(1, sizeof(*root));
    if (!root) return native_error(env, "CAS root allocation failed");
    root->fd = -1;
    root->path = malloc(length + 1);
    if (!root->path || napi_get_value_string_utf8(env, argv[0], root->path, length + 1, &length) != napi_ok ||
        strlen(root->path) != length) goto fail;
    root->fd = open_absolute_directory(root->path);
    if (root->fd < 0 || fstat(root->fd, &root->identity) < 0 ||
        root->identity.st_uid != geteuid() || !cas_root_is_current(root->path, &root->identity)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"beginStage", NULL, cas_root_begin_stage, NULL, NULL, NULL, napi_default, NULL},
        {"openArtifact", NULL, cas_root_open_artifact, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, cas_root_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok) goto fail;
    if (napi_wrap(env, result, root, finalize_cas_root, NULL, NULL) != napi_ok) goto fail;
    if (napi_type_tag_object(env, result, &cas_root_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) return native_error(env, "CAS root handle initialization failed");
    return result;
fail:
    close_cas_root(root); free(root->path); free(root);
    return native_error(env, "CAS root is unsafe or changed");
}

static void close_cas_stage(cas_stage *stage) {
    if (stage->fd >= 0) close(stage->fd);
    if (stage->root_fd >= 0) close(stage->root_fd);
    stage->fd = stage->root_fd = -1;
}

static void finalize_cas_stage(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    cas_stage *stage = data;
    close_cas_stage(stage);
    free(stage->root_path); free(stage->name); free(stage->ref); free(stage);
}

static cas_stage *unwrap_cas_stage(napi_env env, napi_callback_info info) {
    napi_value self;
    cas_stage *stage = NULL;
    bool matches = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &cas_stage_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&stage) != napi_ok || !stage) {
        native_error(env, "invalid CAS stage handle"); return NULL;
    }
    return stage;
}

static napi_value cas_stage_write_chunk(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    size_t argc = 1, length;
    napi_value argv[1];
    void *bytes;
    if (stage->state != 0 || stage->fd < 0 ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_buffer_info(env, argv[0], &bytes, &length) != napi_ok ||
        length == 0 || length > MAX_CHUNK || (off_t)length > stage->expected - stage->written ||
        !cas_root_is_current(stage->root_path, &stage->root_identity)) {
        return native_error(env, "invalid CAS stage write");
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(stage->fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "CAS stage write failed");
        offset += (size_t)count;
        stage->written += count;
    }
    return undefined_value(env);
}

static napi_value cas_stage_seal(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    struct stat named, before, after;
    if (stage->state != 0 || stage->fd < 0 || stage->written != stage->expected ||
        !cas_root_is_current(stage->root_path, &stage->root_identity) ||
        fstatat(stage->root_fd, stage->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        fstat(stage->fd, &before) < 0 || !same_inode(&named, &before) ||
        !cas_file_safe(&before, stage->root_identity.st_uid, stage->expected, 0600) ||
        fchmod(stage->fd, 0400) < 0 || fsync(stage->fd) < 0 || fstat(stage->fd, &after) < 0 ||
        !cas_file_safe(&after, stage->root_identity.st_uid, stage->expected, 0400) ||
        !cas_root_is_current(stage->root_path, &stage->root_identity)) {
        return native_error(env, "CAS stage cannot be sealed");
    }
    stage->sealed = after;
    stage->read_offset = 0;
    stage->state = 1;
    return undefined_value(env);
}

static napi_value cas_stage_read_chunk(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    size_t argc = 1;
    napi_value argv[1];
    double requested;
    if (stage->state != 1 || stage->fd < 0 ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_double(env, argv[0], &requested) != napi_ok ||
        !(requested >= 1 && requested <= MAX_CHUNK) || requested != (double)(uint32_t)requested) {
        return native_error(env, "invalid CAS stage read");
    }
    size_t length = (size_t)requested;
    if ((off_t)length > stage->expected - stage->read_offset) length = (size_t)(stage->expected - stage->read_offset);
    char *bytes = malloc(length ? length : 1);
    if (!bytes) return native_error(env, "CAS stage read allocation failed");
    ssize_t count;
    do { count = pread(stage->fd, bytes, length, stage->read_offset); } while (count < 0 && errno == EINTR);
    if (count < 0) { free(bytes); return native_error(env, "CAS stage read failed"); }
    stage->read_offset += count;
    napi_value result;
    napi_status status = napi_create_buffer_copy(env, (size_t)count, bytes, NULL, &result);
    free(bytes);
    return status == napi_ok ? result : NULL;
}

static int cas_stage_is_stable(cas_stage *stage) {
    struct stat named, after;
    return stage->state == 1 && stage->fd >= 0 && stage->read_offset == stage->expected &&
        cas_root_is_current(stage->root_path, &stage->root_identity) &&
        fstatat(stage->root_fd, stage->name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        fstat(stage->fd, &after) == 0 && same_file_metadata(&stage->sealed, &after) &&
        same_file_metadata(&named, &after);
}

static napi_value cas_stage_assert_stable(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    if (!cas_stage_is_stable(stage)) return native_error(env, "CAS stage is incomplete or changed");
    return undefined_value(env);
}

static napi_value cas_stage_publish(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    if (!cas_stage_is_stable(stage)) return native_error(env, "CAS stage is incomplete or changed");
    int linked = linkat(stage->root_fd, stage->name, stage->root_fd, stage->ref, 0);
    if (linked < 0 && errno != EEXIST) return native_error(env, "CAS artifact publication failed");
    if (linked == 0) {
        if (fsync(stage->root_fd) < 0 || unlinkat(stage->root_fd, stage->name, 0) < 0 ||
            fsync(stage->root_fd) < 0 ||
            !cas_root_is_current(stage->root_path, &stage->root_identity)) {
            return native_error(env, "CAS artifact publication is uncertain");
        }
        stage->state = 2;
    }
    napi_value result;
    if (napi_get_boolean(env, linked == 0, &result) != napi_ok) return NULL;
    return result;
}

static napi_value cas_stage_abort(napi_env env, napi_callback_info info) {
    cas_stage *stage = unwrap_cas_stage(env, info);
    if (!stage) return NULL;
    if (stage->state == 3) return undefined_value(env);
    if (stage->root_fd >= 0 && stage->name && stage->state != 2) {
        struct stat named, held;
        if (!cas_root_is_current(stage->root_path, &stage->root_identity) ||
            fstat(stage->fd, &held) < 0) return native_error(env, "CAS stage cleanup cannot prove its root");
        if (fstatat(stage->root_fd, stage->name, &named, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!same_inode(&named, &held) || unlinkat(stage->root_fd, stage->name, 0) < 0 ||
                fsync(stage->root_fd) < 0) return native_error(env, "CAS stage cleanup is uncertain");
        } else if (errno != ENOENT) {
            return native_error(env, "CAS stage cleanup cannot inspect its name");
        }
    }
    close_cas_stage(stage);
    stage->state = 3;
    return undefined_value(env);
}

static napi_value cas_root_begin_stage(napi_env env, napi_callback_info info) {
    cas_root *root = unwrap_cas_root(env, info);
    if (!root) return NULL;
    size_t argc = 3;
    napi_value argv[3];
    char ref[65], nonce[33];
    double requested;
    if (root->fd < 0 || !cas_root_is_current(root->path, &root->identity) ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 3 ||
        !read_hex(env, argv[0], ref, 64) || !read_hex(env, argv[2], nonce, 32) ||
        napi_get_value_double(env, argv[1], &requested) != napi_ok ||
        !(requested >= 0 && requested <= 9007199254740991.0) ||
        requested != (double)(int64_t)requested) return native_error(env, "invalid CAS stage request");
    cas_stage *stage = calloc(1, sizeof(*stage));
    if (!stage) return native_error(env, "CAS stage allocation failed");
    stage->fd = stage->root_fd = -1;
    stage->expected = (off_t)requested;
    stage->root_path = strdup(root->path);
    stage->ref = strdup(ref);
    stage->name = malloc(5 + 64 + 1 + 32 + 1);
    if (!stage->root_path || !stage->ref || !stage->name) goto fail;
    snprintf(stage->name, 5 + 64 + 1 + 32 + 1, ".tmp-%s-%s", ref, nonce);
    stage->root_fd = fcntl(root->fd, F_DUPFD_CLOEXEC, 0);
    stage->root_identity = root->identity;
    if (stage->root_fd < 0) goto fail;
    stage->fd = openat(stage->root_fd, stage->name,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat created;
    if (stage->fd < 0 || fstat(stage->fd, &created) < 0 ||
        !cas_file_safe(&created, root->identity.st_uid, 0, 0600) ||
        !cas_root_is_current(root->path, &root->identity)) goto fail_created;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"writeChunk", NULL, cas_stage_write_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"seal", NULL, cas_stage_seal, NULL, NULL, NULL, napi_default, NULL},
        {"readChunk", NULL, cas_stage_read_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertStable", NULL, cas_stage_assert_stable, NULL, NULL, NULL, napi_default, NULL},
        {"publish", NULL, cas_stage_publish, NULL, NULL, NULL, napi_default, NULL},
        {"abort", NULL, cas_stage_abort, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok) goto fail_created;
    if (napi_wrap(env, result, stage, finalize_cas_stage, NULL, NULL) != napi_ok) goto fail_created;
    if (napi_type_tag_object(env, result, &cas_stage_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) return native_error(env, "CAS stage handle initialization failed");
    return result;
fail_created:
    if (stage->fd >= 0) {
        struct stat named, held;
        if (fstat(stage->fd, &held) == 0 &&
            fstatat(stage->root_fd, stage->name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_inode(&named, &held)) unlinkat(stage->root_fd, stage->name, 0);
    }
fail:
    close_cas_stage(stage); free(stage->root_path); free(stage->name); free(stage->ref); free(stage);
    return native_error(env, "CAS stage creation failed");
}

static void close_cas_artifact(cas_artifact *artifact) {
    if (artifact->fd >= 0) close(artifact->fd);
    if (artifact->root_fd >= 0) close(artifact->root_fd);
    artifact->fd = artifact->root_fd = -1;
}

static void finalize_cas_artifact(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    cas_artifact *artifact = data;
    close_cas_artifact(artifact); free(artifact->root_path); free(artifact->ref); free(artifact);
}

static cas_artifact *unwrap_cas_artifact(napi_env env, napi_callback_info info) {
    napi_value self;
    cas_artifact *artifact = NULL;
    bool matches = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &cas_artifact_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, (void **)&artifact) != napi_ok || !artifact) {
        native_error(env, "invalid CAS artifact handle"); return NULL;
    }
    return artifact;
}

static napi_value cas_artifact_read_chunk(napi_env env, napi_callback_info info) {
    cas_artifact *artifact = unwrap_cas_artifact(env, info);
    if (!artifact) return NULL;
    size_t argc = 1;
    napi_value argv[1];
    double requested;
    if (artifact->fd < 0 ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_double(env, argv[0], &requested) != napi_ok ||
        !(requested >= 1 && requested <= MAX_CHUNK) || requested != (double)(uint32_t)requested) {
        return native_error(env, "invalid CAS artifact read");
    }
    size_t length = (size_t)requested;
    if ((off_t)length > artifact->before.st_size - artifact->read_offset) {
        length = (size_t)(artifact->before.st_size - artifact->read_offset);
    }
    char *bytes = malloc(length ? length : 1);
    if (!bytes) return native_error(env, "CAS artifact read allocation failed");
    ssize_t count;
    do { count = pread(artifact->fd, bytes, length, artifact->read_offset); } while (count < 0 && errno == EINTR);
    if (count < 0) { free(bytes); return native_error(env, "CAS artifact read failed"); }
    artifact->read_offset += count;
    napi_value result;
    napi_status status = napi_create_buffer_copy(env, (size_t)count, bytes, NULL, &result);
    free(bytes);
    return status == napi_ok ? result : NULL;
}

static napi_value cas_artifact_assert_stable(napi_env env, napi_callback_info info) {
    cas_artifact *artifact = unwrap_cas_artifact(env, info);
    if (!artifact) return NULL;
    struct stat named, after;
    if (artifact->fd < 0 || artifact->read_offset != artifact->before.st_size ||
        !cas_root_is_current(artifact->root_path, &artifact->root_identity) ||
        fstat(artifact->fd, &after) < 0 ||
        fstatat(artifact->root_fd, artifact->ref, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !same_file_metadata(&artifact->before, &after) ||
        !same_file_metadata(&named, &after)) {
        return native_error(env, "CAS artifact is incomplete or changed");
    }
    return undefined_value(env);
}

static napi_value cas_artifact_close(napi_env env, napi_callback_info info) {
    cas_artifact *artifact = unwrap_cas_artifact(env, info);
    if (!artifact) return NULL;
    close_cas_artifact(artifact);
    return undefined_value(env);
}

static napi_value cas_root_open_artifact(napi_env env, napi_callback_info info) {
    cas_root *root = unwrap_cas_root(env, info);
    if (!root) return NULL;
    size_t argc = 2;
    napi_value argv[2];
    char ref[65];
    double requested;
    if (root->fd < 0 || !cas_root_is_current(root->path, &root->identity) ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        !read_hex(env, argv[0], ref, 64) ||
        napi_get_value_double(env, argv[1], &requested) != napi_ok ||
        !(requested >= 0 && requested <= 9007199254740991.0) ||
        requested != (double)(int64_t)requested) return native_error(env, "invalid CAS artifact request");
    cas_artifact *artifact = calloc(1, sizeof(*artifact));
    if (!artifact) return native_error(env, "CAS artifact allocation failed");
    artifact->fd = artifact->root_fd = -1;
    artifact->root_path = strdup(root->path);
    artifact->ref = strdup(ref);
    if (!artifact->root_path || !artifact->ref) goto fail;
    artifact->root_fd = fcntl(root->fd, F_DUPFD_CLOEXEC, 0);
    artifact->root_identity = root->identity;
    if (artifact->root_fd < 0) goto fail;
    struct stat named;
    if (fstatat(artifact->root_fd, ref, &named, AT_SYMLINK_NOFOLLOW) < 0) goto fail;
    artifact->fd = openat(artifact->root_fd, ref, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (artifact->fd < 0 || fstat(artifact->fd, &artifact->before) < 0 ||
        !same_inode(&named, &artifact->before) ||
        !cas_file_safe(&artifact->before, root->identity.st_uid, (off_t)requested, 0400) ||
        !cas_root_is_current(root->path, &root->identity)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"readChunk", NULL, cas_artifact_read_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertStable", NULL, cas_artifact_assert_stable, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, cas_artifact_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok) goto fail;
    if (napi_wrap(env, result, artifact, finalize_cas_artifact, NULL, NULL) != napi_ok) goto fail;
    if (napi_type_tag_object(env, result, &cas_artifact_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok) return native_error(env, "CAS artifact handle initialization failed");
    return result;
fail:
    close_cas_artifact(artifact); free(artifact->root_path); free(artifact->ref); free(artifact);
    return native_error(env, "CAS artifact is unsafe or changed");
}

static napi_value initialize(napi_env env, napi_value exports) {
    const napi_property_descriptor methods[] = {
        {"openRoot", NULL, open_package_root, NULL, NULL, NULL, napi_default, NULL},
        {"openCasRoot", NULL, open_cas_root, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return NULL;
    return exports;
}

NAPI_MODULE(cliq_package_reader, initialize)
