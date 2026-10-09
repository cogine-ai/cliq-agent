/* Source identity is read-only and distinct from private StateRoot/generation
 * ownership. Hold every ancestor: a later pathname lookup grants no authority. */
typedef struct source_cursor source_cursor;
typedef struct {
    int *fds, git_fd, config_fd;
    struct stat *ids, git_id, config_id;
    char **names, *path;
    size_t count;
    off_t config_offset;
    source_cursor *cursors;
    int finalized, retirement_error;
} source_root;
static const napi_type_tag source_root_tag = {0x6aa7d22ed5f2eec2ULL, 0x96f4193bc7fb4e09ULL};
static int source_close_cursors(source_root *root);

static int source_close_fds(source_root *root) {
    int failure = source_close_cursors(root);
    const int config = root->config_fd, git = root->git_fd;
    root->config_fd = root->git_fd = -1;
    if (config >= 0 && close(config) < 0 && !failure) failure = errno;
    if (git >= 0 && close(git) < 0 && !failure) failure = errno;
    for (size_t i = root->count; i > 0; i--) {
        const int fd = root->fds[i - 1]; root->fds[i - 1] = -1;
        if (fd >= 0 && close(fd) < 0 && !failure) failure = errno;
    }
    if (failure) root->retirement_error = failure;
    return root->retirement_error;
}
static void source_free(source_root *root) {
    free(root->fds); free(root->ids); free(root->names); free(root->path); free(root);
}
static void source_free_if_done(source_root *root) {
    if (root->finalized && !root->cursors) source_free(root);
}
static void finalize_source_root(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    source_root *root = data;
    source_close_fds(root); root->finalized = 1; source_free_if_done(root);
}
static int source_config_same(const struct stat *left, const struct stat *right) {
    if (!S_ISREG(right->st_mode) || !same_inode(left, right) || left->st_size != right->st_size ||
        left->st_uid != right->st_uid || left->st_mode != right->st_mode || left->st_nlink != right->st_nlink) return 0;
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
        left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}
static int source_held(source_root *root) {
    struct stat opened, named;
    if (!root->count || root->fds[0] < 0 || root->retirement_error) return 0;
    for (size_t i = 0; i < root->count; i++) {
        if (root->fds[i] < 0 || fstat(root->fds[i], &opened) < 0 || !S_ISDIR(opened.st_mode) ||
            !same_inode(&opened, &root->ids[i]) || opened.st_uid != root->ids[i].st_uid) return 0;
        if (i && (fstatat(root->fds[i - 1], root->names[i - 1], &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !S_ISDIR(named.st_mode) || !same_inode(&opened, &named))) return 0;
    }
    const int root_fd = root->fds[root->count - 1];
    if (root->git_fd < 0) return fstatat(root_fd, ".git", &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (fstat(root->git_fd, &opened) < 0 || !S_ISDIR(opened.st_mode) || !same_inode(&opened, &root->git_id) ||
        opened.st_dev != root->ids[root->count - 1].st_dev ||
        opened.st_uid != root->git_id.st_uid || fstatat(root_fd, ".git", &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISDIR(named.st_mode) || !same_inode(&opened, &named)) return 0;
    if (root->config_fd < 0) return fstatat(root->git_fd, "config", &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    return fstat(root->config_fd, &opened) == 0 && source_config_same(&root->config_id, &opened) &&
        fstatat(root->git_fd, "config", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_config_same(&opened, &named);
}
static source_root *unwrap_source_root(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; source_root *root = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &source_root_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&root) != napi_ok || !root) {
        native_error(env, "invalid source workspace handle"); return NULL;
    }
    return root;
}
static napi_value source_assert(napi_env env, napi_callback_info info) {
    source_root *root = unwrap_source_root(env, info);
    if (!root) return NULL;
    if (!source_held(root)) return native_error(env, "source workspace descriptor identity changed or closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_close(napi_env env, napi_callback_info info) {
    source_root *root = unwrap_source_root(env, info);
    if (!root) return NULL;
    if (source_close_fds(root)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "source workspace descriptor retirement failed"); return NULL;
    }
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_config_chunk(napi_env env, napi_callback_info info) {
    source_root *root = unwrap_source_root(env, info);
    if (!root) return NULL;
    if (!source_held(root)) return native_error(env, "source workspace descriptor identity changed or closed");
    if (root->config_fd < 0 || root->config_offset == root->config_id.st_size) {
        napi_value value; return napi_get_null(env, &value) == napi_ok ? value : NULL;
    }
    unsigned char bytes[65536];
    const off_t remaining = root->config_id.st_size - root->config_offset;
    const size_t length = remaining < (off_t)sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
    ssize_t count;
    do { count = pread(root->config_fd, bytes, length, root->config_offset); } while (count < 0 && errno == EINTR);
    if (count <= 0 || !source_held(root)) return native_error(env, "source Git config changed or became unreadable");
    root->config_offset += count;
    napi_value value; return napi_create_buffer_copy(env, (size_t)count, bytes, NULL, &value) == napi_ok ? value : NULL;
}
#include "source-walk.c"
static napi_value open_workspace_root(napi_env env, napi_callback_info info) {
    size_t argc = 1, length; napi_value argument;
    if (napi_get_cb_info(env, info, &argc, &argument, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_string_utf8(env, argument, NULL, 0, &length) != napi_ok || length < 2 || length > 4096)
        return native_error(env, "invalid source workspace path");
    source_root *root = calloc(1, sizeof(*root));
    if (!root) return native_error(env, "source workspace allocation failed");
    root->git_fd = root->config_fd = -1;
    root->path = malloc(length + 1);
    const char *error = "cannot open source workspace without following symlinks";
    if (!root->path || napi_get_value_string_utf8(env, argument, root->path, length + 1, &length) != napi_ok ||
        strlen(root->path) != length || root->path[0] != '/' || root->path[length - 1] == '/') goto fail;
    size_t capacity = 1;
    for (size_t i = 1; i < length; i++) if (root->path[i] == '/') capacity++;
    root->fds = malloc((capacity + 1) * sizeof(*root->fds));
    root->ids = calloc(capacity + 1, sizeof(*root->ids)); root->names = calloc(capacity, sizeof(*root->names));
    if (!root->fds || !root->ids || !root->names) goto fail;
    root->fds[0] = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC); root->count = 1;
    if (root->fds[0] < 0 || fstat(root->fds[0], &root->ids[0]) < 0) goto fail;
    char *component = root->path + 1;
    for (;;) {
        char *end = strchr(component, '/');
        if (end) *end = '\0';
        if (!*component || strlen(component) > NAME_MAX || strcmp(component, ".") == 0 || strcmp(component, "..") == 0) goto fail;
        root->names[root->count - 1] = component;
        const int fd = openat(root->fds[root->count - 1], component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        root->fds[root->count] = fd; root->count++;
        if (fd < 0 || fstat(fd, &root->ids[root->count - 1]) < 0) goto fail;
        if (!end) break;
        component = end + 1;
    }
    const struct stat *identity = &root->ids[root->count - 1];
    error = "source workspace root must be owned by the effective uid";
    if (identity->st_uid != geteuid()) goto fail;
    error = "workspace .git must be a same-device in-root directory owned by the workspace owner";
    root->git_fd = openat(root->fds[root->count - 1], ".git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root->git_fd < 0) { if (errno != ENOENT) goto fail; }
    else {
        if (fstat(root->git_fd, &root->git_id) < 0 || root->git_id.st_uid != identity->st_uid || root->git_id.st_dev != identity->st_dev) goto fail;
        error = "workspace .git/config must be a bounded regular file, not a symlink or special file";
        root->config_fd = openat(root->git_fd, "config", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (root->config_fd < 0) { if (errno != ENOENT) goto fail; }
        else if (fstat(root->config_fd, &root->config_id) < 0 || !S_ISREG(root->config_id.st_mode) ||
            root->config_id.st_dev != identity->st_dev || root->config_id.st_size < 0 || root->config_id.st_size > 1048576) goto fail;
    }
    error = "source workspace descriptor identity changed or closed";
    if (!source_held(root)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, source_assert, NULL, NULL, NULL, napi_default, NULL},
        {"readGitConfigChunk", NULL, source_config_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"openSnapshot", NULL, source_open_snapshot, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "identity", identity) ||
        (root->git_fd >= 0 && !identity_member(env, result, "repositoryDirectory", &root->git_id)) ||
        napi_type_tag_object(env, result, &source_root_tag) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) goto fail;
    if (napi_wrap(env, result, root, finalize_source_root, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    if (source_close_fds(root)) {
        source_free(root); napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "source opening failed and descriptor retirement did not complete"); return NULL;
    }
    source_free(root); return native_error(env, error);
}
