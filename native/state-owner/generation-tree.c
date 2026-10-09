/* Private generation trees: StateOwner-relative descriptors, never caller paths.
 * The host tree is staging only; Linux containment/VM authority is separate. */
#include <dirent.h>
#define GENERATION_MAX_BYTES (100ULL * 1024 * 1024 * 1024)

typedef struct generation_borrow generation_borrow;
typedef struct generation_cursor generation_cursor;
typedef struct generation_stream generation_stream;
static void close_tree_streams(generation_tree *tree);
struct generation_tree {
    state_lock *lock;
    napi_ref lock_ref;
    int parents[5], fd, git_fd, retained, archived, finalized;
    struct stat parent_ids[5], identity, git_identity;
    char run[129], generation[44], target[44];
    generation_borrow *borrows;
    generation_cursor *cursors;
    generation_stream *streams;
    generation_tree *next;
};
struct generation_borrow {
    generation_tree *tree;
    napi_ref tree_ref;
    int fd;
    generation_borrow *next;
};
static const napi_type_tag tree_tag = {0xc626aab45303f22dULL, 0xf5bdbb739dd3f01eULL};
static const napi_type_tag borrow_tag = {0xc9430387dce4cc29ULL, 0xfbe71a981f7de18cULL};

static void close_tree(generation_tree *tree) {
    close_tree_streams(tree);
    for (generation_borrow *borrow = tree->borrows; borrow; borrow = borrow->next) {
        if (borrow->fd >= 0) close(borrow->fd);
        borrow->fd = -1;
    }
    if (tree->git_fd >= 0) close(tree->git_fd);
    tree->git_fd = -1;
    if (tree->fd >= 0) close(tree->fd);
    tree->fd = -1;
    for (int i = 4; i >= 0; i--) {
        if (tree->parents[i] >= 0) close(tree->parents[i]);
        tree->parents[i] = -1;
    }
}
static void close_lock_trees(state_lock *lock) {
    for (generation_tree *tree = lock->trees; tree; tree = tree->next) close_tree(tree);
}
static void free_tree_if_done(napi_env env, generation_tree *tree) {
    /* Strong JS references do not order environment finalizers. Raw parents
     * remain alive until every native child has unlinked from its list. */
    if (!tree->finalized || tree->streams || tree->cursors || tree->borrows) return;
    state_lock *lock = tree->lock;
    napi_ref lock_ref = tree->lock_ref;
    generation_tree **link = &tree->lock->trees;
    while (*link && *link != tree) link = &(*link)->next;
    if (*link) *link = tree->next;
    free(tree);
    free_lock_if_done(lock);
    napi_delete_reference(env, lock_ref);
}
static void finalize_tree(napi_env env, void *data, void *hint) {
    (void)hint;
    generation_tree *tree = data;
    close_tree(tree);
    tree->finalized = 1;
    free_tree_if_done(env, tree);
}
static int tree_directory_at(int parent, const char *name, const struct stat *identity) {
    struct stat named;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT ? 0 : -1;
    return private_directory(&named) && same_inode(&named, identity) ? 1 : -1;
}
static int tree_held(generation_tree *tree) {
    if (tree->fd < 0 || !lock_is_held(tree->lock)) return 0;
    const char *names[] = {"runs", tree->run, "generations", "quarantine", "workspace-generations"};
    for (int i = 0; i < (tree->retained ? 5 : 3); i++) {
        struct stat opened, named;
        int parent = i == 0 || i == 3 ? tree->lock->root_fd : tree->parents[i - 1];
        if (parent < 0) continue; /* Its absence was checked at the prior level. */
        if (tree->parents[i] < 0) {
            if (fstatat(parent, names[i], &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return 0;
            continue;
        }
        if (fstat(tree->parents[i], &opened) < 0 || !private_directory(&opened) ||
            !same_inode(&opened, &tree->parent_ids[i]) ||
            fstatat(parent, names[i], &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&opened, &named)) return 0;
    }
    struct stat opened, named;
    if (tree->git_fd >= 0 && (fstat(tree->git_fd, &opened) < 0 || !private_directory(&opened) ||
        opened.st_dev != tree->identity.st_dev || !same_inode(&opened, &tree->git_identity) ||
        fstatat(tree->fd, ".git", &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&opened, &named))) return 0;
    if (fstat(tree->fd, &opened) < 0 || !private_directory(&opened) || !same_inode(&opened, &tree->identity)) return 0;
    const int source = tree_directory_at(tree->parents[2], tree->generation, &tree->identity);
    if (!tree->retained) return source == 1;
    const int target = tree->parents[4] < 0 ? 0 : tree_directory_at(tree->parents[4], tree->target, &tree->identity);
    return source == !tree->archived && target == tree->archived;
}
static generation_tree *unwrap_tree(napi_env env, napi_callback_info info) {
    napi_value receiver;
    generation_tree *tree = NULL;
    bool tagged = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok ||
        napi_check_object_type_tag(env, receiver, &tree_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, receiver, (void **)&tree) != napi_ok || !tree) {
        native_error(env, "invalid private generation tree handle"); return NULL;
    }
    return tree;
}
static napi_value tree_assert(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    if (!tree_held(tree)) return native_error(env, "private generation descriptor or StateOwner changed or closed");
    napi_value value;
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value tree_close(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    close_tree(tree);
    napi_value value;
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}

/* Every path is an exact UTF-8 relative entry; .git is controlled by the
 * trusted producer, not interpreted here as a link to a host repository. */
static int tree_path(napi_env env, napi_value value, char path[4097]) {
    size_t length;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length == 0 || length > 4096 ||
        napi_get_value_string_utf8(env, value, path, 4097, &length) != napi_ok || strlen(path) != length ||
        path[0] == '/' || path[length - 1] == '/' || strchr(path, '\\')) return 0;
    char *start = path;
    for (char *p = path; ; p++) {
        if (*p != '/' && *p != 0) continue;
        size_t size = (size_t)(p - start);
        if (size == 0 || size > NAME_MAX || (size == 1 && start[0] == '.') ||
            (size == 2 && start[0] == '.' && start[1] == '.')) return 0;
        if (*p == 0) break;
        start = p + 1;
    }
    return 1;
}
static int content_directory(const struct stat *info, dev_t device) {
    return S_ISDIR(info->st_mode) && info->st_uid == geteuid() && info->st_dev == device &&
        (info->st_mode & 07777) == 0755;
}
static int metadata_path(const char *path) { return !strcmp(path, ".git") || !strncmp(path, ".git/", 5); }
static int entry_directory(const struct stat *info, dev_t device, int metadata) {
    return metadata ? private_directory(info) && info->st_dev == device : content_directory(info, device);
}
/* Holds all traversed ancestors until the operation and post-check finish. */
typedef struct { int fds[2049]; struct stat ids[2049]; char *names[2049]; size_t count; int metadata; char path[4097]; } tree_walk;
static void close_walk(tree_walk *walk) {
    for (size_t i = walk->count; i > 0; i--) close(walk->fds[i - 1]);
    walk->count = 0;
}
static int walk_parent(generation_tree *tree, const char *path, tree_walk *walk, char **leaf) {
    memset(walk, 0, sizeof(*walk));
    walk->metadata = metadata_path(path);
    memcpy(walk->path, path, strlen(path) + 1);
    char *start = walk->path, *slash;
    int parent = tree->fd;
    while ((slash = strchr(start, '/')) != NULL) {
        *slash = 0;
        int fd = openat(parent, start, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat opened, named;
        if (fd < 0) goto failed;
        if (fstat(fd, &opened) < 0 || !entry_directory(&opened, tree->identity.st_dev, walk->metadata) ||
            fstatat(parent, start, &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&opened, &named)) { close(fd); goto failed; }
        walk->fds[walk->count] = fd; walk->ids[walk->count] = opened; walk->names[walk->count++] = start;
        parent = fd; start = slash + 1;
    }
    *leaf = start;
    return parent;
failed:
    close_walk(walk); return -1;
}
static int walk_held(generation_tree *tree, tree_walk *walk) {
    if (!tree_held(tree)) return 0;
    for (size_t i = 0; i < walk->count; i++) {
        struct stat opened, named;
        int parent = i == 0 ? tree->fd : walk->fds[i - 1];
        if (fstat(walk->fds[i], &opened) < 0 || !entry_directory(&opened, tree->identity.st_dev, walk->metadata) ||
            !same_inode(&opened, &walk->ids[i]) || fstatat(parent, walk->names[i], &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !same_inode(&opened, &named)) return 0;
    }
    return 1;
}
static napi_value tree_mkdir(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    size_t argc = 1; napi_value argv[1]; char path[4097], *leaf;
    if (tree->retained || !tree_held(tree) || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        !tree_path(env, argv[0], path)) return native_error(env, "invalid private generation directory path or closed handle");
    tree_walk walk; int parent = walk_parent(tree, path, &walk, &leaf), fd = -1;
    const char *error = "private generation mkdir requires absent entry and held no-follow parents";
    struct stat opened, named;
    int metadata = metadata_path(path);
    if (parent < 0 || !walk_held(tree, &walk) || mkdirat(parent, leaf, 0700) < 0) goto done;
    fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fchmod(fd, metadata ? 0700 : 0755) < 0 || fstat(fd, &opened) < 0 || !entry_directory(&opened, tree->identity.st_dev, metadata) ||
        fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&opened, &named) ||
        !sync_directory(fd) || !sync_directory(parent) || !walk_held(tree, &walk)) goto done;
    if (!strcmp(path, ".git")) { tree->git_fd = fd; tree->git_identity = opened; fd = -1; }
    error = NULL;
done:
    if (fd >= 0) close(fd);
    close_walk(&walk);
    if (error) return native_error(env, error);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static int content_file(const struct stat *info, dev_t device, mode_t mode) {
    return S_ISREG(info->st_mode) && info->st_uid == geteuid() && info->st_dev == device &&
        info->st_nlink == 1 && (info->st_mode & 07777) == mode;
}
static int utf8_valid(const unsigned char *bytes) {
    while (*bytes) {
        unsigned char first = *bytes++;
        if (first < 0x80) continue;
        int count; unsigned int code;
        if (first >= 0xc2 && first <= 0xdf) { count = 1; code = first & 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { count = 2; code = first & 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { count = 3; code = first & 0x07; }
        else return 0;
        for (int i = 0; i < count; i++) {
            if (*bytes < 0x80 || *bytes > 0xbf) return 0;
            code = (code << 6) | (*bytes++ & 0x3f);
        }
        if ((count == 2 && code < 0x800) || (count == 3 && code < 0x10000) ||
            (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff) return 0;
    }
    return 1;
}
static napi_value tree_symlink(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    size_t argc = 2, length; napi_value argv[2]; char path[4097], target[4097], *leaf;
    if (tree->retained || !tree_held(tree) || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 2 ||
        !tree_path(env, argv[0], path) || metadata_path(path) || napi_get_value_string_utf8(env, argv[1], NULL, 0, &length) != napi_ok ||
        length == 0 || length > 4096 || napi_get_value_string_utf8(env, argv[1], target, sizeof(target), &length) != napi_ok ||
        strlen(target) != length || target[0] == '/' || strchr(target, '\\')) return native_error(env, "invalid private generation symlink");
    tree_walk walk; int parent = walk_parent(tree, path, &walk, &leaf);
    const char *error = "private generation symlink requires absent entry and held no-follow parents";
    struct stat created, end;
    if (parent < 0 || !walk_held(tree, &walk) || symlinkat(target, parent, leaf) < 0 ||
        fstatat(parent, leaf, &created, AT_SYMLINK_NOFOLLOW) < 0 || !S_ISLNK(created.st_mode) || created.st_uid != geteuid() ||
        created.st_nlink != 1 || created.st_dev != tree->identity.st_dev) goto done;
#ifdef __APPLE__
    /* Darwin applies umask to symlink permissions. Normalize only this exact
     * no-follow entry; never widen the process-global umask. */
    if (fchmodat(parent, leaf, 0777, AT_SYMLINK_NOFOLLOW) < 0) goto done;
#endif
    if (!sync_directory(parent) ||
        fstatat(parent, leaf, &end, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&created, &end) ||
        !S_ISLNK(end.st_mode) || (end.st_mode & 07777) != 0777 || end.st_nlink != 1 || !walk_held(tree, &walk)) goto done;
    error = NULL;
done:
    close_walk(&walk);
    if (error) return native_error(env, error);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static int stable_content(const struct stat *before, const struct stat *after) {
    if (!same_inode(before, after) || before->st_mode != after->st_mode || before->st_uid != after->st_uid ||
        before->st_nlink != after->st_nlink || before->st_size != after->st_size) return 0;
#ifdef __APPLE__
    return before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec && before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
        before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec && before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return before->st_mtim.tv_sec == after->st_mtim.tv_sec && before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
        before->st_ctim.tv_sec == after->st_ctim.tv_sec && before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}
static int string_property(napi_env env, napi_value result, const char *key, const char *value) {
    napi_value member;
    return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &member) == napi_ok &&
        napi_set_named_property(env, result, key, member) == napi_ok;
}
static int number_property(napi_env env, napi_value result, const char *key, double value) {
    napi_value member;
    return napi_create_double(env, value, &member) == napi_ok && napi_set_named_property(env, result, key, member) == napi_ok;
}
/* Rewalk every directory by held descriptor, fsync files and deepest-first
 * directories, then prove every named ancestor still resolves to that inode. */
typedef struct { int fd; DIR *directory; struct stat before; char *path; char *name; } scan_frame;
static int open_scan_frame(scan_frame *frame, int fd, const char *path, const char *name) {
    frame->fd = fd;
    frame->path = strdup(path); frame->name = name ? strdup(name) : NULL;
    if (!frame->path || (name && !frame->name) || fstat(fd, &frame->before) < 0) goto failed;
    int scan_fd = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan_fd < 0) goto failed;
    frame->directory = fdopendir(scan_fd);
    if (!frame->directory) { close(scan_fd); goto failed; }
    return 1;
failed:
    free(frame->path); free(frame->name); frame->path = frame->name = NULL;
    return 0;
}
static void close_scan_frame(scan_frame *frame, int close_fd) {
    if (frame->directory) closedir(frame->directory);
    if (close_fd) close(frame->fd);
    free(frame->path); free(frame->name);
    memset(frame, 0, sizeof(*frame));
}
struct generation_cursor {
    generation_tree *tree;
    napi_ref tree_ref;
    scan_frame *frames;
    size_t depth, total;
    unsigned int count;
    int complete, failed, closed;
    generation_stream *active_file;
    generation_cursor *next;
};
struct generation_stream {
    generation_tree *tree;
    generation_cursor *cursor;
    napi_ref tree_ref, cursor_ref;
    tree_walk *walk;
    char *leaf;
    struct stat before;
    int fd, writing, complete;
    size_t offset, byte_count;
    generation_stream *next;
};
static const napi_type_tag cursor_tag = {0xa60ae5f30d39d96eULL, 0xa998f2ef4779fd9aULL};
static const napi_type_tag stream_tag = {0xf9f6ca627d87c0b8ULL, 0x96f42b3d97f9311eULL};
static void close_cursor(generation_cursor *cursor) {
    if (cursor->active_file) {
        if (cursor->active_file->fd >= 0) close(cursor->active_file->fd);
        cursor->active_file->fd = -1;
        cursor->active_file->cursor = NULL;
        cursor->active_file = NULL;
        cursor->failed = 1;
    }
    while (cursor->depth) { close_scan_frame(&cursor->frames[cursor->depth - 1], cursor->depth > 1); cursor->depth--; }
    free(cursor->frames); cursor->frames = NULL;
    cursor->closed = 1;
}
static void close_stream(generation_stream *stream) {
    if (stream->fd >= 0) close(stream->fd);
    stream->fd = -1;
    if (stream->walk) { close_walk(stream->walk); free(stream->walk); stream->walk = NULL; }
    if (stream->cursor && stream->cursor->active_file == stream) {
        if (!stream->complete) stream->cursor->failed = 1;
        stream->cursor->active_file = NULL;
    }
    stream->cursor = NULL;
}
static void close_tree_streams(generation_tree *tree) {
    for (generation_stream *stream = tree->streams; stream; stream = stream->next) close_stream(stream);
    for (generation_cursor *cursor = tree->cursors; cursor; cursor = cursor->next) close_cursor(cursor);
}
static int cursor_held(generation_cursor *cursor) {
    if (cursor->closed || cursor->failed || !tree_held(cursor->tree)) return 0;
    for (size_t i = 0; i < cursor->depth; i++) {
        scan_frame *frame = &cursor->frames[i];
        struct stat opened, named;
        if (fstat(frame->fd, &opened) < 0 || !stable_content(&frame->before, &opened)) return 0;
        if (i && (fstatat(cursor->frames[i - 1].fd, frame->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
                  !same_inode(&opened, &named))) return 0;
    }
    return 1;
}
static generation_cursor *unwrap_cursor(napi_env env, napi_callback_info info) {
    napi_value receiver; generation_cursor *cursor = NULL; bool tagged = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok ||
        napi_check_object_type_tag(env, receiver, &cursor_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, receiver, (void **)&cursor) != napi_ok || !cursor) {
        native_error(env, "invalid private generation snapshot cursor"); return NULL;
    }
    return cursor;
}
static generation_stream *unwrap_stream(napi_env env, napi_callback_info info) {
    napi_value receiver; generation_stream *stream = NULL; bool tagged = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok ||
        napi_check_object_type_tag(env, receiver, &stream_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, receiver, (void **)&stream) != napi_ok || !stream) {
        native_error(env, "invalid native-held private generation file"); return NULL;
    }
    return stream;
}
static int stream_held(generation_stream *stream) {
    if (stream->fd < 0 || !tree_held(stream->tree) || (stream->cursor && !cursor_held(stream->cursor))) return 0;
    struct stat opened, named;
    int parent = stream->cursor ? stream->cursor->frames[stream->cursor->depth - 1].fd :
        (stream->walk->count ? stream->walk->fds[stream->walk->count - 1] : stream->tree->fd);
    if ((!stream->cursor && !walk_held(stream->tree, stream->walk)) || fstat(stream->fd, &opened) < 0 ||
        fstatat(parent, stream->leaf, &named, AT_SYMLINK_NOFOLLOW) < 0 || !same_inode(&opened, &named) ||
        !content_file(&opened, stream->tree->identity.st_dev, stream->before.st_mode & 07777)) return 0;
    return stream->writing ? same_inode(&opened, &stream->before) : stable_content(&opened, &stream->before);
}
static napi_value stream_assert(napi_env env, napi_callback_info info) {
    generation_stream *stream = unwrap_stream(env, info);
    if (!stream) return NULL;
    if (!stream_held(stream)) return native_error(env, "private generation file/ancestor changed or closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value stream_close(napi_env env, napi_callback_info info) {
    generation_stream *stream = unwrap_stream(env, info);
    if (!stream) return NULL;
    close_stream(stream);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value stream_read(napi_env env, napi_callback_info info) {
    generation_stream *stream = unwrap_stream(env, info);
    if (!stream) return NULL;
    if (stream->writing || !stream_held(stream)) return native_error(env, "private generation read requires the exact held snapshot file");
    napi_value value;
    if (stream->offset == stream->byte_count) {
        if (!sync_directory(stream->fd) || !stream_held(stream)) return native_error(env, "private generation snapshot file fsync/reobservation failed");
        stream->complete = 1;
        return napi_get_null(env, &value) == napi_ok ? value : NULL;
    }
    size_t length = stream->byte_count - stream->offset;
    if (length > 65536) length = 65536;
    void *bytes;
    if (napi_create_buffer(env, length, &bytes, &value) != napi_ok) return NULL;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(stream->fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "private generation snapshot file changed or became unreadable");
        offset += (size_t)count;
    }
    stream->offset += length;
    if (!stream_held(stream)) return native_error(env, "private generation snapshot file changed during bounded read");
    return value;
}
static napi_value stream_write(napi_env env, napi_callback_info info) {
    generation_stream *stream = unwrap_stream(env, info);
    if (!stream) return NULL;
    size_t argc = 1, length; napi_value argv[1]; bool buffer = false; void *bytes;
    if (!stream->writing || stream->complete || !stream_held(stream) ||
        napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_is_buffer(env, argv[0], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, argv[0], &bytes, &length) != napi_ok || length > 65536 ||
        length > stream->byte_count - stream->offset) return native_error(env, "private generation write requires bounded exact-size held-file chunks");
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(stream->fd, (char *)bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "private generation chunk write failed");
        offset += (size_t)count;
    }
    stream->offset += length;
    if (!stream_held(stream)) return native_error(env, "private generation writer ancestor or file identity changed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value stream_finish(napi_env env, napi_callback_info info) {
    generation_stream *stream = unwrap_stream(env, info);
    if (!stream) return NULL;
    struct stat observed;
    if (!stream->writing || stream->complete || !stream_held(stream) || stream->offset != stream->byte_count ||
        !sync_directory(stream->fd) || fstat(stream->fd, &observed) < 0 || observed.st_size < 0 ||
        (size_t)observed.st_size != stream->byte_count || !stream_held(stream)) {
        return native_error(env, "private generation writer must completely consume verified bytes before file fsync");
    }
    int parent = stream->walk->count ? stream->walk->fds[stream->walk->count - 1] : stream->tree->fd;
    if (!sync_directory(parent) || !stream_held(stream)) return native_error(env, "private generation writer parent fsync or reobservation failed");
    stream->complete = 1;
    close_stream(stream);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static void finalize_stream(napi_env env, void *data, void *hint) {
    (void)hint;
    generation_stream *stream = data;
    generation_tree *tree = stream->tree;
    napi_ref tree_ref = stream->tree_ref, cursor_ref = stream->cursor_ref;
    close_stream(stream);
    generation_stream **link = &stream->tree->streams;
    while (*link && *link != stream) link = &(*link)->next;
    if (*link) *link = stream->next;
    free(stream->leaf); free(stream);
    free_tree_if_done(env, tree);
    if (cursor_ref) napi_delete_reference(env, cursor_ref);
    napi_delete_reference(env, tree_ref);
}
static napi_value mint_stream(napi_env env, generation_stream *stream, napi_value tree_object, napi_value cursor_object) {
    napi_value result;
    const napi_property_descriptor read_methods[] = {
        {"readChunk", NULL, stream_read, NULL, NULL, NULL, napi_default, NULL},
        {"assertHeld", NULL, stream_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, stream_close, NULL, NULL, NULL, napi_default, NULL}
    };
    const napi_property_descriptor write_methods[] = {
        {"writeChunk", NULL, stream_write, NULL, NULL, NULL, napi_default, NULL},
        {"finish", NULL, stream_finish, NULL, NULL, NULL, napi_default, NULL},
        {"assertHeld", NULL, stream_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, stream_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_reference(env, tree_object, 1, &stream->tree_ref) != napi_ok ||
        (cursor_object && napi_create_reference(env, cursor_object, 1, &stream->cursor_ref) != napi_ok) ||
        napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, stream->writing ? sizeof(write_methods) / sizeof(write_methods[0]) :
            sizeof(read_methods) / sizeof(read_methods[0]), stream->writing ? write_methods : read_methods) != napi_ok ||
        napi_type_tag_object(env, result, &stream_tag) != napi_ok || napi_wrap(env, result, stream, finalize_stream, NULL, NULL) != napi_ok) {
        close_stream(stream);
        if (stream->tree_ref) napi_delete_reference(env, stream->tree_ref);
        if (stream->cursor_ref) napi_delete_reference(env, stream->cursor_ref);
        free(stream->leaf); free(stream);
        return native_error(env, "cannot mint native-held private generation file");
    }
    stream->next = stream->tree->streams; stream->tree->streams = stream;
    napi_object_freeze(env, result);
    return result;
}
static napi_value tree_open_writer(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    size_t argc = 3; napi_value argv[3], receiver; char path[4097], *leaf; uint32_t mode; double length;
    if (tree->retained || !tree_held(tree) || napi_get_cb_info(env, info, &argc, argv, &receiver, NULL) != napi_ok || argc != 3 ||
        !tree_path(env, argv[0], path) || napi_get_value_uint32(env, argv[1], &mode) != napi_ok ||
        (metadata_path(path) ? mode != 0600 && mode != 0400 : mode != 0644 && mode != 0755) ||
        napi_get_value_double(env, argv[2], &length) != napi_ok || !(length >= 0 && length <= GENERATION_MAX_BYTES) ||
        length != (size_t)length) return native_error(env, "invalid private generation streaming writer path/mode/size");
    for (generation_cursor *cursor = tree->cursors; cursor; cursor = cursor->next) {
        if (!cursor->closed) return native_error(env, "private generation cannot write while a snapshot cursor is held");
    }
    generation_stream *stream = calloc(1, sizeof(*stream));
    if (!stream) return native_error(env, "cannot allocate private generation writer");
    stream->tree = tree; stream->writing = 1; stream->fd = -1; stream->byte_count = (size_t)length;
    stream->walk = malloc(sizeof(*stream->walk));
    int parent = stream->walk ? walk_parent(tree, path, stream->walk, &leaf) : -1;
    if (parent < 0) goto failed;
    stream->leaf = strdup(leaf);
    if (!stream->leaf || !walk_held(tree, stream->walk)) goto failed;
    stream->fd = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (stream->fd < 0 || fchmod(stream->fd, mode) < 0 || fstat(stream->fd, &stream->before) < 0 ||
        !stream_held(stream)) goto failed;
    return mint_stream(env, stream, receiver, NULL);
failed:
    close_stream(stream); free(stream->leaf); free(stream);
    return native_error(env, "private generation writer requires absent file and held exact no-follow ancestors");
}
static napi_value cursor_close(napi_env env, napi_callback_info info) {
    generation_cursor *cursor = unwrap_cursor(env, info);
    if (!cursor) return NULL;
    close_cursor(cursor);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value cursor_complete(napi_env env, napi_callback_info info) {
    generation_cursor *cursor = unwrap_cursor(env, info);
    if (!cursor) return NULL;
    if (!cursor->complete || !cursor_held(cursor)) return native_error(env, "private generation snapshot is not complete or changed/closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value cursor_next(napi_env env, napi_callback_info info) {
    generation_cursor *cursor = unwrap_cursor(env, info);
    if (!cursor) return NULL;
    napi_value receiver, entry, null;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok || !cursor_held(cursor) || cursor->active_file) {
        return native_error(env, "private generation snapshot requires a held cursor and fully consumed closed preceding file");
    }
    napi_get_null(env, &null);
    if (cursor->complete) return null;
    while (cursor->depth) {
        scan_frame *frame = &cursor->frames[cursor->depth - 1];
        errno = 0;
        struct dirent *item = readdir(frame->directory);
        if (!item) {
            struct stat after, named;
            if (errno || !sync_directory(frame->fd) || fstat(frame->fd, &after) < 0 ||
                !stable_content(&frame->before, &after) || !cursor_held(cursor) ||
                (cursor->depth > 1 && (fstatat(cursor->frames[cursor->depth - 2].fd, frame->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
                    !same_inode(&after, &named)))) goto failed;
            close_scan_frame(frame, cursor->depth > 1); cursor->depth--; continue;
        }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (strchr(item->d_name, '\\') || !utf8_valid((unsigned char *)item->d_name)) goto failed;
        char path[4097];
        int length = snprintf(path, sizeof(path), "%s%s%s", frame->path, *frame->path ? "/" : "", item->d_name);
        struct stat named, opened;
        if (!metadata_path(path) && cursor->count++ >= 100000) goto failed;
        if (length < 1 || length > 4096 || fstatat(frame->fd, item->d_name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            named.st_uid != geteuid() || named.st_dev != cursor->tree->identity.st_dev || napi_create_object(env, &entry) != napi_ok ||
            !string_property(env, entry, "path", path) || !number_property(env, entry, "mode", named.st_mode & 07777)) goto failed;
        if (S_ISDIR(named.st_mode)) {
            if (!entry_directory(&named, cursor->tree->identity.st_dev, metadata_path(path)) ||
                (metadata_path(path) && cursor->tree->git_fd < 0) || cursor->depth >= 2049 ||
                !string_property(env, entry, "kind", "directory")) goto failed;
            int child = openat(frame->fd, item->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) goto failed;
            if (fstat(child, &opened) < 0 || !same_inode(&opened, &named) ||
                !open_scan_frame(&cursor->frames[cursor->depth], child, path, item->d_name)) { close(child); goto failed; }
            cursor->depth++;
        } else if (S_ISREG(named.st_mode)) {
            mode_t mode = named.st_mode & 07777;
            if ((metadata_path(path) ? mode != 0600 && mode != 0400 : mode != 0644 && mode != 0755) ||
                !content_file(&named, cursor->tree->identity.st_dev, mode) || named.st_size < 0 ||
                (unsigned long long)named.st_size > GENERATION_MAX_BYTES - cursor->total) goto failed;
            generation_stream *stream = calloc(1, sizeof(*stream));
            if (!stream) goto failed;
            stream->tree = cursor->tree; stream->cursor = cursor; stream->fd = -1;
            stream->leaf = strdup(item->d_name); stream->byte_count = (size_t)named.st_size; stream->before = named;
            stream->fd = openat(frame->fd, item->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            if (!stream->leaf || !stream_held(stream)) { close_stream(stream); free(stream->leaf); free(stream); goto failed; }
            napi_value tree_object, file;
            if (napi_get_reference_value(env, cursor->tree_ref, &tree_object) != napi_ok) { close_stream(stream); free(stream->leaf); free(stream); goto failed; }
            file = mint_stream(env, stream, tree_object, receiver);
            if (!file) goto failed;
            cursor->active_file = stream; cursor->total += stream->byte_count;
            if (!string_property(env, entry, "kind", "file") || !number_property(env, entry, "byteCount", (double)stream->byte_count) ||
                napi_set_named_property(env, entry, "file", file) != napi_ok) goto failed;
        } else if (S_ISLNK(named.st_mode)) {
            char target[4097]; ssize_t size = readlinkat(frame->fd, item->d_name, target, sizeof(target));
            if (metadata_path(path) || size <= 0 || size > 4096 || (named.st_mode & 07777) != 0777 || named.st_nlink != 1 ||
                (size_t)size > GENERATION_MAX_BYTES - cursor->total) goto failed;
            target[size] = 0;
            if (!utf8_valid((unsigned char *)target) || fstatat(frame->fd, item->d_name, &opened, AT_SYMLINK_NOFOLLOW) < 0 ||
                !stable_content(&named, &opened) || !string_property(env, entry, "kind", "symlink") || !string_property(env, entry, "target", target)) goto failed;
            cursor->total += (size_t)size;
        } else goto failed;
        napi_object_freeze(env, entry);
        return entry;
    }
    for (int i = 4; i >= 0; i--) {
        if (cursor->tree->parents[i] >= 0 && !sync_directory(cursor->tree->parents[i])) goto failed;
    }
    if (!sync_directory(cursor->tree->lock->root_fd) || !cursor_held(cursor)) goto failed;
    cursor->complete = 1;
    return null;
failed:
    cursor->failed = 1;
    close_cursor(cursor);
    return native_error(env, "private generation snapshot rejected changed, linked, special or unreadable entries");
}
static void finalize_cursor(napi_env env, void *data, void *hint) {
    (void)hint;
    generation_cursor *cursor = data;
    generation_tree *tree = cursor->tree;
    napi_ref tree_ref = cursor->tree_ref;
    close_cursor(cursor);
    generation_cursor **link = &cursor->tree->cursors;
    while (*link && *link != cursor) link = &(*link)->next;
    if (*link) *link = cursor->next;
    free(cursor);
    free_tree_if_done(env, tree);
    napi_delete_reference(env, tree_ref);
}
static napi_value tree_open_snapshot(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    if (!tree_held(tree)) return native_error(env, "private generation descriptor or StateOwner changed/closed");
    for (generation_stream *stream = tree->streams; stream; stream = stream->next) {
        if (stream->writing && stream->fd >= 0) return native_error(env, "private generation snapshot requires all native writer handles closed");
    }
    generation_cursor *cursor = calloc(1, sizeof(*cursor));
    if (!cursor) return native_error(env, "cannot allocate private generation snapshot");
    cursor->tree = tree; cursor->frames = calloc(2049, sizeof(*cursor->frames));
    napi_value receiver, result;
    const napi_property_descriptor methods[] = {
        {"next", NULL, cursor_next, NULL, NULL, NULL, napi_default, NULL},
        {"assertComplete", NULL, cursor_complete, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, cursor_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (!cursor->frames || !open_scan_frame(&cursor->frames[0], tree->fd, "", NULL)) goto failed;
    cursor->depth = 1;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok ||
        napi_create_reference(env, receiver, 1, &cursor->tree_ref) != napi_ok || napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &cursor_tag) != napi_ok || napi_wrap(env, result, cursor, finalize_cursor, NULL, NULL) != napi_ok) goto failed;
    cursor->next = tree->cursors; tree->cursors = cursor;
    napi_object_freeze(env, result);
    return result;
failed:
    close_cursor(cursor);
    if (cursor->tree_ref) napi_delete_reference(env, cursor->tree_ref);
    free(cursor);
    return native_error(env, "cannot mint held private generation snapshot");
}
static generation_borrow *unwrap_borrow(napi_env env, napi_callback_info info) {
    napi_value receiver; generation_borrow *borrow = NULL; bool tagged = false;
    if (napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok ||
        napi_check_object_type_tag(env, receiver, &borrow_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, receiver, (void **)&borrow) != napi_ok || !borrow) {
        native_error(env, "invalid borrowed private generation handle"); return NULL;
    }
    return borrow;
}
static napi_value borrow_assert(napi_env env, napi_callback_info info) {
    generation_borrow *borrow = unwrap_borrow(env, info);
    if (!borrow) return NULL;
    struct stat info_stat;
    if (borrow->fd < 0 || !tree_held(borrow->tree) || fstat(borrow->fd, &info_stat) < 0 ||
        !same_inode(&info_stat, &borrow->tree->identity) || !private_directory(&info_stat)) {
        return native_error(env, "borrowed private generation descriptor or StateOwner changed or closed");
    }
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value borrow_close(napi_env env, napi_callback_info info) {
    generation_borrow *borrow = unwrap_borrow(env, info);
    if (!borrow) return NULL;
    if (borrow->fd >= 0) close(borrow->fd);
    borrow->fd = -1;
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value borrow_quota(napi_env env, napi_callback_info info) {
    generation_borrow *borrow = unwrap_borrow(env, info);
    if (!borrow) return NULL;
#ifdef __linux__
    size_t argc = 1; napi_value argv[1], result; double maximum;
    struct stat identity; struct statfs before, after;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_double(env, argv[0], &maximum) != napi_ok || !(maximum >= 1 && maximum <= 9007199254740991.0) ||
        maximum != (unsigned long long)maximum || borrow->fd < 0 || !tree_held(borrow->tree) ||
        fstat(borrow->fd, &identity) < 0 || !same_inode(&identity, &borrow->tree->identity) ||
        fstatfs(borrow->fd, &before) < 0 || before.f_blocks == 0 || before.f_frsize <= 0 ||
        (unsigned long long)before.f_blocks > 9007199254740991ULL / (unsigned long long)before.f_frsize) {
        return native_error(env, "private generation quota requires a held Linux filesystem and exact positive byte ceiling");
    }
    unsigned long long capacity = (unsigned long long)before.f_blocks * (unsigned long long)before.f_frsize;
    if (capacity > (unsigned long long)maximum) return native_error(env, "private generation filesystem capacity exceeds the frozen generation quota");
    if (fstatfs(borrow->fd, &after) < 0 || before.f_type != after.f_type || before.f_blocks != after.f_blocks ||
        before.f_frsize != after.f_frsize || memcmp(&before.f_fsid, &after.f_fsid, sizeof(before.f_fsid)) != 0 ||
        !tree_held(borrow->tree) || fstat(borrow->fd, &identity) < 0 || !same_inode(&identity, &borrow->tree->identity)) {
        return native_error(env, "private generation filesystem identity/capacity changed during quota observation");
    }
    char type[32]; snprintf(type, sizeof(type), "%llu", (unsigned long long)before.f_type);
    if (napi_create_object(env, &result) != napi_ok || !number_property(env, result, "totalBytes", (double)capacity) ||
        !string_property(env, result, "filesystemType", type) || !identity_member(env, result, "identity", &identity)) return NULL;
    napi_object_freeze(env, result);
    return result;
#else
    return native_error(env, "private generation hard quota observation requires a qualified Linux filesystem");
#endif
}
static void finalize_borrow(napi_env env, void *data, void *hint) {
    (void)hint;
    generation_borrow *borrow = data;
    generation_tree *tree = borrow->tree;
    napi_ref tree_ref = borrow->tree_ref;
    if (borrow->fd >= 0) close(borrow->fd);
    generation_borrow **link = &borrow->tree->borrows;
    while (*link && *link != borrow) link = &(*link)->next;
    if (*link) *link = borrow->next;
    free(borrow);
    free_tree_if_done(env, tree);
    napi_delete_reference(env, tree_ref);
}
static napi_value tree_borrow(napi_env env, napi_callback_info info) {
    generation_tree *tree = unwrap_tree(env, info);
    if (!tree) return NULL;
    if (tree->retained || !tree_held(tree)) return native_error(env, "retained observation tree cannot transfer execution authority or is closed");
    generation_borrow *borrow = calloc(1, sizeof(*borrow));
    if (!borrow) return native_error(env, "cannot allocate generation borrow");
    borrow->tree = tree;
    borrow->fd = openat(tree->fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    napi_value result, receiver;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, borrow_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, borrow_close, NULL, NULL, NULL, napi_default, NULL}
        ,{"assertQuota", NULL, borrow_quota, NULL, NULL, NULL, napi_default, NULL}
    };
    struct stat opened;
    if (borrow->fd < 0 || fstat(borrow->fd, &opened) < 0 || !same_inode(&opened, &tree->identity) || !tree_held(tree) ||
        napi_get_cb_info(env, info, NULL, NULL, &receiver, NULL) != napi_ok || napi_create_reference(env, receiver, 1, &borrow->tree_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || !number_property(env, result, "fd", borrow->fd) ||
        !identity_member(env, result, "identity", &opened) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &borrow_tag) != napi_ok || napi_wrap(env, result, borrow, finalize_borrow, NULL, NULL) != napi_ok) {
        if (borrow->fd >= 0) close(borrow->fd);
        if (borrow->tree_ref) napi_delete_reference(env, borrow->tree_ref);
        free(borrow); return native_error(env, "cannot mint held generation borrow");
    }
    borrow->next = tree->borrows; tree->borrows = borrow;
    napi_object_freeze(env, result);
    return result;
}
static napi_value generation_tree_open(napi_env env, napi_callback_info info, int create) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    size_t argc = 5; napi_value argv[5], receiver, result;
    generation_tree *tree = calloc(1, sizeof(*tree));
    if (!tree) return native_error(env, "cannot allocate private generation tree");
    tree->lock = lock; tree->fd = tree->git_fd = -1;
    for (int i = 0; i < 5; i++) tree->parents[i] = -1;
    const char *error = "invalid private generation ids or closed StateOwner";
    if (!lock_is_held(lock) || napi_get_cb_info(env, info, &argc, argv, &receiver, NULL) != napi_ok ||
        (argc != 2 && (create || argc != 5)) ||
        !read_component(env, argv[0], tree->run, sizeof(tree->run), 0) ||
        !read_component(env, argv[1], tree->generation, sizeof(tree->generation), 43)) goto failed;
    struct stat expected = {0};
    if (argc == 5) {
        unsigned long long device, file;
        if (!read_component(env, argv[2], tree->target, sizeof(tree->target), 43) ||
            !read_unsigned_id(env, argv[3], &device) || !read_unsigned_id(env, argv[4], &file)) goto failed;
        expected.st_dev = (dev_t)device; expected.st_ino = (ino_t)file;
#ifdef __APPLE__
        if ((unsigned long long)(uint32_t)expected.st_dev != device) goto failed;
#else
        if ((unsigned long long)expected.st_dev != device) goto failed;
#endif
        if ((unsigned long long)expected.st_ino != file) goto failed;
        tree->retained = 1;
    }
    const char *names[] = {"runs", tree->run, "generations", "quarantine", "workspace-generations"};
    error = "private generation requires exact same-device no-follow private parents";
    for (int i = 0; i < 3; i++) {
        tree->parents[i] = open_private_child(i == 0 ? lock->root_fd : tree->parents[i - 1], names[i], create,
                                             &tree->parent_ids[i], lock->root.st_dev);
        if (tree->parents[i] < 0) goto failed;
    }
    if (tree->retained) {
        for (int i = 3; i < 5; i++) {
            const int parent = i == 3 ? lock->root_fd : tree->parents[3];
            struct stat named;
            if (fstatat(parent, names[i], &named, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno == ENOENT) break;
                goto failed;
            }
            tree->parents[i] = open_private_child(parent, names[i], 0, &tree->parent_ids[i], lock->root.st_dev);
            if (tree->parents[i] < 0) goto failed;
        }
        error = "retained private generation requires exactly one original or exact target; refusing conflict or identity drift";
        const int source = tree_directory_at(tree->parents[2], tree->generation, &expected);
        const int target = tree->parents[4] < 0 ? 0 : tree_directory_at(tree->parents[4], tree->target, &expected);
        if (source < 0 || target < 0 || source + target != 1) goto failed;
        tree->archived = target;
    }
    error = "private generation creation requires an absent derived locator; no overwrite or adoption";
    if (create && mkdirat(tree->parents[2], tree->generation, 0700) < 0) goto failed;
    tree->fd = openat(tree->parents[tree->archived ? 4 : 2], tree->archived ? tree->target : tree->generation,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (tree->fd < 0 || fstat(tree->fd, &tree->identity) < 0 || !private_directory(&tree->identity) ||
        tree->identity.st_dev != lock->root.st_dev || (tree->retained && !same_inode(&tree->identity, &expected)) ||
        !tree_held(tree)) goto failed;
    if (!create) {
        struct stat named;
        if (fstatat(tree->fd, ".git", &named, AT_SYMLINK_NOFOLLOW) == 0) {
            tree->git_fd = openat(tree->fd, ".git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (tree->git_fd < 0 || fstat(tree->git_fd, &tree->git_identity) < 0 || !private_directory(&tree->git_identity) ||
                tree->git_identity.st_dev != tree->identity.st_dev || !same_inode(&named, &tree->git_identity) || !tree_held(tree)) goto failed;
        } else if (errno != ENOENT) goto failed;
    }
    error = "private generation ancestor fsync or identity check failed";
    if (!sync_directory(tree->fd) || !sync_directory(lock->root_fd)) goto failed;
    for (int i = 0; i < 5; i++) if (tree->parents[i] >= 0 && !sync_directory(tree->parents[i])) goto failed;
    if (!tree_held(tree)) goto failed;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, tree_assert, NULL, NULL, NULL, napi_default, NULL},
        {"mkdir", NULL, tree_mkdir, NULL, NULL, NULL, napi_default, NULL},
        {"symlink", NULL, tree_symlink, NULL, NULL, NULL, napi_default, NULL},
        {"openSnapshot", NULL, tree_open_snapshot, NULL, NULL, NULL, napi_default, NULL},
        {"openFileWriter", NULL, tree_open_writer, NULL, NULL, NULL, napi_default, NULL},
        {"borrow", NULL, tree_borrow, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, tree_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "identity", &tree->identity) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_create_reference(env, receiver, 1, &tree->lock_ref) != napi_ok ||
        napi_type_tag_object(env, result, &tree_tag) != napi_ok || napi_wrap(env, result, tree, finalize_tree, NULL, NULL) != napi_ok) goto failed;
    tree->next = lock->trees; lock->trees = tree;
    napi_object_freeze(env, result);
    return result;
failed:
    close_tree(tree);
    if (tree->lock_ref) napi_delete_reference(env, tree->lock_ref);
    free(tree);
    return native_error(env, error);
}
static napi_value create_generation_tree(napi_env env, napi_callback_info info) { return generation_tree_open(env, info, 1); }
static napi_value open_generation_tree(napi_env env, napi_callback_info info) { return generation_tree_open(env, info, 0); }
