/* Read-only, metadata-first source traversal. Unlike a private generation,
 * source regular files may be hardlinks; capture erases their link identity.
 * A returned entry is the only capability that can open its exact content. */
#include <strings.h>
typedef struct source_entry source_entry;
typedef struct source_reader source_reader;
struct source_cursor {
    source_root *root;
    source_entry *parent;
    napi_ref root_ref, parent_ref;
    DIR *directory;
    int fd, closed, complete, finalized;
    struct stat before;
    char *path;
    source_entry *entries;
    source_cursor *next;
};
struct source_entry {
    source_cursor *cursor, *child;
    source_reader *reader;
    napi_ref cursor_ref;
    struct stat before;
    char *name, *path;
    int closed, finalized, opened, link_read;
    source_entry *next;
};
struct source_reader {
    source_entry *entry;
    napi_ref entry_ref;
    int fd, complete;
    off_t offset;
};
static const napi_type_tag source_cursor_tag = {0xe61d6a99a824e51dULL, 0x9b70d08bad17d268ULL};
static const napi_type_tag source_entry_tag = {0xa82cb9f7882ef489ULL, 0x8a687e43855ea784ULL};
static const napi_type_tag source_reader_tag = {0x4f3a21abb3504b3aULL, 0x939bd238c710ac36ULL};
static void source_free_entry_if_done(napi_env env, source_entry *entry);
static void source_free_cursor_if_done(napi_env env, source_cursor *cursor);
static int source_close_cursor(source_cursor *cursor);
static napi_value source_entry_directory(napi_env env, napi_callback_info info);

static int source_metadata_same(const struct stat *left, const struct stat *right) {
    if (!same_inode(left, right) || left->st_uid != right->st_uid || left->st_gid != right->st_gid ||
        left->st_mode != right->st_mode || left->st_nlink != right->st_nlink || left->st_size != right->st_size) return 0;
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
        left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}
static napi_value source_retirement_failure(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "source descriptor retirement failed"); return NULL;
}
static int source_close_reader(source_reader *reader) {
    int fd = reader->fd; reader->fd = -1;
    if (fd >= 0 && close(fd) < 0) reader->entry->cursor->root->retirement_error = errno;
    return reader->entry->cursor->root->retirement_error;
}
static int source_close_entry(source_entry *entry) {
    entry->closed = 1;
    if (entry->reader) source_close_reader(entry->reader);
    if (entry->child) source_close_cursor(entry->child);
    return entry->cursor->root->retirement_error;
}
static int source_close_cursor(source_cursor *cursor) {
    cursor->closed = 1;
    for (source_entry *entry = cursor->entries; entry; entry = entry->next) source_close_entry(entry);
    DIR *directory = cursor->directory; cursor->directory = NULL; cursor->fd = -1;
    if (directory && closedir(directory) < 0) cursor->root->retirement_error = errno;
    return cursor->root->retirement_error;
}
static int source_close_cursors(source_root *root) {
    for (source_cursor *cursor = root->cursors; cursor; cursor = cursor->next) source_close_cursor(cursor);
    return root->retirement_error;
}
static int source_entry_held(source_entry *entry);
static int source_cursor_held(source_cursor *cursor) {
    if (cursor->closed || cursor->fd < 0 || !source_held(cursor->root)) return 0;
    /* Walk raw parents iteratively; deep sources do not consume the C stack. */
    for (source_cursor *current = cursor; current;) {
        struct stat observed, named;
        if (current->closed || current->fd < 0 || fstat(current->fd, &observed) < 0 ||
            !source_metadata_same(&current->before, &observed)) return 0;
        source_entry *parent = current->parent;
        if (!parent) return same_inode(&observed, &cursor->root->ids[cursor->root->count - 1]);
        if (parent->closed || parent->cursor->closed || fstatat(parent->cursor->fd, parent->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !source_metadata_same(&parent->before, &named) || !same_inode(&named, &observed)) return 0;
        current = parent->cursor;
    }
    return 0;
}
static int source_entry_held(source_entry *entry) {
    struct stat named;
    return !entry->closed && source_cursor_held(entry->cursor) &&
        fstatat(entry->cursor->fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&entry->before, &named);
}
/* A held Trust record needs unchanged named ancestors, not a snapshot of
 * unrelated home-directory contents. Only directories relax content metadata;
 * the leaf record still checks its full size/time/mode/link identity. */
static int source_path_metadata_same(const struct stat *before, const struct stat *observed) {
    if (!S_ISDIR(before->st_mode)) return source_metadata_same(before, observed);
    return S_ISDIR(observed->st_mode) && same_inode(before, observed) && before->st_uid == observed->st_uid &&
        before->st_gid == observed->st_gid && before->st_mode == observed->st_mode;
}
static int source_cursor_path_held(source_cursor *cursor) {
    if (!source_held(cursor->root)) return 0;
    for (source_cursor *current = cursor; current;) {
        struct stat observed, named;
        if (current->closed || current->fd < 0 || fstat(current->fd, &observed) < 0 ||
            !source_path_metadata_same(&current->before, &observed)) return 0;
        source_entry *parent = current->parent;
        if (!parent) return same_inode(&observed, &cursor->root->ids[cursor->root->count - 1]);
        if (parent->closed || parent->cursor->closed ||
            fstatat(parent->cursor->fd, parent->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
            !source_path_metadata_same(&parent->before, &named) || !same_inode(&named, &observed)) return 0;
        current = parent->cursor;
    }
    return 0;
}
static int source_entry_same_device(source_entry *entry) {
    return entry->before.st_dev == entry->cursor->root->ids[entry->cursor->root->count - 1].st_dev;
}
static int source_reader_held(source_reader *reader) {
    struct stat observed;
    return reader->fd >= 0 && source_entry_held(reader->entry) && fstat(reader->fd, &observed) == 0 &&
        S_ISREG(observed.st_mode) && source_metadata_same(&reader->entry->before, &observed);
}
static void *source_unwrap(napi_env env, napi_callback_info info, const napi_type_tag *tag) {
    napi_value self; bool tagged = false; void *value = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, &value) != napi_ok || !value) native_error(env, "invalid opaque source handle");
    return value;
}
static void source_free_cursor_if_done(napi_env env, source_cursor *cursor) {
    if (!cursor->finalized || cursor->entries) return;
    source_root *root = cursor->root; source_entry *parent = cursor->parent;
    napi_ref root_ref = cursor->root_ref, parent_ref = cursor->parent_ref;
    source_cursor **link = &root->cursors;
    while (*link && *link != cursor) link = &(*link)->next;
    if (*link) *link = cursor->next;
    if (parent) parent->child = NULL;
    free(cursor->path); free(cursor);
    source_free_if_done(root);
    /* A finalized parent cascade can release the last root cursor. Do not
     * touch root after that cascade: the root may have been freed there. */
    if (parent) source_free_entry_if_done(env, parent);
    if (parent_ref) napi_delete_reference(env, parent_ref);
    napi_delete_reference(env, root_ref);
}
static void source_free_entry_if_done(napi_env env, source_entry *entry) {
    if (!entry->finalized || entry->reader || entry->child) return;
    source_cursor *cursor = entry->cursor; napi_ref cursor_ref = entry->cursor_ref;
    source_entry **link = &cursor->entries;
    while (*link && *link != entry) link = &(*link)->next;
    if (*link) *link = entry->next;
    free(entry->name); free(entry->path); free(entry);
    source_free_cursor_if_done(env, cursor);
    napi_delete_reference(env, cursor_ref);
}
static void source_finalize_cursor(napi_env env, void *data, void *hint) {
    (void)hint; source_cursor *cursor = data;
    source_close_cursor(cursor); cursor->finalized = 1; source_free_cursor_if_done(env, cursor);
}
static void source_finalize_entry(napi_env env, void *data, void *hint) {
    (void)hint; source_entry *entry = data;
    source_close_entry(entry); entry->finalized = 1; source_free_entry_if_done(env, entry);
}
static void source_finalize_reader(napi_env env, void *data, void *hint) {
    (void)hint; source_reader *reader = data; source_entry *entry = reader->entry; napi_ref ref = reader->entry_ref;
    source_close_reader(reader); entry->reader = NULL; free(reader);
    source_free_entry_if_done(env, entry); napi_delete_reference(env, ref);
}
static napi_value source_reader_assert(napi_env env, napi_callback_info info) {
    source_reader *reader = source_unwrap(env, info, &source_reader_tag);
    if (!reader) return NULL;
    if (!source_reader_held(reader)) return native_error(env, "source file identity changed or closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_reader_close(napi_env env, napi_callback_info info) {
    source_reader *reader = source_unwrap(env, info, &source_reader_tag);
    if (!reader) return NULL;
    if (source_close_reader(reader)) return source_retirement_failure(env);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_reader_chunk(napi_env env, napi_callback_info info) {
    source_reader *reader = source_unwrap(env, info, &source_reader_tag);
    if (!reader) return NULL;
    if (!source_reader_held(reader)) return native_error(env, "source file identity changed or closed");
    napi_value value;
    if (reader->offset == reader->entry->before.st_size) {
        reader->complete = 1; return napi_get_null(env, &value) == napi_ok ? value : NULL;
    }
    off_t remaining = reader->entry->before.st_size - reader->offset;
    size_t length = remaining < 65536 ? (size_t)remaining : 65536; void *bytes;
    if (napi_create_buffer(env, length, &bytes, &value) != napi_ok) return NULL;
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(reader->fd, (char *)bytes + done, length - done, reader->offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "source file changed or became unreadable");
        done += (size_t)count;
    }
    reader->offset += (off_t)length;
    if (!source_reader_held(reader)) return native_error(env, "source file changed during bounded read");
    return value;
}
static napi_value source_entry_assert(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag);
    if (!entry) return NULL;
    if (!source_entry_held(entry)) return native_error(env, "source entry identity changed or closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_entry_assert_path(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag); struct stat named;
    if (!entry) return NULL;
    if (entry->closed || !source_cursor_path_held(entry->cursor) ||
        fstatat(entry->cursor->fd, entry->name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !source_path_metadata_same(&entry->before, &named))
        return native_error(env, "source named path identity changed or closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_entry_close(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag);
    if (!entry) return NULL;
    if (source_close_entry(entry)) return source_retirement_failure(env);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_entry_file(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag); napi_value self;
    if (!entry) return NULL;
    if (!source_entry_held(entry) || !source_entry_same_device(entry) || !S_ISREG(entry->before.st_mode) || entry->opened || entry->before.st_size < 0 ||
        entry->before.st_size > (off_t)9007199254740991LL || napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok)
        return native_error(env, "source reader requires an unopened selected regular entry");
    source_reader *reader = calloc(1, sizeof(*reader));
    if (!reader) return native_error(env, "source reader allocation failed");
    reader->entry = entry; reader->fd = openat(entry->cursor->fd, entry->name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (!source_reader_held(reader)) goto failed;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"readChunk", NULL, source_reader_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertHeld", NULL, source_reader_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_reader_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_reference(env, self, 1, &reader->entry_ref) != napi_ok || napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, 3, methods) != napi_ok || napi_type_tag_object(env, result, &source_reader_tag) != napi_ok ||
        napi_wrap(env, result, reader, source_finalize_reader, NULL, NULL) != napi_ok) goto failed;
    entry->reader = reader; entry->opened = 1; napi_object_freeze(env, result); return result;
failed:
    source_close_reader(reader); if (reader->entry_ref) napi_delete_reference(env, reader->entry_ref); free(reader);
    return entry->cursor->root->retirement_error ? source_retirement_failure(env) : native_error(env, "source regular entry could not be opened exactly");
}
static napi_value source_entry_link(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag);
    if (!entry) return NULL;
    if (!source_entry_held(entry) || !source_entry_same_device(entry) || !S_ISLNK(entry->before.st_mode))
        return native_error(env, "source link requires a selected held same-device symlink entry");
    char bytes[4097]; ssize_t length = readlinkat(entry->cursor->fd, entry->name, bytes, sizeof(bytes));
    if (length <= 0 || length > 4096) return native_error(env, "source symlink target is not bounded UTF-8");
    bytes[length] = 0;
    if (!utf8_valid((unsigned char *)bytes) || strlen(bytes) != (size_t)length || !source_entry_held(entry))
        return native_error(env, "source symlink target changed or is not UTF-8");
    entry->link_read = 1;
    napi_value value; return napi_create_string_utf8(env, bytes, (size_t)length, &value) == napi_ok ? value : NULL;
}
static napi_value source_cursor_close(napi_env env, napi_callback_info info) {
    source_cursor *cursor = source_unwrap(env, info, &source_cursor_tag);
    if (!cursor) return NULL;
    if (source_close_cursor(cursor)) return source_retirement_failure(env);
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_cursor_complete(napi_env env, napi_callback_info info) {
    source_cursor *cursor = source_unwrap(env, info, &source_cursor_tag);
    if (!cursor) return NULL;
    if (!cursor->complete || !source_cursor_held(cursor)) return native_error(env, "source metadata enumeration is incomplete or changed/closed");
    napi_value value; return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value source_cursor_next(napi_env env, napi_callback_info info) {
    source_cursor *cursor = source_unwrap(env, info, &source_cursor_tag); napi_value self, result;
    if (!cursor) return NULL;
    if (!source_cursor_held(cursor) || napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok)
        return native_error(env, "source metadata cursor changed or closed");
    for (;;) {
        if (cursor->complete) return napi_get_null(env, &result) == napi_ok ? result : NULL;
        errno = 0; struct dirent *item = readdir(cursor->directory);
        if (!item) {
            if (errno || !source_cursor_held(cursor)) return native_error(env, "source metadata enumeration changed or failed");
            cursor->complete = 1; return napi_get_null(env, &result) == napi_ok ? result : NULL;
        }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (!strcasecmp(item->d_name, ".git")) {
            /* Only the held root repository has a separate Git capture path.
             * A selected subtree must not silently erase a nested repository. */
            if (*cursor->path) return native_error(env, "selected source subtree contains nested Git metadata");
            continue;
        }
        if (strchr(item->d_name, '\\') || !utf8_valid((unsigned char *)item->d_name) ||
            strlen(cursor->path) + strlen(item->d_name) + (*cursor->path ? 1 : 0) > 4096)
            return native_error(env, "source metadata name is not a bounded UTF-8 relative path");
        /* Do not open directories, read file bytes or readlink here. Metadata
         * inventory can discard an unreadable excluded entry without effects. */
        struct stat named;
        if (fstatat(cursor->fd, item->d_name, &named, AT_SYMLINK_NOFOLLOW) < 0 || !source_cursor_held(cursor))
            return native_error(env, "source metadata entry changed or is unreadable");
        source_entry *entry = calloc(1, sizeof(*entry));
        if (!entry) return native_error(env, "source entry allocation failed");
        entry->cursor = cursor; entry->before = named; entry->name = strdup(item->d_name);
        size_t length = strlen(cursor->path) + strlen(item->d_name) + 2;
        entry->path = malloc(length);
        if (entry->path) snprintf(entry->path, length, "%s%s%s", cursor->path, *cursor->path ? "/" : "", item->d_name);
        const char *kind = S_ISDIR(named.st_mode) ? "directory" : S_ISREG(named.st_mode) ? "file" : S_ISLNK(named.st_mode) ? "symlink" : "unsupported";
        const napi_property_descriptor methods[] = {
            {"openFile", NULL, source_entry_file, NULL, NULL, NULL, napi_default, NULL},
            {"openDirectory", NULL, source_entry_directory, NULL, NULL, NULL, napi_default, NULL},
            {"readSymlink", NULL, source_entry_link, NULL, NULL, NULL, napi_default, NULL},
            {"assertHeld", NULL, source_entry_assert, NULL, NULL, NULL, napi_default, NULL},
            {"assertPathHeld", NULL, source_entry_assert_path, NULL, NULL, NULL, napi_default, NULL},
            {"close", NULL, source_entry_close, NULL, NULL, NULL, napi_default, NULL}
        };
        if (!entry->name || !entry->path || napi_create_reference(env, self, 1, &entry->cursor_ref) != napi_ok ||
            napi_create_object(env, &result) != napi_ok || !string_property(env, result, "path", entry->path) ||
            !string_property(env, result, "kind", kind) || !number_property(env, result, "mode", named.st_mode & 07777) ||
            !number_property(env, result, "byteCount", S_ISREG(named.st_mode) ? (double)named.st_size : 0) ||
            !number_property(env, result, "linkCount", (double)named.st_nlink) || !identity_member(env, result, "identity", &named) ||
            napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok || napi_type_tag_object(env, result, &source_entry_tag) != napi_ok ||
            napi_wrap(env, result, entry, source_finalize_entry, NULL, NULL) != napi_ok) {
            if (entry->cursor_ref) napi_delete_reference(env, entry->cursor_ref);
            free(entry->name); free(entry->path); free(entry); return native_error(env, "source entry mint failed");
        }
        entry->next = cursor->entries; cursor->entries = entry; napi_object_freeze(env, result); return result;
    }
}
static napi_value source_mint_cursor(napi_env env, source_root *root, napi_value root_object,
                                    source_entry *parent, napi_value parent_object, int fd, const char *path) {
    source_cursor *cursor = calloc(1, sizeof(*cursor));
    if (!cursor) { if (close(fd) < 0) root->retirement_error = errno; return native_error(env, "source cursor allocation failed"); }
    cursor->root = root; cursor->parent = parent; cursor->fd = fd; cursor->path = strdup(path);
    cursor->directory = fdopendir(fd);
    if (!cursor->directory) { cursor->fd = -1; if (close(fd) < 0) root->retirement_error = errno; }
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"next", NULL, source_cursor_next, NULL, NULL, NULL, napi_default, NULL},
        {"assertComplete", NULL, source_cursor_complete, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_cursor_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (!cursor->directory || !cursor->path || fstat(fd, &cursor->before) < 0 ||
        (parent && !source_metadata_same(&parent->before, &cursor->before)) ||
        napi_create_reference(env, root_object, 1, &cursor->root_ref) != napi_ok ||
        (parent_object && napi_create_reference(env, parent_object, 1, &cursor->parent_ref) != napi_ok) ||
        napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, 3, methods) != napi_ok ||
        napi_type_tag_object(env, result, &source_cursor_tag) != napi_ok ||
        napi_wrap(env, result, cursor, source_finalize_cursor, NULL, NULL) != napi_ok) {
        source_close_cursor(cursor);
        if (cursor->root_ref) napi_delete_reference(env, cursor->root_ref);
        if (cursor->parent_ref) napi_delete_reference(env, cursor->parent_ref);
        free(cursor->path); free(cursor); return root->retirement_error ? source_retirement_failure(env) : native_error(env, "source directory cursor could not be opened exactly");
    }
    cursor->next = root->cursors; root->cursors = cursor;
    if (parent) { parent->child = cursor; parent->opened = 1; }
    napi_object_freeze(env, result); return result;
}
static napi_value source_entry_directory(napi_env env, napi_callback_info info) {
    source_entry *entry = source_unwrap(env, info, &source_entry_tag); napi_value self, root_object;
    if (!entry) return NULL;
    if (!source_entry_held(entry) || !source_entry_same_device(entry) || !S_ISDIR(entry->before.st_mode) || entry->opened ||
        napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_get_reference_value(env, entry->cursor->root_ref, &root_object) != napi_ok)
        return native_error(env, "source directory requires an unopened selected held entry");
    int fd = openat(entry->cursor->fd, entry->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return native_error(env, "selected source directory is unreadable");
    return source_mint_cursor(env, entry->cursor->root, root_object, entry, self, fd, entry->path);
}
static napi_value source_open_snapshot(napi_env env, napi_callback_info info) {
    source_root *root = unwrap_source_root(env, info); napi_value self;
    if (!root) return NULL;
    if (!source_held(root) || napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok)
        return native_error(env, "source root changed or closed");
    /* A dup shares readdir's offset. Open the held directory's fixed dot to
     * give each inventory its own open file description, not a caller path. */
    int fd = openat(root->fds[root->count - 1], ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return native_error(env, "source metadata root is unreadable");
    return source_mint_cursor(env, root, self, NULL, NULL, fd, "");
}
