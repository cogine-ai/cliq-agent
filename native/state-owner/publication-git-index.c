/* Fixed read-only .git/index observation under the original publication owner.
 * This grants no Trust, source consent, claim, execution or canonical-index
 * authority. The business producer validates its current publication first. */
struct publication_git_reader {
    state_lock *lock;
    source_root *root;
    napi_ref lock_ref, root_ref;
    publication_git_reader *lock_next, *root_next;
    struct stat before;
    int fd, present, closed, complete;
    off_t offset;
};
static const napi_type_tag publication_git_reader_tag = {0x17305dbee32d91aaULL, 0xaa705e8cc72b64e3ULL};
static int publication_git_close(publication_git_reader *reader) {
    int fd = reader->fd; reader->fd = -1; reader->closed = 1;
    if (fd >= 0 && close(fd) < 0) {
        reader->lock->publication_retirement_error = errno;
        reader->root->retirement_error = errno;
    }
    return reader->lock->publication_retirement_error || reader->root->retirement_error;
}
static int close_lock_publication_git_readers(state_lock *lock) {
    for (publication_git_reader *reader = lock->publication_git_readers; reader; reader = reader->lock_next) publication_git_close(reader);
    return lock->publication_retirement_error;
}
static int close_root_publication_git_readers(source_root *root) {
    for (publication_git_reader *reader = root->publication_git_readers; reader; reader = reader->root_next) publication_git_close(reader);
    return root->retirement_error;
}
static int publication_git_held(publication_git_reader *reader) {
    struct stat held, named;
    if (reader->closed || reader->lock->publication_retirement_error || reader->root->retirement_error ||
        !lock_is_held_with_retirement(reader->lock, &reader->lock->publication_retirement_error) || !source_held(reader->root)) return 0;
    if (!reader->present) return fstatat(reader->root->git_fd, "index", &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    return reader->fd >= 0 && fstat(reader->fd, &held) == 0 && source_metadata_same(&reader->before, &held) &&
        fstatat(reader->root->git_fd, "index", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&held, &named);
}
static publication_git_reader *publication_git_unwrap(napi_env env, napi_callback_info info) {
    return source_unwrap(env, info, &publication_git_reader_tag);
}
static napi_value publication_git_assert(napi_env env, napi_callback_info info) {
    publication_git_reader *reader = publication_git_unwrap(env, info);
    if (!reader) return NULL;
    if (reader->lock->publication_retirement_error || reader->root->retirement_error) return publication_retirement_error(env);
    if (!publication_git_held(reader)) return reader->lock->publication_retirement_error ? publication_retirement_error(env) :
        native_error(env, "publication Git index identity changed or closed");
    return publication_undefined(env);
}
static napi_value publication_git_complete(napi_env env, napi_callback_info info) {
    publication_git_reader *reader = publication_git_unwrap(env, info);
    if (!reader) return NULL;
    if (reader->lock->publication_retirement_error || reader->root->retirement_error) return publication_retirement_error(env);
    if (!reader->complete || !publication_git_held(reader)) return reader->lock->publication_retirement_error ? publication_retirement_error(env) :
        native_error(env, "publication Git index has no complete unchanged EOF observation");
    return publication_undefined(env);
}
static napi_value publication_git_chunk(napi_env env, napi_callback_info info) {
    publication_git_reader *reader = publication_git_unwrap(env, info); napi_value value;
    if (!reader) return NULL;
    if (reader->lock->publication_retirement_error || reader->root->retirement_error) return publication_retirement_error(env);
    if (!publication_git_held(reader)) return reader->lock->publication_retirement_error ? publication_retirement_error(env) :
        native_error(env, "publication Git index identity changed or closed");
    if (!reader->present || reader->offset == reader->before.st_size) {
        unsigned char extra; ssize_t count = 0;
        if (reader->present) do { count = pread(reader->fd, &extra, 1, reader->offset); } while (count < 0 && errno == EINTR);
        if (count != 0 || !publication_git_held(reader)) return reader->lock->publication_retirement_error ? publication_retirement_error(env) :
            native_error(env, "publication Git index EOF or metadata changed");
        reader->complete = 1; return napi_get_null(env, &value) == napi_ok ? value : NULL;
    }
    off_t remaining = reader->before.st_size - reader->offset;
    size_t length = remaining < 65536 ? (size_t)remaining : 65536; void *bytes;
    if (napi_create_buffer(env, length, &bytes, &value) != napi_ok) return NULL;
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(reader->fd, (char *)bytes + done, length - done, reader->offset + (off_t)done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return native_error(env, "publication Git index ended before its original bounded size");
        done += (size_t)count;
    }
    reader->offset += (off_t)length;
    if (!publication_git_held(reader)) return reader->lock->publication_retirement_error ? publication_retirement_error(env) :
        native_error(env, "publication Git index changed during the original read");
    return value;
}
static napi_value publication_git_reader_close(napi_env env, napi_callback_info info) {
    publication_git_reader *reader = publication_git_unwrap(env, info);
    if (!reader) return NULL;
    return publication_git_close(reader) ? publication_retirement_error(env) : publication_undefined(env);
}
static void publication_git_free(napi_env env, publication_git_reader *reader) {
    source_root *root = reader->root; state_lock *lock = reader->lock;
    publication_git_reader **link = &lock->publication_git_readers;
    while (*link && *link != reader) link = &(*link)->lock_next;
    if (*link) *link = reader->lock_next;
    link = &root->publication_git_readers;
    while (*link && *link != reader) link = &(*link)->root_next;
    if (*link) *link = reader->root_next;
    napi_ref root_ref = reader->root_ref, lock_ref = reader->lock_ref;
    free(reader); source_free_if_done(root); free_lock_if_done(lock);
    if (root_ref) napi_delete_reference(env, root_ref);
    if (lock_ref) napi_delete_reference(env, lock_ref);
}
static void publication_git_finalize(napi_env env, void *data, void *hint) {
    (void)hint; publication_git_reader *reader = data; publication_git_close(reader); publication_git_free(env, reader);
}
static napi_value open_publication_git_index(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info); source_root *root = NULL;
    napi_value self, argv[5], result, value; size_t argc = 5; bool tagged = false;
    unsigned long long device, inode; double uid, maximum;
    if (!lock) return NULL;
    if (lock->publication_retirement_error) return publication_retirement_error(env);
    if (!lock_is_held_with_retirement(lock, &lock->publication_retirement_error)) return lock->publication_retirement_error ? publication_retirement_error(env) :
        native_error(env, "publication Git index requires its actual held StateOwner");
    if (napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != 5 ||
        napi_check_object_type_tag(env, argv[0], &source_root_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, argv[0], (void **)&root) != napi_ok || !root || !source_held(root) || root->git_fd < 0 ||
        !read_unsigned_id(env, argv[1], &device) || !read_unsigned_id(env, argv[2], &inode) || !inode ||
        napi_get_value_double(env, argv[3], &uid) != napi_ok || !(uid >= 0 && uid <= 4294967295.0 && uid == (double)(unsigned int)uid) || napi_get_value_double(env, argv[4], &maximum) != napi_ok ||
        !(maximum >= 1 && maximum <= 268435456 && maximum == (double)(unsigned int)maximum))
        return native_error(env, "publication Git index requires the original repository identity and fixed byte bound");
#ifdef __APPLE__
    const unsigned long long actual_device = (uint32_t)root->git_id.st_dev;
#else
    const unsigned long long actual_device = root->git_id.st_dev;
#endif
    if (device != actual_device || inode != (unsigned long long)root->git_id.st_ino || uid != root->git_id.st_uid)
        return native_error(env, "publication Git index requires the original repository identity and fixed byte bound");
    publication_git_reader *reader = calloc(1, sizeof(*reader));
    if (!reader) return native_error(env, "publication Git index allocation failed");
    reader->fd = -1; reader->root = root; reader->lock = lock;
    const char *error = "publication Git index is not a same-device single-link bounded regular file";
    if (fstatat(root->git_fd, "index", &reader->before, AT_SYMLINK_NOFOLLOW) < 0) {
        if (errno != ENOENT) goto failed;
    } else {
        reader->present = 1;
        if (!S_ISREG(reader->before.st_mode) || reader->before.st_nlink != 1 || reader->before.st_uid != root->git_id.st_uid ||
            reader->before.st_dev != root->git_id.st_dev || reader->before.st_size < 0 || (double)reader->before.st_size > maximum) goto failed;
        reader->fd = openat(root->git_fd, "index", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat held;
        if (reader->fd < 0 || fstat(reader->fd, &held) < 0 || !source_metadata_same(&reader->before, &held)) goto failed;
    }
    if (!publication_git_held(reader)) goto failed;
    const napi_property_descriptor methods[] = {
        {"readChunk", NULL, publication_git_chunk, NULL, NULL, NULL, napi_default, NULL},
        {"assertHeld", NULL, publication_git_assert, NULL, NULL, NULL, napi_default, NULL},
        {"assertComplete", NULL, publication_git_complete, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, publication_git_reader_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, reader->present, &value) != napi_ok ||
        napi_set_named_property(env, result, "present", value) != napi_ok || napi_create_double(env, reader->present ? (double)reader->before.st_size : 0, &value) != napi_ok ||
        napi_set_named_property(env, result, "byteCount", value) != napi_ok ||
        (reader->present && !identity_member(env, result, "identity", &reader->before)) ||
        napi_type_tag_object(env, result, &publication_git_reader_tag) != napi_ok || napi_define_properties(env, result, 4, methods) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok || napi_create_reference(env, self, 1, &reader->lock_ref) != napi_ok ||
        napi_create_reference(env, argv[0], 1, &reader->root_ref) != napi_ok || napi_wrap(env, result, reader, publication_git_finalize, NULL, NULL) != napi_ok) goto failed;
    reader->lock_next = lock->publication_git_readers; lock->publication_git_readers = reader;
    reader->root_next = root->publication_git_readers; root->publication_git_readers = reader;
    return result;
failed:
    publication_git_close(reader);
    if (reader->root_ref) napi_delete_reference(env, reader->root_ref);
    if (reader->lock_ref) napi_delete_reference(env, reader->lock_ref);
    free(reader);
    return lock->publication_retirement_error || root->retirement_error ? publication_retirement_error(env) : native_error(env, error);
}
