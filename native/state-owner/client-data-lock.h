/* Private client-data serialization only. No StateOwner, database, process
 * lifetime, credential or execution authority is acquired by this holder.
 * The fixed file is a live OS mutex, not durable evidence: it is never unlinked
 * or interpreted after death. No fsync is needed to preserve a live flock;
 * request-data durability remains with the caller's existing fsync protocol. */
#define CLIENT_DATA_LOCK_NAME "client-mutation.lock"
typedef struct {
    int directory_fd, file_fd, retirement_failed;
    struct stat directory, file;
} client_data_lock;
static const napi_type_tag client_data_lock_tag = {0x2152aeb3cc514869ULL, 0xbae03f6746cf86abULL};
static atomic_int client_data_lock_retirement_failed = 0;

static int client_data_same_directory(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode;
}
static int client_data_same_file(const struct stat *a, const struct stat *b) {
#ifdef __APPLE__
    int times = a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    int times = a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
    return client_data_same_directory(a, b) && a->st_nlink == b->st_nlink && a->st_size == b->st_size && times;
}
static int client_data_file(const struct stat *file) {
    return private_lock_file(file) && file->st_size == 0;
}
static void client_data_close(client_data_lock *lock) {
    int file = lock->file_fd, directory = lock->directory_fd;
    lock->file_fd = lock->directory_fd = -1;
    if (file >= 0 && close(file) != 0) lock->retirement_failed = 1;
    if (directory >= 0 && close(directory) != 0) lock->retirement_failed = 1;
    if (lock->retirement_failed) atomic_store(&client_data_lock_retirement_failed, 1);
}
static napi_value client_data_retirement_error(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "private client-data lock descriptors did not retire"); return NULL;
}
static int client_data_held(client_data_lock *lock) {
    struct stat directory, file, named, after, directory_after;
    return lock->directory_fd >= 0 && lock->file_fd >= 0 &&
        fstat(lock->directory_fd, &directory) == 0 && private_directory(&directory) &&
        client_data_same_directory(&lock->directory, &directory) &&
        fstat(lock->file_fd, &file) == 0 && client_data_file(&file) && client_data_same_file(&lock->file, &file) &&
        fstatat(lock->directory_fd, CLIENT_DATA_LOCK_NAME, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        client_data_file(&named) && client_data_same_file(&file, &named) &&
        fstat(lock->file_fd, &after) == 0 && client_data_same_file(&file, &after) &&
        fstat(lock->directory_fd, &directory_after) == 0 && client_data_same_directory(&directory, &directory_after);
}
static client_data_lock *client_data_receiver(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1], self; bool tagged = false; client_data_lock *lock = NULL;
    if (napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != 0 ||
        napi_check_object_type_tag(env, self, &client_data_lock_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&lock) != napi_ok || !lock) {
        native_error(env, "private client-data lock requires its original receiver and no arguments"); return NULL;
    }
    return lock;
}
static napi_value client_data_assert(napi_env env, napi_callback_info info) {
    client_data_lock *lock = client_data_receiver(env, info); napi_value value;
    if (!lock) return NULL;
    if (lock->retirement_failed || atomic_load(&client_data_lock_retirement_failed)) return client_data_retirement_error(env);
    if (!client_data_held(lock)) return native_error(env, "private client-data lock changed or closed");
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value client_data_release(napi_env env, napi_callback_info info) {
    client_data_lock *lock = client_data_receiver(env, info); napi_value value;
    if (!lock) return NULL;
    client_data_close(lock);
    if (lock->retirement_failed || atomic_load(&client_data_lock_retirement_failed)) return client_data_retirement_error(env);
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static void client_data_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; client_data_lock *lock = data; client_data_close(lock); free(lock);
}
static napi_value try_lock_client_data_directory(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2], result; double input;
    if (atomic_load(&client_data_lock_retirement_failed)) return client_data_retirement_error(env);
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_get_value_double(env, argv[0], &input) != napi_ok || !(input >= 0 && input <= INT_MAX) || input != (int)input)
        return native_error(env, "private client-data locking requires one directory descriptor");
    client_data_lock *lock = calloc(1, sizeof(*lock));
    if (!lock) return native_error(env, "private client-data lock allocation failed");
    lock->directory_fd = lock->file_fd = -1;
    struct stat original;
    int valid = fstat((int)input, &original) == 0 && private_directory(&original);
    if (valid) lock->directory_fd = fcntl((int)input, F_DUPFD_CLOEXEC, 3);
    valid = valid && lock->directory_fd >= 0 && fstat(lock->directory_fd, &lock->directory) == 0 &&
        private_directory(&lock->directory) && client_data_same_directory(&original, &lock->directory);
    if (valid) lock->file_fd = openat(lock->directory_fd, CLIENT_DATA_LOCK_NAME,
        O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    valid = valid && lock->file_fd >= 0 && fstat(lock->file_fd, &lock->file) == 0 && client_data_file(&lock->file) && client_data_held(lock);
    int busy = 0;
    if (valid && flock(lock->file_fd, LOCK_EX | LOCK_NB) != 0) {
        busy = errno == EWOULDBLOCK || errno == EAGAIN; valid = 0;
    }
    if (valid) valid = client_data_held(lock);
    if (!valid) {
        client_data_close(lock); int failed = lock->retirement_failed; free(lock);
        if (failed) return client_data_retirement_error(env);
        if (busy) return napi_get_null(env, &result) == napi_ok ? result : NULL;
        return native_error(env, "private client-data directory or fixed lock file is unavailable or changed");
    }
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, client_data_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, client_data_release, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, 2, methods) != napi_ok ||
        napi_type_tag_object(env, result, &client_data_lock_tag) != napi_ok ||
        napi_wrap(env, result, lock, client_data_finalize, NULL, NULL) != napi_ok) {
        client_data_close(lock); int failed = lock->retirement_failed; free(lock);
        if (failed) return client_data_retirement_error(env);
        return native_error(env, "private client-data lock result could not be constructed");
    }
    return result;
}
