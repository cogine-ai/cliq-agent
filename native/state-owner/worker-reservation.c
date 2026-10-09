/* Fixed StateOwner-relative reservation files. Only the installed Linux
 * helper writes birth facts; this handle exposes no path or writer operation. */
typedef struct worker_reservation_borrow worker_reservation_borrow;
struct worker_reservation {
    state_lock *lock;
    napi_ref lock_ref;
    int parent_fd, fd, closed, finalized;
    struct stat parent, identity;
    char name[44];
    worker_reservation_borrow *borrows;
    worker_reservation *next;
};
struct worker_reservation_borrow {
    worker_reservation *reservation;
    napi_ref reservation_ref;
    int fd;
    worker_reservation_borrow *next;
};
static const napi_type_tag worker_reservation_tag = {0x6dc9a623dc9c4e51ULL, 0x9c534ed274782df1ULL};
static const napi_type_tag worker_reservation_borrow_tag = {0xf8f45213ca864911ULL, 0x85175bd7acf51f21ULL};
static void reservation_close_descriptor(state_lock *lock, int *slot) {
    int fd = *slot; *slot = -1;
    if (fd >= 0 && close(fd) < 0) lock->worker_reservation_error = errno;
}
static void close_worker_reservation(worker_reservation *reservation) {
    reservation->closed = 1;
    for (worker_reservation_borrow *borrow = reservation->borrows; borrow; borrow = borrow->next)
        reservation_close_descriptor(reservation->lock, &borrow->fd);
    reservation_close_descriptor(reservation->lock, &reservation->fd);
    reservation_close_descriptor(reservation->lock, &reservation->parent_fd);
}
static int close_lock_worker_reservations(state_lock *lock) {
    for (worker_reservation *reservation = lock->worker_reservations; reservation; reservation = reservation->next)
        close_worker_reservation(reservation);
    return lock->worker_reservation_error;
}
static napi_value reservation_retirement_failure(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "worker reservation descriptors did not retire; StateOwner remains held");
    return NULL;
}
static void free_worker_reservation(napi_env env, worker_reservation *reservation) {
    if (!reservation->finalized || reservation->borrows) return;
    state_lock *lock = reservation->lock; napi_ref ref = reservation->lock_ref;
    worker_reservation **link = &lock->worker_reservations;
    while (*link && *link != reservation) link = &(*link)->next;
    if (*link) *link = reservation->next;
    free(reservation); free_lock_if_done(lock);
    if (ref) napi_delete_reference(env, ref);
}
static void finalize_worker_reservation(napi_env env, void *data, void *hint) {
    (void)hint; worker_reservation *reservation = data;
    close_worker_reservation(reservation); reservation->finalized = 1;
    free_worker_reservation(env, reservation);
}
static worker_reservation *unwrap_worker_reservation(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; worker_reservation *reservation = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &worker_reservation_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&reservation) != napi_ok || !reservation) {
        native_error(env, "invalid opaque worker reservation"); return NULL;
    }
    return reservation;
}
static int worker_reservation_held(worker_reservation *reservation) {
    struct stat parent, file, named;
    return !reservation->closed && !reservation->lock->worker_reservation_error && reservation->parent_fd >= 0 &&
        reservation->fd >= 0 && lock_is_held(reservation->lock) &&
        fstat(reservation->parent_fd, &parent) == 0 && private_directory(&parent) &&
        same_inode(&parent, &reservation->parent) && parent.st_dev == reservation->lock->root.st_dev &&
        fstatat(reservation->lock->runtime_fd, "worker-reservations", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_directory(&named) && same_inode(&named, &parent) &&
        fstat(reservation->fd, &file) == 0 && private_lock_file(&file) &&
        same_inode(&file, &reservation->identity) && file.st_dev == reservation->lock->root.st_dev &&
        fstatat(reservation->parent_fd, reservation->name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_lock_file(&named) && same_inode(&named, &file);
}
static napi_value worker_reservation_assert(napi_env env, napi_callback_info info) {
    worker_reservation *reservation = unwrap_worker_reservation(env, info); napi_value result;
    if (!reservation) return NULL;
    if (!worker_reservation_held(reservation)) return native_error(env, "worker reservation identity changed or closed");
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value worker_reservation_close(napi_env env, napi_callback_info info) {
    worker_reservation *reservation = unwrap_worker_reservation(env, info); napi_value result;
    if (!reservation) return NULL;
    close_worker_reservation(reservation);
    if (reservation->lock->worker_reservation_error) return reservation_retirement_failure(env);
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static worker_reservation_borrow *unwrap_worker_reservation_borrow(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; worker_reservation_borrow *borrow = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &worker_reservation_borrow_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&borrow) != napi_ok || !borrow) {
        native_error(env, "invalid worker reservation borrow"); return NULL;
    }
    return borrow;
}
static napi_value worker_reservation_borrow_assert(napi_env env, napi_callback_info info) {
    worker_reservation_borrow *borrow = unwrap_worker_reservation_borrow(env, info); struct stat file; napi_value result;
    if (!borrow) return NULL;
    if (borrow->fd < 0 || !worker_reservation_held(borrow->reservation) ||
        fstat(borrow->fd, &file) < 0 || !private_lock_file(&file) || !same_inode(&file, &borrow->reservation->identity))
        return native_error(env, "worker reservation borrow changed or closed");
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value worker_reservation_borrow_close(napi_env env, napi_callback_info info) {
    worker_reservation_borrow *borrow = unwrap_worker_reservation_borrow(env, info); napi_value result;
    if (!borrow) return NULL;
    reservation_close_descriptor(borrow->reservation->lock, &borrow->fd);
    if (borrow->reservation->lock->worker_reservation_error) return reservation_retirement_failure(env);
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void finalize_worker_reservation_borrow(napi_env env, void *data, void *hint) {
    (void)hint; worker_reservation_borrow *borrow = data; worker_reservation *reservation = borrow->reservation;
    napi_ref ref = borrow->reservation_ref;
    reservation_close_descriptor(reservation->lock, &borrow->fd);
    worker_reservation_borrow **link = &reservation->borrows;
    while (*link && *link != borrow) link = &(*link)->next;
    if (*link) *link = borrow->next;
    free(borrow); free_worker_reservation(env, reservation);
    if (ref) napi_delete_reference(env, ref);
}
static napi_value worker_reservation_borrow_handle(napi_env env, napi_callback_info info) {
    worker_reservation *reservation = unwrap_worker_reservation(env, info);
    if (!reservation) return NULL;
    if (!worker_reservation_held(reservation)) return native_error(env, "worker reservation is closed or changed");
    worker_reservation_borrow *borrow = calloc(1, sizeof(*borrow));
    if (!borrow) return native_error(env, "cannot allocate worker reservation borrow");
    borrow->reservation = reservation; borrow->fd = fcntl(reservation->fd, F_DUPFD_CLOEXEC, 0);
    napi_value self, result, descriptor; struct stat file;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, worker_reservation_borrow_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, worker_reservation_borrow_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (borrow->fd < 0 || fstat(borrow->fd, &file) < 0 || !private_lock_file(&file) ||
        !same_inode(&file, &reservation->identity) || !worker_reservation_held(reservation) ||
        napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_create_reference(env, self, 1, &borrow->reservation_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || napi_create_int32(env, borrow->fd, &descriptor) != napi_ok ||
        napi_set_named_property(env, result, "fd", descriptor) != napi_ok ||
        !identity_member(env, result, "identity", &file) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &worker_reservation_borrow_tag) != napi_ok ||
        napi_wrap(env, result, borrow, finalize_worker_reservation_borrow, NULL, NULL) != napi_ok) {
        reservation_close_descriptor(reservation->lock, &borrow->fd);
        if (borrow->reservation_ref) napi_delete_reference(env, borrow->reservation_ref);
        free(borrow);
        if (reservation->lock->worker_reservation_error) return reservation_retirement_failure(env);
        return native_error(env, "cannot mint worker reservation borrow");
    }
    borrow->next = reservation->borrows; reservation->borrows = borrow;
    napi_object_freeze(env, result); return result;
}
static int worker_reservation_expected(napi_env env, napi_value device_value, napi_value inode_value,
                                       napi_value uid_value, const struct stat *file) {
    char device[32], inode[32], expected_device[32], expected_inode[32]; double uid; size_t length;
#ifdef __APPLE__
    unsigned long long device_id = (uint32_t)file->st_dev;
#else
    unsigned long long device_id = file->st_dev;
#endif
    snprintf(expected_device, sizeof(expected_device), "%llu", device_id);
    snprintf(expected_inode, sizeof(expected_inode), "%llu", (unsigned long long)file->st_ino);
    return napi_get_value_string_utf8(env, device_value, device, sizeof(device), &length) == napi_ok &&
        length < sizeof(device) && strcmp(device, expected_device) == 0 &&
        napi_get_value_string_utf8(env, inode_value, inode, sizeof(inode), &length) == napi_ok &&
        length < sizeof(inode) && strcmp(inode, expected_inode) == 0 &&
        napi_get_value_double(env, uid_value, &uid) == napi_ok && uid == file->st_uid;
}
static napi_value worker_reservation_open(napi_env env, napi_callback_info info, int create) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    size_t argc = 4; napi_value args[4], self, result;
    if (!lock_is_held(lock) || lock->worker_reservation_error ||
        napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != (create ? 1U : 4U))
        return native_error(env, "invalid worker reservation or closed StateOwner");
    worker_reservation *reservation = calloc(1, sizeof(*reservation));
    if (!reservation) return native_error(env, "cannot allocate worker reservation");
    reservation->lock = lock; reservation->fd = reservation->parent_fd = -1;
    const char *error = "invalid derived worker reservation name";
    if (!read_component(env, args[0], reservation->name, sizeof(reservation->name), 43)) goto failed;
    for (size_t i = 0; i < 43; i++) if (!((reservation->name[i] >= '0' && reservation->name[i] <= '9') ||
        (reservation->name[i] >= 'a' && reservation->name[i] <= 'z') ||
        (reservation->name[i] >= 'A' && reservation->name[i] <= 'Z') ||
        reservation->name[i] == '-' || reservation->name[i] == '_')) goto failed;
    error = "worker reservation parent is unsafe";
    int made_parent = 0;
    if (create) {
        if (mkdirat(lock->runtime_fd, "worker-reservations", 0700) == 0) made_parent = 1;
        else if (errno != EEXIST) goto failed;
    }
    reservation->parent_fd = openat(lock->runtime_fd, "worker-reservations", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat named;
    if (reservation->parent_fd < 0 || fstat(reservation->parent_fd, &reservation->parent) < 0 ||
        !private_directory(&reservation->parent) || reservation->parent.st_dev != lock->root.st_dev ||
        fstatat(lock->runtime_fd, "worker-reservations", &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !same_inode(&named, &reservation->parent) || !lock_is_held(lock)) goto failed;
    if (made_parent && !sync_directory(lock->runtime_fd)) goto failed;
    error = "worker reservation file is unsafe or missing";
    reservation->fd = openat(reservation->parent_fd, reservation->name,
        O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0600);
    if (reservation->fd < 0 || fstat(reservation->fd, &reservation->identity) < 0 ||
        !private_lock_file(&reservation->identity) || reservation->identity.st_dev != lock->root.st_dev ||
        (create && reservation->identity.st_size != 0) ||
        (!create && !worker_reservation_expected(env, args[1], args[2], args[3], &reservation->identity)) ||
        !worker_reservation_held(reservation)) goto failed;
    error = "worker reservation persistence failed";
    if (create && (fsync(reservation->fd) < 0 || !sync_directory(reservation->parent_fd) ||
        !worker_reservation_held(reservation))) goto failed;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, worker_reservation_assert, NULL, NULL, NULL, napi_default, NULL},
        {"borrow", NULL, worker_reservation_borrow_handle, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, worker_reservation_close, NULL, NULL, NULL, napi_default, NULL}
    };
    error = "cannot mint worker reservation";
    if (napi_create_reference(env, self, 1, &reservation->lock_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || !identity_member(env, result, "identity", &reservation->identity) ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &worker_reservation_tag) != napi_ok ||
        napi_wrap(env, result, reservation, finalize_worker_reservation, NULL, NULL) != napi_ok) goto failed;
    reservation->next = lock->worker_reservations; lock->worker_reservations = reservation;
    napi_object_freeze(env, result); return result;
failed:
    close_worker_reservation(reservation);
    if (reservation->lock_ref) napi_delete_reference(env, reservation->lock_ref);
    free(reservation);
    if (lock->worker_reservation_error) return reservation_retirement_failure(env);
    return native_error(env, error);
}
static napi_value create_worker_reservation(napi_env env, napi_callback_info info) { return worker_reservation_open(env, info, 1); }
static napi_value open_worker_reservation(napi_env env, napi_callback_info info) { return worker_reservation_open(env, info, 0); }
