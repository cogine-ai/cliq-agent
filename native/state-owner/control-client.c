/* Fixed installed-auth transport. It borrows only the producer's original
 * verified root and selected executable, never a StateOwner/SQLite lock. */
#ifdef __linux__
#include <sys/syscall.h>
typedef struct {
    napi_env env;
    pthread_t thread;
    pid_t owner_pid, pid;
    uid_t owner_uid, uid;
    gid_t owner_gid, gid;
    int root_fd, runtime_fd, image_fd, fd, transferred, retirement_failed;
    struct stat root, runtime, image, entry, transport;
    char root_path[PATH_MAX], socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)], start_token[128];
} installed_control_client;

static const napi_type_tag installed_client_tag = {0xe325f2bd66704f24ULL, 0x92f17a3a2a737d68ULL};
static atomic_int installed_client_retirement_failed = 0;

static napi_value installed_client_error(napi_env env, const char *code, const char *message) {
    napi_throw_error(env, code, message);
    return NULL;
}
static int installed_client_owner(installed_control_client *client, napi_env env) {
    return client->env == env && client->owner_pid == getpid() &&
        pthread_equal(client->thread, pthread_self()) && syscall(SYS_gettid) == getpid() &&
        client->owner_uid == getuid() && client->owner_uid == geteuid() &&
        client->owner_gid == getgid() && client->owner_gid == getegid();
}
static void installed_client_retire(installed_control_client *client, int *fd) {
    retire_process_fd(fd, &client->retirement_failed);
    if (client->retirement_failed) atomic_store(&installed_client_retirement_failed, 1);
}
static int installed_client_close(installed_control_client *client) {
    if (client->retirement_failed || atomic_load(&installed_client_retirement_failed)) return 0;
    if (client->fd >= 0 && shutdown(client->fd, SHUT_RDWR) < 0 && errno != ENOTCONN) {
        client->retirement_failed = 1;
        atomic_store(&installed_client_retirement_failed, 1);
        return 0;
    }
    installed_client_retire(client, &client->fd);
    if (client->retirement_failed) return 0;
    installed_client_retire(client, &client->image_fd);
    if (client->retirement_failed) return 0;
    installed_client_retire(client, &client->runtime_fd);
    if (client->retirement_failed) return 0;
    installed_client_retire(client, &client->root_fd);
    return !client->retirement_failed;
}
static int installed_client_namespace(installed_control_client *client) {
    struct stat root, runtime, entry, image, transport, visible;
    int valid = fstat(client->root_fd, &root) == 0 && private_directory(&root) && root.st_gid == getegid() &&
        same_inode(&root, &client->root) && fstat(client->runtime_fd, &runtime) == 0 &&
        private_directory(&runtime) && runtime.st_gid == getegid() && same_inode(&runtime, &client->runtime) &&
        fstatat(client->root_fd, "runtime", &entry, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&entry, &runtime) &&
        fstatat(client->runtime_fd, CONTROL_SOCKET_NAME, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_socket(&entry) && same_inode(&entry, &client->entry) &&
        fstat(client->image_fd, &image) == 0 && same_image(&image, &client->image) &&
        fstat(client->fd, &transport) == 0 && same_inode(&transport, &client->transport) && stream_socket(client->fd);
    if (!valid) return 0;
    int reopened = open_root_with_retirement(client->root_path, &client->retirement_failed);
    valid = reopened >= 0 && fstat(reopened, &visible) == 0 && private_directory(&visible) && same_inode(&visible, &root);
    installed_client_retire(client, &reopened);
    if (client->retirement_failed) return -1;
    return valid;
}
static int installed_client_is_held(installed_control_client *client) {
    if (client->retirement_failed || atomic_load(&installed_client_retirement_failed) ||
        atomic_load(&current_process_retirement_failed)) return -1;
    if (!installed_client_owner(client, client->env) || client->fd < 0 || client->root_fd < 0 ||
        client->runtime_fd < 0 || client->image_fd < 0) return 0;
    int namespace = installed_client_namespace(client);
    if (namespace != 1) return namespace;
    struct stat running;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    socklen_t address_size = sizeof(address);
    pid_t pid;
    uid_t uid;
    gid_t gid;
    char token[128], image_path[PATH_MAX];
    struct pollfd status = {client->fd, POLLIN, 0};
    int polled;
    do { polled = poll(&status, 1, 0); } while (polled < 0 && errno == EINTR);
    if (polled < 0 || (status.revents & (POLLHUP | POLLERR | POLLNVAL)) ||
        getpeername(client->fd, (struct sockaddr *)&address, &address_size) != 0 || address.sun_family != AF_UNIX ||
        !memchr(address.sun_path, '\0', sizeof(address.sun_path)) || strcmp(address.sun_path, client->socket_path) != 0 ||
        !peer_credentials(client->fd, &pid, &uid, &gid) || pid != client->pid || uid != client->uid || gid != client->gid ||
        uid != client->owner_uid || observe_process_with_retirement(pid, token, &client->retirement_failed) != 1 ||
        strcmp(token, client->start_token) != 0) return client->retirement_failed ? -1 : 0;
    char byte;
    ssize_t count;
    do { count = recv(client->fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT); } while (count < 0 && errno == EINTR);
    if (count == 0 || (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) return 0;
    int fd = open_process_image(pid, uid, gid, image_path, &running, &client->retirement_failed);
    int valid = fd >= 0 && same_image(&running, &client->image);
    installed_client_retire(client, &fd);
    if (client->retirement_failed) return -1;
    valid = valid && observe_process_with_retirement(pid, token, &client->retirement_failed) == 1 &&
        strcmp(token, client->start_token) == 0 && peer_credentials(client->fd, &pid, &uid, &gid) &&
        pid == client->pid && uid == client->uid && gid == client->gid;
    if (client->retirement_failed) return -1;
    if (!valid) return 0;
    /* Close the locator cut after process/image temporary descriptors retire. */
    return installed_client_namespace(client);
}
static installed_control_client *installed_client_unwrap(napi_env env, napi_callback_info info) {
    installed_control_client *client = unwrap_control(env, info, &installed_client_tag, "invalid installed control client");
    size_t argc = 1;
    napi_value argument;
    if (client && (!installed_client_owner(client, env) ||
        napi_get_cb_info(env, info, &argc, &argument, NULL, NULL) != napi_ok || argc != 0)) {
        installed_client_error(env, "ERR_CLIQ_CONTROL_CLIENT", "installed control client belongs to another owner context");
        return NULL;
    }
    return client;
}
static napi_value installed_client_assert(napi_env env, napi_callback_info info) {
    installed_control_client *client = installed_client_unwrap(env, info);
    if (!client) return NULL;
    int held = installed_client_is_held(client);
    if (held < 0) return installed_client_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "installed control client resources are uncertain");
    if (!held) return installed_client_error(env, "ERR_CLIQ_CONTROL_CLIENT", "installed control client bindings changed or closed");
    return undefined_result(env);
}
static napi_value installed_client_release(napi_env env, napi_callback_info info) {
    installed_control_client *client = installed_client_unwrap(env, info);
    if (!client) return NULL;
    if (!installed_client_close(client)) return installed_client_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "installed control client did not retire");
    return undefined_result(env);
}
static napi_value installed_client_transfer(napi_env env, napi_callback_info info) {
    installed_control_client *client = installed_client_unwrap(env, info);
    if (!client) return NULL;
    int held = installed_client_is_held(client);
    if (held < 0) return installed_client_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "installed control client resources are uncertain");
    if (!held || client->transferred) return installed_client_error(env, "ERR_CLIQ_CONTROL_CLIENT", "installed control transfer is closed or consumed");
    int fd = fcntl(client->fd, F_DUPFD_CLOEXEC, 0);
    napi_value result;
    if (fd < 0 || !socket_flags(fd) || napi_create_int32(env, fd, &result) != napi_ok) {
        installed_client_retire(client, &fd);
        return installed_client_error(env, client->retirement_failed ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_CONTROL_CLIENT", "installed control transfer failed");
    }
    client->transferred = 1;
    return result;
}
static void installed_client_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    installed_control_client *client = data;
    /* An uncertain close is not GC permission to discard the retained guards. */
    if (installed_client_close(client)) free(client);
}
static int installed_client_tuple(napi_env env, napi_value value, const struct stat *identity, int image) {
    bool array = false, lossless;
    uint32_t count;
    uint64_t expected[9] = {(uint64_t)identity->st_dev, (uint64_t)identity->st_ino, (uint64_t)identity->st_uid,
        (uint64_t)identity->st_gid, (uint64_t)identity->st_mode, (uint64_t)identity->st_size,
        (uint64_t)identity->st_nlink, (uint64_t)identity->st_mtim.tv_sec * 1000000000ULL + identity->st_mtim.tv_nsec,
        (uint64_t)identity->st_ctim.tv_sec * 1000000000ULL + identity->st_ctim.tv_nsec};
    uint32_t wanted = image ? 9 : 5;
    if (napi_is_array(env, value, &array) != napi_ok || !array ||
        napi_get_array_length(env, value, &count) != napi_ok || count != wanted) return 0;
    for (uint32_t index = 0; index < wanted; index++) {
        napi_value field;
        uint64_t actual;
        if (napi_get_element(env, value, index, &field) != napi_ok ||
            napi_get_value_bigint_uint64(env, field, &actual, &lossless) != napi_ok || !lossless || actual != expected[index]) return 0;
    }
    return 1;
}
static napi_value connect_installed_control(napi_env env, napi_callback_info info) {
    if (atomic_load(&installed_client_retirement_failed) || atomic_load(&current_process_retirement_failed))
        return installed_client_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "installed control client process is uncertain");
    installed_control_client *client = calloc(1, sizeof(*client));
    if (!client) return installed_client_error(env, "ERR_CLIQ_CONTROL_CLIENT", "installed control allocation failed");
    client->env = env; client->thread = pthread_self(); client->owner_pid = getpid();
    client->owner_uid = geteuid(); client->owner_gid = getegid();
    client->root_fd = client->runtime_fd = client->image_fd = client->fd = -1;
    napi_value argv[6], result, server, token;
    size_t argc = 6, length;
    double root_fd, image_fd;
    int wrapped = 0;
    if (!installed_client_owner(client, env) || napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 5 ||
        napi_get_value_double(env, argv[0], &root_fd) != napi_ok || !(root_fd >= 0 && root_fd <= INT_MAX) || root_fd != (int)root_fd ||
        napi_get_value_string_utf8(env, argv[1], NULL, 0, &length) != napi_ok || length < 2 || length >= sizeof(client->root_path) ||
        napi_get_value_string_utf8(env, argv[1], client->root_path, sizeof(client->root_path), &length) != napi_ok ||
        strlen(client->root_path) != length ||
        napi_get_value_double(env, argv[3], &image_fd) != napi_ok || !(image_fd >= 0 && image_fd <= INT_MAX) || image_fd != (int)image_fd) goto fail;
    client->root_fd = fcntl((int)root_fd, F_DUPFD_CLOEXEC, 0);
    client->image_fd = fcntl((int)image_fd, F_DUPFD_CLOEXEC, 0);
    if (client->root_fd < 0 || client->image_fd < 0 || fstat(client->root_fd, &client->root) != 0 ||
        !private_directory(&client->root) || client->root.st_gid != getegid() ||
        !installed_client_tuple(env, argv[2], &client->root, 0) || fstat(client->image_fd, &client->image) != 0 ||
        !same_image(&client->image, &client->image) || client->image.st_uid != geteuid() || client->image.st_gid != getegid() ||
        (client->image.st_mode & 07777) != 0500 || client->image.st_nlink != 1 ||
        !installed_client_tuple(env, argv[4], &client->image, 1)) goto fail;
    client->runtime_fd = openat(client->root_fd, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (client->runtime_fd < 0 || fstat(client->runtime_fd, &client->runtime) != 0 ||
        !private_directory(&client->runtime) || client->runtime.st_gid != getegid() ||
        fstatat(client->runtime_fd, CONTROL_SOCKET_NAME, &client->entry, AT_SYMLINK_NOFOLLOW) != 0 || !private_socket(&client->entry)) goto fail;
    int path_length = snprintf(client->socket_path, sizeof(client->socket_path), "%s/runtime/%s", client->root_path, CONTROL_SOCKET_NAME);
    if (path_length < 0 || (size_t)path_length >= sizeof(client->socket_path)) goto fail;
    client->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, client->socket_path, (size_t)path_length + 1);
    if (client->fd < 0 || connect(client->fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        fstat(client->fd, &client->transport) != 0 || !S_ISSOCK(client->transport.st_mode) ||
        !peer_credentials(client->fd, &client->pid, &client->uid, &client->gid) || client->uid != client->owner_uid ||
        observe_process_with_retirement(client->pid, client->start_token, &client->retirement_failed) != 1 ||
        installed_client_is_held(client) != 1) goto fail;
    const napi_property_descriptor methods[] = {
        {"takeSocketFd", NULL, installed_client_transfer, NULL, NULL, NULL, napi_default, NULL},
        {"assertHeld", NULL, installed_client_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, installed_client_release, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &server) != napi_ok || !uint_member(env, server, "pid", client->pid) ||
        !uint_member(env, server, "uid", client->uid) || !uint_member(env, server, "gid", client->gid) ||
        napi_create_string_utf8(env, client->start_token, NAPI_AUTO_LENGTH, &token) != napi_ok ||
        napi_set_named_property(env, server, "processStartToken", token) != napi_ok || napi_object_freeze(env, server) != napi_ok ||
        napi_create_object(env, &result) != napi_ok || napi_set_named_property(env, result, "server", server) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &installed_client_tag) != napi_ok || napi_object_freeze(env, result) != napi_ok ||
        napi_wrap(env, result, client, installed_client_finalize, NULL, NULL) != napi_ok) goto fail;
    wrapped = 1;
    if (installed_client_is_held(client) != 1) goto fail;
    return result;
fail:;
    int retired = installed_client_close(client);
    if (!wrapped && retired) free(client);
    return installed_client_error(env, retired ? "ERR_CLIQ_CONTROL_CLIENT" : "ERR_CLIQ_RESOURCE_RETIREMENT",
        retired ? "fixed installed control connection or selected server identity is unavailable" : "installed control acquisition cleanup is uncertain");
}
#else
static napi_value connect_installed_control(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "installed control client requires Linux");
}
#endif
