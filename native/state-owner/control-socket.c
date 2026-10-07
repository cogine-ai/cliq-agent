/* Included by state-owner.c: these primitives have no caller-selected socket,
 * descriptor, pid, or executable path. The StateOwner lock is their authority. */
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef __APPLE__
#include <mach/vm_prot.h>
#endif

#define CONTROL_SOCKET_NAME "control-v1.sock"
#define CONTROL_ACCEPT_BURST 32
#define CONTROL_IMAGE_MAX_BYTES (256LL * 1024 * 1024)
#define CONTROL_IMAGE_MAX_REGIONS 4096

typedef struct control_peer control_peer;
typedef struct control_observation control_observation;

struct control_listener {
    napi_env env;
    state_lock *lock;
    napi_ref lock_ref, self_ref, accept_ref, error_ref;
    napi_async_cleanup_hook_handle cleanup_handle;
    uv_poll_t poll;
    int fd, poll_initialized, poll_closed, finalized;
    struct stat transport, entry;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    control_listener *next;
    control_peer *peers;
};

struct control_peer {
    napi_env env;
    control_listener *listener;
    napi_ref listener_ref;
    int fd, transferred, has_image;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    struct stat socket, image;
    char start_token[128];
    control_peer *next;
    control_observation *observations;
};

struct control_observation {
    napi_env env;
    control_peer *peer;
    napi_ref peer_ref;
    int image_fd;
    struct stat image;
    char image_path[PATH_MAX];
    control_observation *next;
};

static const napi_type_tag listener_tag = {0x1a1fc006844c4d70ULL, 0x8a72d9b7fbd0cd75ULL};
static const napi_type_tag peer_tag = {0x733716941bc34e21ULL, 0x82ee08b5eaa7536aULL};
static const napi_type_tag observation_tag = {0x80d847492f1f419cULL, 0xaf4cfe91468053daULL};
/* umask is shared by Node worker environments. Serialize this helper's own
 * bind brackets; unrelated host calls which change umask remain outside the
 * trusted embedding contract and are not protected by this mutex. */
static pthread_mutex_t control_bind_mutex = PTHREAD_MUTEX_INITIALIZER;

static void close_listener(control_listener *listener);
static void close_peer(control_peer *peer);
static void free_listener_if_done(control_listener *listener);

static int private_socket(const struct stat *identity) {
    return S_ISSOCK(identity->st_mode) && identity->st_uid == geteuid() &&
        (identity->st_mode & 07777) == 0600 && identity->st_nlink == 1;
}

static int socket_flags(int fd) {
    int descriptor = fcntl(fd, F_GETFD), status = fcntl(fd, F_GETFL);
    return descriptor >= 0 && status >= 0 &&
        fcntl(fd, F_SETFD, descriptor | FD_CLOEXEC) == 0 &&
        fcntl(fd, F_SETFL, status | O_NONBLOCK) == 0;
}

static int stream_socket(int fd) {
    int type = 0;
    socklen_t size = sizeof(type);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    socklen_t address_size = sizeof(address);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && size == sizeof(type) && type == SOCK_STREAM &&
        getsockname(fd, (struct sockaddr *)&address, &address_size) == 0 && address.sun_family == AF_UNIX;
}

static int listening_socket(int fd) {
#ifdef __APPLE__
    /* XNU exposes the SO_ACCEPTCONN bit via native descriptor inspection;
     * getsockopt(SO_ACCEPTCONN) itself returns ENOPROTOOPT on Darwin. */
    struct socket_fdinfo socket;
    memset(&socket, 0, sizeof(socket));
    return proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) == sizeof(socket) &&
        socket.psi.soi_type == SOCK_STREAM && socket.psi.soi_family == AF_UNIX &&
        (socket.psi.soi_options & SO_ACCEPTCONN) != 0;
#else
    int accepting = 0;
    socklen_t size = sizeof(accepting);
    return getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &size) == 0 && size == sizeof(accepting) && accepting != 0;
#endif
}

static int listener_is_held(control_listener *listener) {
    if (listener->fd < 0 || !lock_is_held(listener->lock)) return 0;
    struct stat transport, entry;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    socklen_t address_size = sizeof(address);
    return fstat(listener->fd, &transport) == 0 && S_ISSOCK(transport.st_mode) &&
        same_inode(&transport, &listener->transport) && stream_socket(listener->fd) &&
        listening_socket(listener->fd) &&
        getsockname(listener->fd, (struct sockaddr *)&address, &address_size) == 0 &&
        memchr(address.sun_path, '\0', sizeof(address.sun_path)) != NULL && strcmp(address.sun_path, listener->path) == 0 &&
        fstatat(listener->lock->runtime_fd, CONTROL_SOCKET_NAME, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_socket(&entry) && same_inode(&entry, &listener->entry);
}

static int peer_credentials(int fd, pid_t *pid, uid_t *uid, gid_t *gid) {
#ifdef __APPLE__
    socklen_t size = sizeof(*pid);
    return getpeereid(fd, uid, gid) == 0 &&
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, pid, &size) == 0 && size == sizeof(*pid) && *pid > 0;
#else
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 || size != sizeof(credentials) || credentials.pid <= 0) return 0;
    *pid = credentials.pid; *uid = credentials.uid; *gid = credentials.gid;
    return 1;
#endif
}

static int peer_is_held(control_peer *peer) {
    if (peer->fd < 0 || !listener_is_held(peer->listener)) return 0;
    struct stat socket;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    struct pollfd status = {peer->fd, POLLIN, 0};
    int polled;
    do { polled = poll(&status, 1, 0); } while (polled < 0 && errno == EINTR);
    if (polled < 0 || (status.revents & (POLLHUP | POLLERR | POLLNVAL))) return 0;
    /* Peek does not compete with Node's duplicate for bytes. A FIN with no
     * unread data is positive closure; EAGAIN is a live idle connection. */
    char byte;
    ssize_t read;
    do { read = recv(peer->fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT); } while (read < 0 && errno == EINTR);
    if (read == 0 || (read < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) return 0;
    return fstat(peer->fd, &socket) == 0 && S_ISSOCK(socket.st_mode) && same_inode(&socket, &peer->socket) &&
        stream_socket(peer->fd) && peer_credentials(peer->fd, &pid, &uid, &gid) &&
        pid == peer->pid && uid == peer->uid && gid == peer->gid && uid == geteuid();
}

static int same_image(const struct stat *left, const struct stat *right) {
#ifdef __APPLE__
    const struct timespec lm = left->st_mtimespec, rm = right->st_mtimespec;
    const struct timespec lc = left->st_ctimespec, rc = right->st_ctimespec;
#else
    const struct timespec lm = left->st_mtim, rm = right->st_mtim;
    const struct timespec lc = left->st_ctim, rc = right->st_ctim;
#endif
    return S_ISREG(left->st_mode) && same_inode(left, right) && left->st_size > 0 &&
        left->st_size <= CONTROL_IMAGE_MAX_BYTES && left->st_size == right->st_size &&
        left->st_mode == right->st_mode && left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
        left->st_nlink == right->st_nlink && lm.tv_sec == rm.tv_sec && lm.tv_nsec == rm.tv_nsec &&
        lc.tv_sec == rc.tv_sec && lc.tv_nsec == rc.tv_nsec;
}

/* A native-derived absolute executable locator, never caller input. Each
 * ancestor and the final regular image are opened no-follow. */
static int open_image_path(const char *path) {
    if (path[0] != '/' || strlen(path) >= PATH_MAX) return -1;
    char parent[PATH_MAX];
    memcpy(parent, path, strlen(path) + 1);
    char *name = strrchr(parent, '/');
    if (!name || name[1] == '\0') return -1;
    const char *base = path + (name - parent) + 1;
    int directory;
    if (name == parent) directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    else { *name = '\0'; directory = open_root(parent); }
    if (directory < 0) return -1;
    int fd = openat(directory, base, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    close(directory);
    return fd;
}

#ifdef __APPLE__
static int mapped_image(pid_t pid, const char *path, const struct stat *image) {
    uint64_t address = 0;
    for (int count = 0; count < CONTROL_IMAGE_MAX_REGIONS; count++) {
        struct proc_regionwithpathinfo region;
        memset(&region, 0, sizeof(region));
        if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &region, sizeof(region)) != sizeof(region)) return 0;
        const struct proc_regioninfo *info = &region.prp_prinfo;
        const struct vnode_info_path *vnode = &region.prp_vip;
        if ((info->pri_protection & VM_PROT_EXECUTE) &&
            memchr(vnode->vip_path, '\0', sizeof(vnode->vip_path)) && strcmp(vnode->vip_path, path) == 0) {
            return vnode->vip_vi.vi_stat.vst_dev == (uint32_t)image->st_dev &&
                vnode->vip_vi.vi_stat.vst_ino == image->st_ino;
        }
        if (info->pri_size == 0 || info->pri_address < address || UINT64_MAX - info->pri_address < info->pri_size) return 0;
        address = info->pri_address + info->pri_size;
    }
    return 0;
}
#endif

/* Opens the peer's actual native executable and independently checks its
 * native path. Deleted/replaced images, credentials drift, hidden procfs and
 * unavailable VM-region inspection are all indeterminate, never authority. */
static int open_peer_image(control_peer *peer, char path[PATH_MAX], struct stat *image) {
    int fd = -1, named = -1;
#ifdef __APPLE__
    struct proc_bsdinfo process;
    memset(&process, 0, sizeof(process));
    if (proc_pidinfo(peer->pid, PROC_PIDTBSDINFO, 0, &process, sizeof(process)) != sizeof(process) ||
        process.pbi_pid != (uint32_t)peer->pid || process.pbi_uid != peer->uid || process.pbi_gid != peer->gid ||
        proc_pidpath(peer->pid, path, PATH_MAX) <= 0 || !memchr(path, '\0', PATH_MAX)) return -1;
    fd = open_image_path(path);
    if (fd < 0 || fstat(fd, image) < 0 || !same_image(image, image) || !mapped_image(peer->pid, path, image)) goto fail;
#else
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%ld", (long)peer->pid);
    int process = open(proc_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (process < 0) return -1;
    struct statfs filesystem;
    if (fstatfs(process, &filesystem) < 0 || filesystem.f_type != PROC_SUPER_MAGIC) { close(process); return -1; }
    int status_fd = openat(process, "status", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *status = status_fd < 0 ? NULL : fdopen(status_fd, "r");
    if (!status) { if (status_fd >= 0) close(status_fd); close(process); return -1; }
    char line[4096];
    int uid_matches = 0, gid_matches = 0;
    while (fgets(line, sizeof(line), status)) {
        unsigned long first, effective, saved, filesystem_id;
        if (strncmp(line, "Uid:", 4) == 0 && sscanf(line + 4, "%lu %lu %lu %lu", &first, &effective, &saved, &filesystem_id) == 4)
            uid_matches = effective == peer->uid;
        if (strncmp(line, "Gid:", 4) == 0 && sscanf(line + 4, "%lu %lu %lu %lu", &first, &effective, &saved, &filesystem_id) == 4)
            gid_matches = effective == peer->gid;
    }
    int failed = ferror(status);
    fclose(status);
    ssize_t length = readlinkat(process, "exe", path, PATH_MAX - 1);
    if (!failed && uid_matches && gid_matches && length > 0 && length < PATH_MAX - 1) {
        path[length] = '\0';
        /* Only this verified procfs kernel entry is intentionally followed. */
        fd = openat(process, "exe", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    }
    close(process);
    if (fd < 0 || fstat(fd, image) < 0 || !same_image(image, image)) goto fail;
    named = open_image_path(path);
    struct stat named_image;
    if (named < 0 || fstat(named, &named_image) < 0 || !same_image(image, &named_image)) goto fail;
    close(named);
#endif
    return fd;
fail:
    if (named >= 0) close(named);
    if (fd >= 0) close(fd);
    return -1;
}

static void close_observation(control_observation *observation) {
    if (observation->image_fd >= 0) close(observation->image_fd);
    observation->image_fd = -1;
    if (observation->peer) {
        control_observation **slot = &observation->peer->observations;
        while (*slot && *slot != observation) slot = &(*slot)->next;
        if (*slot) *slot = observation->next;
        observation->peer = NULL;
    }
    if (observation->peer_ref) { napi_delete_reference(observation->env, observation->peer_ref); observation->peer_ref = NULL; }
}

static void finalize_observation(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    close_observation(data);
    free(data);
}

static void close_peer(control_peer *peer) {
    if (peer->fd >= 0) { shutdown(peer->fd, SHUT_RDWR); close(peer->fd); peer->fd = -1; }
    while (peer->observations) close_observation(peer->observations);
}

static void finalize_peer(napi_env env, void *data, void *hint) {
    (void)hint;
    control_peer *peer = data;
    control_listener *listener = peer->listener;
    close_peer(peer);
    control_peer **slot = &peer->listener->peers;
    while (*slot && *slot != peer) slot = &(*slot)->next;
    if (*slot) *slot = peer->next;
    if (peer->listener_ref) napi_delete_reference(env, peer->listener_ref);
    free(peer);
    free_listener_if_done(listener);
}

static void *unwrap_control(napi_env env, napi_callback_info info, const napi_type_tag *tag, const char *error) {
    napi_value self;
    bool matches = false;
    void *data = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, self, &data) != napi_ok || !data) { native_error(env, error); return NULL; }
    return data;
}

static napi_value undefined_result(napi_env env) {
    napi_value value;
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}

static napi_value release_observation(napi_env env, napi_callback_info info) {
    control_observation *observation = unwrap_control(env, info, &observation_tag, "invalid control observation handle");
    if (!observation) return NULL;
    close_observation(observation);
    return undefined_result(env);
}

static napi_value release_peer(napi_env env, napi_callback_info info) {
    control_peer *peer = unwrap_control(env, info, &peer_tag, "invalid control peer handle");
    if (!peer) return NULL;
    close_peer(peer);
    return undefined_result(env);
}

static napi_value take_socket_fd(napi_env env, napi_callback_info info) {
    control_peer *peer = unwrap_control(env, info, &peer_tag, "invalid control peer handle");
    if (!peer) return NULL;
    if (peer->transferred || !peer_is_held(peer)) return native_error(env, "control socket transfer is unavailable or already consumed");
    int fd = fcntl(peer->fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0 || !socket_flags(fd)) { if (fd >= 0) close(fd); return native_error(env, "control socket transfer failed"); }
    napi_value value;
    if (napi_create_int32(env, fd, &value) != napi_ok) { close(fd); return NULL; }
    peer->transferred = 1;
    return value;
}

static int uint_member(napi_env env, napi_value object, const char *name, uint32_t number) {
    napi_value value;
    return napi_create_uint32(env, number, &value) == napi_ok && napi_set_named_property(env, object, name, value) == napi_ok;
}

static int observation_is_held(control_peer *peer, control_observation *observation) {
    if (observation->peer != peer || observation->image_fd < 0 || !peer_is_held(peer)) return 0;
    struct stat held, current;
    char token[128], path[PATH_MAX];
    if (fstat(observation->image_fd, &held) < 0 || !same_image(&held, &observation->image) ||
        observe_process(peer->pid, token) != 1 || strcmp(token, peer->start_token) != 0) return 0;
    int fd = open_peer_image(peer, path, &current);
    int valid = fd >= 0 && strcmp(path, observation->image_path) == 0 && same_image(&current, &held);
    if (fd >= 0) close(fd);
    return valid && observe_process(peer->pid, token) == 1 && strcmp(token, peer->start_token) == 0 && peer_is_held(peer);
}

static napi_value assert_observation(napi_env env, napi_callback_info info) {
    control_peer *peer = unwrap_control(env, info, &peer_tag, "invalid control peer handle");
    if (!peer) return NULL;
    size_t argc = 2;
    napi_value argv[2];
    bool matches = false;
    control_observation *observation = NULL;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 1 ||
        napi_check_object_type_tag(env, argv[0], &observation_tag, &matches) != napi_ok || !matches ||
        napi_unwrap(env, argv[0], (void **)&observation) != napi_ok || !observation || !observation_is_held(peer, observation))
        return native_error(env, "control peer observation closed, drifted, or unavailable");
    return undefined_result(env);
}

static napi_value capture_peer(napi_env env, napi_callback_info info) {
    control_peer *peer = unwrap_control(env, info, &peer_tag, "invalid control peer handle");
    if (!peer) return NULL;
    if (!peer_is_held(peer)) return native_error(env, "control peer is closed, drifted, or unavailable");
    char token[128];
    if (observe_process(peer->pid, token) != 1 || strcmp(token, peer->start_token) != 0)
        return native_error(env, "control peer process observation is unavailable or changed since acceptance");
    control_observation *observation = calloc(1, sizeof(*observation));
    if (!observation) return native_error(env, "control peer observation allocation failed");
    observation->env = env; observation->image_fd = -1;
    observation->image_fd = open_peer_image(peer, observation->image_path, &observation->image);
    if (observation->image_fd < 0 || (peer->has_image && !same_image(&observation->image, &peer->image))) goto fail;
    if (!peer->has_image) { peer->image = observation->image; peer->has_image = 1; }
    napi_value self;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_create_reference(env, self, 1, &observation->peer_ref) != napi_ok) goto fail;
    observation->peer = peer; observation->next = peer->observations; peer->observations = observation;
    if (!observation_is_held(peer, observation)) goto fail;
    napi_value result, start, fd, bytes;
    const napi_property_descriptor methods[] = {{"close", NULL, release_observation, NULL, NULL, NULL, napi_default, NULL}};
    if (napi_create_object(env, &result) != napi_ok || !uint_member(env, result, "pid", peer->pid) ||
        !uint_member(env, result, "uid", peer->uid) || !uint_member(env, result, "gid", peer->gid) ||
        !identity_member(env, result, "listener", &peer->listener->entry) || !identity_member(env, result, "acceptedSocket", &peer->socket) ||
        napi_create_string_utf8(env, peer->start_token, NAPI_AUTO_LENGTH, &start) != napi_ok ||
        napi_set_named_property(env, result, "processStartToken", start) != napi_ok ||
        napi_create_int32(env, observation->image_fd, &fd) != napi_ok || napi_set_named_property(env, result, "imageFd", fd) != napi_ok ||
        napi_create_double(env, observation->image.st_size, &bytes) != napi_ok || napi_set_named_property(env, result, "imageByteCount", bytes) != napi_ok ||
        napi_define_properties(env, result, 1, methods) != napi_ok || napi_type_tag_object(env, result, &observation_tag) != napi_ok ||
        napi_object_freeze(env, result) != napi_ok || napi_wrap(env, result, observation, finalize_observation, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    finalize_observation(env, observation, NULL);
    return native_error(env, "control peer image, process, credentials, or descriptor observation failed");
}

static napi_value create_peer(napi_env env, control_listener *listener, int fd, control_peer **created) {
    *created = NULL;
    control_peer *peer = calloc(1, sizeof(*peer));
    if (!peer) { close(fd); return NULL; }
    peer->env = env; peer->listener = listener; peer->fd = fd;
    if (!socket_flags(fd) || fstat(fd, &peer->socket) < 0 || !S_ISSOCK(peer->socket.st_mode) ||
        !peer_credentials(fd, &peer->pid, &peer->uid, &peer->gid) || peer->uid != geteuid() ||
        observe_process(peer->pid, peer->start_token) != 1) { close(fd); free(peer); return NULL; }
    /* Anchor this accepted peer before giving JS an idle connection. A passed
     * client descriptor can outlive its original process; the first eventual
     * frame must compare this token, never adopt a reused numeric pid. */
    char token[128];
    if (!peer_is_held(peer) || observe_process(peer->pid, token) != 1 || strcmp(token, peer->start_token) != 0) {
        close(fd); free(peer); return NULL;
    }
    peer->next = listener->peers; listener->peers = peer;
    napi_value result, owner;
    const napi_property_descriptor methods[] = {
        {"takeSocketFd", NULL, take_socket_fd, NULL, NULL, NULL, napi_default, NULL},
        {"capture", NULL, capture_peer, NULL, NULL, NULL, napi_default, NULL},
        {"assertObservation", NULL, assert_observation, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, release_peer, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_get_reference_value(env, listener->self_ref, &owner) != napi_ok ||
        napi_create_reference(env, owner, 1, &peer->listener_ref) != napi_ok || napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &peer_tag) != napi_ok || napi_object_freeze(env, result) != napi_ok ||
        napi_wrap(env, result, peer, finalize_peer, NULL, NULL) != napi_ok) { finalize_peer(env, peer, NULL); return NULL; }
    *created = peer;
    return result;
}

static void free_listener_if_done(control_listener *listener) {
    /* Environment finalizers are independently ordered even when JS strong
     * refs exist. Every peer must unlink before the listener can be freed. */
    if (!listener->finalized || listener->peers || (listener->poll_initialized && !listener->poll_closed)) return;
    if (listener->lock_ref) napi_delete_reference(listener->env, listener->lock_ref);
    free(listener);
}

static void poll_closed(uv_handle_t *handle) {
    control_listener *listener = handle->data;
    listener->poll_closed = 1;
    napi_async_cleanup_hook_handle cleanup = listener->cleanup_handle;
    listener->cleanup_handle = NULL;
    free_listener_if_done(listener);
    if (cleanup) napi_remove_async_cleanup_hook(cleanup);
}

static void cleanup_listener(napi_async_cleanup_hook_handle handle, void *data) {
    (void)handle;
    close_listener(data);
}

static void close_listener(control_listener *listener) {
    if (listener->fd < 0) return;
    int fd = listener->fd;
    listener->fd = -1;
    if (listener->poll_initialized) { uv_poll_stop(&listener->poll); uv_close((uv_handle_t *)&listener->poll, poll_closed); }
    for (control_peer *peer = listener->peers; peer; peer = peer->next) close_peer(peer);
    close(fd);
    /* A replaced path is not ours to delete. Check private parent authority and
     * the exact socket inode; never remove a symlink or permission drift. */
    struct stat entry;
    if (lock_is_held(listener->lock) && fstatat(listener->lock->runtime_fd, CONTROL_SOCKET_NAME, &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_socket(&entry) && same_inode(&entry, &listener->entry)) {
        unlinkat(listener->lock->runtime_fd, CONTROL_SOCKET_NAME, 0);
        sync_directory(listener->lock->runtime_fd);
    }
    control_listener **slot = &listener->lock->listeners;
    while (*slot && *slot != listener) slot = &(*slot)->next;
    if (*slot) *slot = listener->next;
    /* Keep the async cleanup hook until poll_closed even after explicit close.
     * Worker termination can otherwise invalidate env between uv_close and
     * the callback which finally releases the lock reference. */
    if (listener->accept_ref) { napi_delete_reference(listener->env, listener->accept_ref); listener->accept_ref = NULL; }
    if (listener->error_ref) { napi_delete_reference(listener->env, listener->error_ref); listener->error_ref = NULL; }
    if (listener->self_ref) { napi_delete_reference(listener->env, listener->self_ref); listener->self_ref = NULL; }
}

static void close_lock_listeners(state_lock *lock) {
    while (lock->listeners) close_listener(lock->listeners);
}

static void finalize_listener(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    control_listener *listener = data;
    close_listener(listener);
    listener->finalized = 1;
    free_listener_if_done(listener);
}

static napi_value assert_listener(napi_env env, napi_callback_info info) {
    control_listener *listener = unwrap_control(env, info, &listener_tag, "invalid control listener handle");
    if (!listener) return NULL;
    if (!listener_is_held(listener)) return native_error(env, "control listener descriptor or named identity changed or closed");
    return undefined_result(env);
}

static napi_value release_listener(napi_env env, napi_callback_info info) {
    control_listener *listener = unwrap_control(env, info, &listener_tag, "invalid control listener handle");
    if (!listener) return NULL;
    close_listener(listener);
    return undefined_result(env);
}

static void fatal_pending_exception(napi_env env) {
    bool pending = false;
    napi_value exception;
    if (napi_is_exception_pending(env, &pending) == napi_ok && pending &&
        napi_get_and_clear_last_exception(env, &exception) == napi_ok) napi_fatal_exception(env, exception);
}

static void fail_listener(control_listener *listener) {
    napi_env env = listener->env;
    napi_value callback, receiver, message, error, ignored;
    int ready = listener->error_ref && napi_get_reference_value(env, listener->error_ref, &callback) == napi_ok &&
        napi_get_global(env, &receiver) == napi_ok &&
        napi_create_string_utf8(env, "control listener unavailable or descriptor identity changed", NAPI_AUTO_LENGTH, &message) == napi_ok &&
        napi_create_error(env, NULL, message, &error) == napi_ok;
    close_listener(listener);
    if (ready) napi_make_callback(env, NULL, receiver, callback, 1, &error, &ignored);
    fatal_pending_exception(env);
}

static void accept_ready(uv_poll_t *poll, int status, int events) {
    control_listener *listener = poll->data;
    napi_env env = listener->env;
    napi_handle_scope scope;
    if (napi_open_handle_scope(env, &scope) != napi_ok) { close_listener(listener); return; }
    if (status < 0 || !(events & UV_READABLE) || !listener_is_held(listener)) { fail_listener(listener); goto done; }
    for (int count = 0; count < CONTROL_ACCEPT_BURST && listener->fd >= 0; count++) {
        int fd = accept(listener->fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            fail_listener(listener); break;
        }
        if (!listener_is_held(listener)) { close(fd); fail_listener(listener); break; }
        control_peer *peer;
        napi_value connection = create_peer(env, listener, fd, &peer), callback, receiver, ignored;
        if (!connection) { fatal_pending_exception(env); continue; }
        if (napi_get_reference_value(env, listener->accept_ref, &callback) != napi_ok ||
            napi_get_global(env, &receiver) != napi_ok ||
            napi_make_callback(env, NULL, receiver, callback, 1, &connection, &ignored) != napi_ok) {
            close_peer(peer); fatal_pending_exception(env);
        }
    }
done:
    napi_close_handle_scope(env, scope);
}

/* A dead predecessor may leave a socket entry. Only ECONNREFUSED is positive
 * absence of a listener; a live endpoint, symlink, wrong owner/mode or any
 * indeterminate error is never removed. There is no directory scan/fallback. */
static int remove_stale_socket(control_listener *listener) {
    state_lock *lock = listener->lock;
    struct stat prior, current;
    if (fstatat(lock->runtime_fd, CONTROL_SOCKET_NAME, &prior, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT;
    if (!private_socket(&prior) || !lock_is_held(lock)) return 0;
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0 || !socket_flags(probe)) { if (probe >= 0) close(probe); return 0; }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, listener->path, strlen(listener->path) + 1);
    int connected = connect(probe, (struct sockaddr *)&address, sizeof(address));
    int failure = errno;
    close(probe);
    return connected < 0 && failure == ECONNREFUSED && lock_is_held(lock) &&
        fstatat(lock->runtime_fd, CONTROL_SOCKET_NAME, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        private_socket(&current) && same_inode(&prior, &current) &&
        unlinkat(lock->runtime_fd, CONTROL_SOCKET_NAME, 0) == 0 && sync_directory(lock->runtime_fd);
}

static napi_value open_control_listener(napi_env env, napi_callback_info info) {
    state_lock *lock = unwrap_lock(env, info);
    if (!lock) return NULL;
    size_t argc = 3;
    napi_value argv[3], self;
    napi_valuetype first, second;
    if (napi_get_cb_info(env, info, &argc, argv, &self, NULL) != napi_ok || argc != 2 ||
        napi_typeof(env, argv[0], &first) != napi_ok || first != napi_function ||
        napi_typeof(env, argv[1], &second) != napi_ok || second != napi_function || !lock_is_held(lock) || lock->listeners)
        return native_error(env, "control listener requires the held StateOwner and two callbacks");
    control_listener *listener = calloc(1, sizeof(*listener));
    if (!listener) return native_error(env, "control listener allocation failed");
    listener->env = env; listener->lock = lock; listener->fd = -1;
    const char *error = "fixed control socket path exceeds platform limit";
    int length = snprintf(listener->path, sizeof(listener->path), "%s/runtime/%s", lock->path, CONTROL_SOCKET_NAME);
    if (length <= 0 || (size_t)length >= sizeof(listener->path)) goto fail;
    error = "existing control socket is live, unsafe, or unavailable";
    if (!remove_stale_socket(listener)) goto fail;
    error = "cannot create private control listener";
    listener->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener->fd < 0 || !socket_flags(listener->fd)) goto fail;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    memcpy(address.sun_path, listener->path, strlen(listener->path) + 1);
    if (!lock_is_held(lock)) goto fail;
    /* bind has no permission argument and Mac cannot open the named socket.
     * Worker environments can execute native callbacks on different threads,
     * so a synchronous JS callback alone does not serialize save/restore. No
     * JS callback or async work is allowed inside this mutex-held interval. */
    error = "control socket permission bracket acquisition failed";
    int acquired = pthread_mutex_lock(&control_bind_mutex);
    if (acquired != 0) { errno = acquired; goto fail; }
    /* Read the prior mask by tightening first, never by temporarily clearing
     * restrictions. An existing private layout can reopen even when the host
     * now denies owner read/write; do not relax that mask to create a socket. */
    mode_t prior_mask = umask(0777);
    int compatible_mask = (prior_mask & 0600) == 0;
    int bound = -1, failure = EPERM;
    if (compatible_mask) {
        umask(0177);
        bound = bind(listener->fd, (struct sockaddr *)&address, sizeof(address));
        failure = errno;
    }
    umask(prior_mask);
    int released = pthread_mutex_unlock(&control_bind_mutex);
    error = "control socket permission bracket release failed";
    if (released != 0) { errno = released; goto fail; }
    errno = failure;
    error = "control socket requires a host umask that permits owner read and write";
    if (!compatible_mask) goto fail;
    error = "control socket bind failed";
    if (bound < 0) goto fail;
    error = "control socket named entry is not private or StateOwner changed";
    if (fstatat(lock->runtime_fd, CONTROL_SOCKET_NAME, &listener->entry, AT_SYMLINK_NOFOLLOW) < 0 ||
        !private_socket(&listener->entry) || !lock_is_held(lock)) goto fail;
    error = "control socket listening transport setup failed";
    if (fstat(listener->fd, &listener->transport) < 0 || listen(listener->fd, 128) < 0) goto fail;
    error = "control socket named entry or listening transport identity differs";
    if (!listener_is_held(listener)) goto fail;
    error = "control socket directory durability failed";
    if (!sync_directory(lock->runtime_fd)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, assert_listener, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, release_listener, NULL, NULL, NULL, napi_default, NULL}
    };
    error = "control listener handle or event loop setup failed";
    uv_loop_t *loop;
    if (napi_create_reference(env, self, 1, &listener->lock_ref) != napi_ok ||
        napi_create_reference(env, argv[0], 1, &listener->accept_ref) != napi_ok ||
        napi_create_reference(env, argv[1], 1, &listener->error_ref) != napi_ok ||
        napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &listener_tag) != napi_ok || napi_object_freeze(env, result) != napi_ok ||
        napi_get_uv_event_loop(env, &loop) != napi_ok || uv_poll_init(loop, &listener->poll, listener->fd) != 0) goto fail;
    listener->poll_initialized = 1; listener->poll.data = listener;
    if (napi_create_reference(env, result, 1, &listener->self_ref) != napi_ok ||
        napi_add_async_cleanup_hook(env, cleanup_listener, listener, &listener->cleanup_handle) != napi_ok) goto fail;
    if (uv_poll_start(&listener->poll, UV_READABLE, accept_ready) != 0) goto fail;
    if (napi_wrap(env, result, listener, finalize_listener, NULL, NULL) != napi_ok) goto fail;
    listener->next = lock->listeners; lock->listeners = listener;
    return result;
fail:
    finalize_listener(env, listener, NULL);
    return native_error(env, error);
}
