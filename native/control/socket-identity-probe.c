#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
/* A disposable OS characterization, not a listener/authentication backend.
 * The JS runner owns and removes the unique temporary parent directory. */
static void identity(const struct stat *info) {
#ifdef __APPLE__
    unsigned long long device = (uint32_t)info->st_dev;
#else
    unsigned long long device = info->st_dev;
#endif
    printf("{\"deviceId\":\"%llu\",\"fileId\":\"%llu\",\"ownerUid\":%u,\"mode\":%u,\"isSocket\":%s}",
        device, (unsigned long long)info->st_ino, info->st_uid,
        info->st_mode & 07777, S_ISSOCK(info->st_mode) ? "true" : "false");
}

static int same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int peer_credentials(int fd, pid_t *pid, uid_t *uid, gid_t *gid) {
#ifdef __APPLE__
    socklen_t size = sizeof(*pid);
    return getpeereid(fd, uid, gid) == 0 &&
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, pid, &size) == 0 && size == sizeof(*pid);
#else
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 || size != sizeof(peer)) return 0;
    *pid = peer.pid; *uid = peer.uid; *gid = peer.gid;
    return 1;
#endif
}

int main(int argc, char **argv) {
    int root = -1, runtime = -1, listener = -1, client = -1, accepted = -1, path_fd = -1, replacement = -1;
    const char *failure = "invalid probe directory";
    if (argc != 2) goto fail;
    root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat root_info;
    if (root < 0 || fstat(root, &root_info) < 0 || root_info.st_uid != geteuid() ||
        (root_info.st_mode & 07777) != 0700) goto fail;
    failure = "cannot create private probe runtime";
    if (mkdirat(root, "runtime", 0700) < 0) goto fail;
    runtime = openat(root, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (runtime < 0) goto fail;

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    int length = snprintf(address.sun_path, sizeof(address.sun_path), "%s/runtime/control-v1.sock", argv[1]);
    failure = "probe path exceeds the platform Unix socket limit";
    if (length < 0 || (size_t)length >= sizeof(address.sun_path)) goto fail;
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    failure = "cannot bind the probe Unix stream socket";
    if (listener < 0) goto fail;
    mode_t previous_mask = umask(0177);
    int bound = bind(listener, (struct sockaddr *)&address, sizeof(address));
    int bind_errno = errno;
    umask(previous_mask);
    errno = bind_errno;
    if (bound < 0 || listen(listener, 1) < 0) goto fail;

    struct stat path_info, listener_info, accepted_info;
    failure = "cannot observe the listener and pathname independently";
    if (fstatat(runtime, "control-v1.sock", &path_info, AT_SYMLINK_NOFOLLOW) < 0 ||
        fstat(listener, &listener_info) < 0 || !S_ISSOCK(path_info.st_mode) ||
        (path_info.st_mode & 07777) != 0600 || !S_ISSOCK(listener_info.st_mode)) goto fail;
    errno = 0;
    int chmod_result = fchmod(listener, 0600), chmod_errno = errno;
#ifdef __APPLE__
    path_fd = openat(runtime, "control-v1.sock", O_EVTONLY | O_NOFOLLOW | O_CLOEXEC);
#else
    path_fd = openat(runtime, "control-v1.sock", O_PATH | O_NOFOLLOW | O_CLOEXEC);
#endif
    int path_errno = path_fd < 0 ? errno : 0;
    struct stat held_path;
    failure = "opened path descriptor differs from the endpoint";
    if (path_fd >= 0 && (fstat(path_fd, &held_path) < 0 || !same_identity(&path_info, &held_path))) goto fail;

    client = socket(AF_UNIX, SOCK_STREAM, 0);
    failure = "cannot establish the probe connection";
    if (client < 0 || connect(client, (struct sockaddr *)&address, sizeof(address)) < 0) goto fail;
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || fstat(accepted, &accepted_info) < 0) goto fail;
    pid_t pid, repeated_pid; uid_t uid, repeated_uid; gid_t gid, repeated_gid;
    failure = "native peer credential samples disagree with the probe process";
    if (!peer_credentials(accepted, &pid, &uid, &gid) ||
        !peer_credentials(accepted, &repeated_pid, &repeated_uid, &repeated_gid) ||
        pid != getpid() || uid != geteuid() || gid != getegid() ||
        repeated_pid != pid || repeated_uid != uid || repeated_gid != gid) goto fail;

    failure = "cannot characterize endpoint replacement";
    if (renameat(runtime, "control-v1.sock", runtime, "original.sock") < 0) goto fail;
    replacement = socket(AF_UNIX, SOCK_STREAM, 0);
    if (replacement < 0 || bind(replacement, (struct sockaddr *)&address, sizeof(address)) < 0) goto fail;
    struct stat replaced_path, retained_listener;
    if (fstatat(runtime, "control-v1.sock", &replaced_path, AT_SYMLINK_NOFOLLOW) < 0 ||
        fstat(listener, &retained_listener) < 0) goto fail;
    struct utsname system;
    if (uname(&system) < 0) goto fail;

    printf("{\"schemaVersion\":1,\"platform\":\"%s\",\"kernelRelease\":\"%s\",\"endpoint\":",
#ifdef __APPLE__
        "macos",
#else
        "linux",
#endif
        system.release);
    identity(&path_info);
    printf(",\"listenerDescriptor\":"); identity(&listener_info);
    printf(",\"acceptedDescriptor\":"); identity(&accepted_info);
    printf(",\"socketFchmod\":{\"succeeded\":%s,\"errno\":%d},\"endpointDescriptorOpen\":{\"succeeded\":%s,\"errno\":%d},",
        chmod_result == 0 ? "true" : "false", chmod_result < 0 ? chmod_errno : 0,
        path_fd >= 0 ? "true" : "false", path_errno);
    printf("\"peerSamplesMatchSelf\":true,\"namespaceAndListenerIdentityEqual\":%s,\"replacementChangesEndpointIdentity\":%s,\"replacementPreservesListenerIdentity\":%s}\n",
        same_identity(&path_info, &listener_info) ? "true" : "false",
        !same_identity(&path_info, &replaced_path) ? "true" : "false",
        same_identity(&listener_info, &retained_listener) ? "true" : "false");
    if (path_fd >= 0) close(path_fd);
    close(replacement); close(accepted); close(client); close(listener); close(runtime); close(root);
    return 0;
fail:
    fprintf(stderr, "%s (errno=%d: %s)\n", failure, errno, strerror(errno));
    if (path_fd >= 0) close(path_fd);
    if (replacement >= 0) close(replacement);
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    if (runtime >= 0) close(runtime);
    if (root >= 0) close(root);
    return 1;
}
