#define _GNU_SOURCE
/* Test-only OS diagnostic. Not a production launcher, StateOwner, signed
 * installation, or durable worker-birth/death evidence. The caller is a real
 * systemd user-service under an independently disposable, non-root UID.
 *
 * argv: CONTROLLER_LEAF NODE SCRIPT controller WORKER_LEAF empty|live
 * fd 3: Node's connected Unix-stream IPC channel (stdio: 'ipc', JSON mode).
 * The launcher stays in the Supervisor service. Only its actual child is born
 * in the held anchor leaf; the launcher closes its IPC copy and reaps that child.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CGROUP_MOUNT "/sys/fs/cgroup"
#define PROBE_PATH_BYTES 4096

static int failure(const char *operation, int error) {
    fprintf(stderr, "anchor birth probe: %s (errno=%d: %s)\n", operation, error, strerror(error));
    return error == EACCES || error == EPERM ? 77 : error == ENOSYS ? 69 : 70;
}

/* Consume before close, never retry a possibly reused descriptor. All errors
 * fail this diagnostic; no result is used to mint production authority. */
static bool retire(int *fd) {
    int owned = *fd;
    *fd = -1;
    return owned < 0 || close(owned) == 0;
}

static bool absolute_path(const char *path) {
    size_t length = strnlen(path, PROBE_PATH_BYTES);
    if (length < 2 || length == PROBE_PATH_BYTES || path[0] != '/') return false;
    const char *component = path + 1;
    for (const char *cursor = component; ; cursor++) {
        if (*cursor != '/' && *cursor != '\0') continue;
        size_t bytes = (size_t)(cursor - component);
        if (bytes == 0 || (bytes == 1 && component[0] == '.') ||
            (bytes == 2 && component[0] == '.' && component[1] == '.')) return false;
        if (*cursor == '\0') return true;
        component = cursor + 1;
    }
}

static bool cgroup_path(const char *path) {
    return absolute_path(path) && strncmp(path, CGROUP_MOUNT "/", sizeof(CGROUP_MOUNT)) == 0;
}

static bool same_directory(const struct stat *a, const struct stat *b) {
    return S_ISDIR(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_mode == b->st_mode;
}

static int open_cgroup(const char *path) {
    if (!cgroup_path(path)) { errno = EINVAL; return -1; }
    int current = open(CGROUP_MOUNT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return -1;
    struct statfs filesystem;
    if (fstatfs(current, &filesystem) != 0 || filesystem.f_type != CGROUP2_SUPER_MAGIC) {
        int error = errno ? errno : EINVAL;
        if (!retire(&current)) error = errno;
        errno = error; return -1;
    }
    char relative[PROBE_PATH_BYTES];
    memcpy(relative, path + sizeof(CGROUP_MOUNT), strlen(path + sizeof(CGROUP_MOUNT)) + 1);
    char *save = NULL;
    for (char *part = strtok_r(relative, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        int next = openat(current, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int error = errno;
        if (!retire(&current)) {
            error = errno;
            if (!retire(&next)) error = errno;
            errno = error; return -1;
        }
        if (next < 0) { errno = error; return -1; }
        current = next;
    }
    return current;
}

static bool read_bounded(int directory, const char *name, char *buffer, size_t capacity) {
    int file = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file < 0) return false;
    size_t used = 0;
    bool valid = true;
    while (used < capacity - 1) {
        ssize_t bytes = read(file, buffer + used, capacity - 1 - used);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) { valid = false; break; }
        if (bytes == 0) break;
        used += (size_t)bytes;
    }
    if (valid && used == capacity - 1) {
        char extra;
        ssize_t bytes;
        do { bytes = read(file, &extra, 1); } while (bytes < 0 && errno == EINTR);
        if (bytes != 0) { if (bytes > 0) errno = EOVERFLOW; valid = false; }
    }
    int error = errno;
    if (!retire(&file)) { error = errno; valid = false; }
    buffer[used] = '\0';
    errno = error;
    return valid;
}

static bool whitespace_only(const char *text) {
    for (; *text; text++) if (!isspace((unsigned char)*text)) return false;
    return true;
}

static bool empty_domain_leaf(int directory, struct stat *identity) {
    struct statfs filesystem;
    char value[PROBE_PATH_BYTES];
    if (fstat(directory, identity) != 0 || fstatfs(directory, &filesystem) != 0) return false;
    if (!S_ISDIR(identity->st_mode) || filesystem.f_type != CGROUP2_SUPER_MAGIC ||
        identity->st_uid != geteuid() || (identity->st_mode & 07777) != 0700) { errno = EINVAL; return false; }
    if (!read_bounded(directory, "cgroup.type", value, sizeof(value))) return false;
    if (strcmp(value, "domain\n") != 0) { errno = EINVAL; return false; }
    if (!read_bounded(directory, "cgroup.subtree_control", value, sizeof(value))) return false;
    if (!whitespace_only(value)) { errno = EBUSY; return false; }
    if (!read_bounded(directory, "cgroup.procs", value, sizeof(value))) return false;
    if (!whitespace_only(value)) { errno = EBUSY; return false; }
    int copy = fcntl(directory, F_DUPFD_CLOEXEC, 4);
    if (copy < 0) return false;
    DIR *entries = fdopendir(copy);
    if (!entries) { int error = errno; if (!retire(&copy)) error = errno; errno = error; return false; }
    bool valid = true;
    size_t count = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(entries))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (++count > 512) { errno = EOVERFLOW; valid = false; break; }
        struct stat child;
        if (fstatat(directory, entry->d_name, &child, AT_SYMLINK_NOFOLLOW) != 0) { valid = false; break; }
        if (S_ISDIR(child.st_mode)) { errno = EBUSY; valid = false; break; }
        errno = 0;
    }
    int error = errno;
    if (error != 0) valid = false;
    if (closedir(entries) != 0) { error = errno; valid = false; }
    errno = error;
    return valid;
}

static bool node_ipc(void) {
    const char *channel = getenv("NODE_CHANNEL_FD");
    const char *serialization = getenv("NODE_CHANNEL_SERIALIZATION_MODE");
    int type;
    socklen_t bytes = sizeof(type);
    struct sockaddr_un local, peer;
    socklen_t local_bytes = sizeof(local), peer_bytes = sizeof(peer);
    if (!channel || strcmp(channel, "3") != 0 || (serialization && strcmp(serialization, "json") != 0)) {
        errno = EINVAL; return false;
    }
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) if (fcntl(fd, F_GETFD) < 0) return false;
    if (getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &bytes) != 0 ||
        getsockname(3, (struct sockaddr *)&local, &local_bytes) != 0 ||
        getpeername(3, (struct sockaddr *)&peer, &peer_bytes) != 0) return false;
    if (bytes != sizeof(type) || type != SOCK_STREAM || local.sun_family != AF_UNIX || peer.sun_family != AF_UNIX) {
        errno = EINVAL; return false;
    }
    return true;
}

static bool placed_child(pid_t child, const char *path, int held, const struct stat *identity) {
    char process_path[64], membership[PROBE_PATH_BYTES];
    int length = snprintf(process_path, sizeof(process_path), "/proc/%ld", (long)child);
    if (length < 1 || (size_t)length >= sizeof(process_path)) { errno = EOVERFLOW; return false; }
    int process = open(process_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (process < 0) return false;
    struct stat process_identity, current, named_identity;
    struct statfs filesystem;
    bool valid = fstat(process, &process_identity) == 0 && process_identity.st_uid == geteuid() &&
        fstatfs(process, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC &&
        read_bounded(process, "cgroup", membership, sizeof(membership));
    int error = errno;
    if (!retire(&process)) { error = errno; valid = false; }
    if (valid) {
        size_t bytes = strlen(membership);
        if (bytes > 0 && membership[bytes - 1] == '\n') membership[--bytes] = '\0';
        valid = strncmp(membership, "0::", 3) == 0 && strcmp(membership + 3, path + strlen(CGROUP_MOUNT)) == 0;
        if (!valid) error = EINVAL;
    }
    int named = valid ? open_cgroup(path) : -1;
    if (valid) {
        valid = named >= 0 && fstat(held, &current) == 0 && fstat(named, &named_identity) == 0 &&
            same_directory(identity, &current) && same_directory(identity, &named_identity);
        if (!valid) error = errno ? errno : EINVAL;
    }
    if (!retire(&named)) { error = errno; valid = false; }
    errno = error;
    return valid;
}

int main(int argc, char **argv) {
    if (argc != 7 || !cgroup_path(argv[1]) || !absolute_path(argv[2]) || !absolute_path(argv[3]) ||
        strcmp(argv[4], "controller") != 0 || !cgroup_path(argv[5]) ||
        (strcmp(argv[6], "empty") != 0 && strcmp(argv[6], "live") != 0) ||
        geteuid() == 0 || geteuid() != getuid() || getegid() != getgid()) return failure("invalid non-root diagnostic invocation", EINVAL);
    if (!node_ipc()) return failure("expected Node JSON IPC on fd 3", errno);
    struct sigaction action;
    memset(&action, 0, sizeof(action)); sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &action, NULL) != 0) return failure("exclusive child reaping unavailable", errno);
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) return failure("gate error reporting unavailable", errno);
    if (syscall(SYS_close_range, 4U, UINT_MAX, 0U) != 0) return failure("inherited descriptor retirement unavailable", errno);
    int node = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (node < 0) return failure("Node image unavailable", errno);
    struct stat image, script;
    if (fstat(node, &image) != 0 || !S_ISREG(image.st_mode) || image.st_nlink != 1 ||
        (image.st_mode & 06022) != 0 || (image.st_mode & 0111) == 0 ||
        lstat(argv[3], &script) != 0 || !S_ISREG(script.st_mode) || script.st_uid != 0 ||
        script.st_nlink != 1 || (script.st_mode & 0222) != 0) {
        int error = errno ? errno : EINVAL; if (!retire(&node)) error = errno;
        return failure("expected fixed executable and root-owned read-only script", error);
    }
    int destination = open_cgroup(argv[1]);
    struct stat identity;
    if (destination < 0 || !empty_domain_leaf(destination, &identity)) {
        int error = errno; if (!retire(&destination)) error = errno; if (!retire(&node)) error = errno;
        return failure("private empty controller leaf unavailable", error);
    }
    int gate[2] = { -1, -1 };
    if (pipe2(gate, O_CLOEXEC) != 0) {
        int error = errno; if (!retire(&destination)) error = errno; if (!retire(&node)) error = errno;
        return failure("placement gate unavailable", error);
    }
    struct clone_args birth;
    memset(&birth, 0, sizeof(birth));
    birth.flags = CLONE_INTO_CGROUP;
    birth.exit_signal = SIGCHLD;
    birth.cgroup = (uint64_t)destination;
    pid_t child = (pid_t)syscall(SYS_clone3, &birth, sizeof(birth));
    if (child < 0) {
        int error = errno;
        if (!retire(&gate[0])) error = errno;
        if (!retire(&gate[1])) error = errno;
        if (!retire(&destination)) error = errno;
        if (!retire(&node)) error = errno;
        return failure("clone3(CLONE_INTO_CGROUP); no fork/migration fallback", error);
    }
    if (child == 0) {
        if (!retire(&gate[1]) || !retire(&destination)) _exit(70);
        char go;
        ssize_t bytes;
        do { bytes = read(gate[0], &go, 1); } while (bytes < 0 && errno == EINTR);
        if (bytes != 1 || go != '1' || !retire(&gate[0]) || fcntl(3, F_SETFD, 0) != 0) _exit(70);
        if ((node > 4 && syscall(SYS_close_range, 4U, (unsigned int)node - 1, 0U) != 0) ||
            syscall(SYS_close_range, (unsigned int)node + 1, UINT_MAX, 0U) != 0) _exit(70);
        char *const arguments[] = { argv[2], argv[3], argv[4], argv[5], argv[6], NULL };
        char *const environment[] = { "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
            "NODE_CHANNEL_FD=3", "NODE_CHANNEL_SERIALIZATION_MODE=json", NULL };
        fexecve(node, arguments, environment);
        static const char message[] = "anchor birth probe: controller exec failed\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        _exit(127);
    }
    int channel = 3, error = 0;
    if (!retire(&channel)) error = errno;
    if (!retire(&gate[0])) error = errno;
    if (!retire(&node)) error = errno;
    if (error == 0 && !placed_child(child, argv[1], destination, &identity)) error = errno ? errno : EINVAL;
    if (error == 0) {
        ssize_t sent;
        do { sent = write(gate[1], "1", 1); } while (sent < 0 && errno == EINTR);
        if (sent != 1) error = errno ? errno : EIO;
    }
    if (!retire(&gate[1])) error = errno;
    /* On any failure, terminate the exclusive unreaped child before joining:
     * do not depend on an uncertain gate close producing EOF. SIGCHLD is not
     * auto-reaped, so this PID cannot be recycled before our exact waitpid.
     * On success, Node IPC belongs only to the real controller: a Supervisor
     * crash closes its peer even if this waitpid launcher has not exited. */
    if (error != 0 && kill(child, SIGKILL) != 0 && errno != ESRCH) error = errno;
    int status = 0;
    pid_t joined;
    do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
    if (joined != child) error = errno ? errno : ECHILD;
    if (!retire(&destination)) error = errno;
    if (error != 0) return failure("exact controller placement/retirement failed", error);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return failure("controller did not terminalize", ECHILD);
}
