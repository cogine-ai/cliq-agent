#define _GNU_SOURCE
#include "worker-common.h"
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>

#define CGROUP2_MAGIC 0x63677270
#define EXT4_MAGIC 0xef53
#define MAX_OBSERVATION_PIDS 4096
#define OBSERVATION_TIMEOUT_MS 5000

/* Private rejection diagnostics; every nonzero status still fails closed. */
enum spawn_rejection {
    CLIQ_SPAWN_INPUT_GATE = 1001,
    CLIQ_SPAWN_CGROUP_CREATE = 1002,
    CLIQ_SPAWN_CGROUP_RESOURCES = 1003,
    CLIQ_SPAWN_PROCESS_GROUP = 1004,
    CLIQ_SPAWN_STDIO = 1005,
    CLIQ_SPAWN_CHANNEL = 1006,
    CLIQ_SPAWN_FORK = 1007,
    CLIQ_SPAWN_MONITOR_TOKEN = 1008,
    CLIQ_SPAWN_MONITOR_PLACEMENT = 1009,
    CLIQ_SPAWN_INITIAL_SEND = 1010,
    CLIQ_SPAWN_READY_WAIT = 1011,
    CLIQ_SPAWN_READY_RECEIVE = 1012,
    CLIQ_SPAWN_PROCESS_INSPECTION = 1013,
    CLIQ_SPAWN_IDENTITY_TOKEN = 1014,
    CLIQ_SPAWN_READY_RECEIVE_IMAGE_EOF = 1015
};

struct scope {
    bool created, active, released, stopped, invocation;
    unsigned int parent;
    int cgroup, process_group, channel, stdout_fd, stderr_fd;
    pid_t monitor, init, worker;
    char monitor_start_token[CLIQ_WORKER_TOKEN_BYTES];
    struct cliq_worker_packet identity;
};
static struct scope scopes[CLIQ_WORKER_MAX_SCOPES];
static volatile sig_atomic_t shutdown_requested;

static void request_shutdown(int signal_number) {
    (void)signal_number;
    int saved = errno;
    if (!shutdown_requested) { shutdown_requested = 1; close(CLIQ_WORKER_CHANNEL_FD); }
    errno = saved;
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool readable(int fd, int timeout) {
    struct pollfd observed = { .fd = fd, .events = POLLIN };
    int ready;
    do { ready = poll(&observed, 1, timeout); } while (ready < 0 && errno == EINTR && !shutdown_requested);
    return ready == 1 && (observed.revents & POLLIN) != 0;
}

static bool write_control(int directory, const char *name, const char *text) {
    int fd = openat(directory, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t length = strlen(text);
    ssize_t written;
    do { written = write(fd, text, length); } while (written < 0 && errno == EINTR);
    bool ok = written == (ssize_t)length;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool cgroup_empty(int directory) {
    char buffer[512];
    int fd = openat(directory, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0) return false;
    buffer[length] = '\0';
    return strncmp(buffer, "populated 0\n", 12) == 0 || strstr(buffer, "\npopulated 0\n") != NULL;
}

static bool native_cgroup(int directory) {
    struct stat metadata; struct statfs filesystem;
    return fstat(directory, &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
        metadata.st_uid == geteuid() && (metadata.st_mode & 0022) == 0 &&
        fstatfs(directory, &filesystem) == 0 && filesystem.f_type == CGROUP2_MAGIC;
}

static bool valid_cgroup_name(const char *name) {
    return strnlen(name, 96) == 69 && memcmp(name, "cliq-", 5) == 0 && cliq_hex_digest(name + 5);
}

static bool generation_matches(int fd, const struct cliq_worker_packet *request) {
    struct stat metadata; struct statfs filesystem;
    if (fstat(fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() || (metadata.st_mode & 0777) != 0700 ||
        (uint64_t)metadata.st_dev != request->generation_device ||
        (uint64_t)metadata.st_ino != request->generation_inode ||
        fstatfs(fd, &filesystem) != 0 || filesystem.f_type != EXT4_MAGIC || filesystem.f_bsize <= 0 || filesystem.f_blocks <= 0) return false;
    /* A dedicated bounded filesystem is the currently supported quota shape.
     * Free space is not a quota. Ordinary StateRoot filesystem capacity fails. */
    uint64_t blocks = (uint64_t)filesystem.f_blocks, size = (uint64_t)filesystem.f_bsize;
    return size <= UINT64_MAX / blocks && blocks * size <= request->max_generation_bytes;
}

static bool scope_process_current(const struct scope *scope) {
    char filename[128], token[CLIQ_WORKER_TOKEN_BYTES]; struct stat image, runtime, namespace;
    if (!cliq_process_token(scope->worker, token) || strcmp(token, scope->identity.start_token) != 0) return false;
    snprintf(filename, sizeof(filename), "/proc/%ld/exe", (long)scope->worker);
    if (stat(filename, &image) != 0 || !S_ISREG(image.st_mode)) return false;
    snprintf(filename, sizeof(filename), "/proc/%ld/root/runtime/%s", (long)scope->worker,
        scope->invocation ? "cliq-linux-edit" : "cliq-linux-worker");
    if (stat(filename, &runtime) != 0 || runtime.st_dev != image.st_dev || runtime.st_ino != image.st_ino) return false;
    snprintf(filename, sizeof(filename), "/proc/%ld/ns/pid", (long)scope->worker);
    return stat(filename, &namespace) == 0 && (uint64_t)namespace.st_ino == scope->identity.pid_namespace_inode &&
        cliq_generation_mount(scope->worker, scope->identity.generation_device, scope->identity.generation_inode, !scope->invocation) &&
        cliq_process_token(scope->worker, token) && strcmp(token, scope->identity.start_token) == 0;
}

static bool resources(int root, const struct cliq_worker_packet *request) {
    if (request->max_processes < 3 || request->max_processes > 1024 ||
        request->memory_bytes < UINT64_C(268435456) || request->memory_bytes > UINT64_C(34359738368) ||
        request->cpu_quota < 10000 || request->cpu_quota > 1600000 ||
        request->max_open_files < 64 || request->max_open_files > 8192 ||
        request->max_file_bytes < 1048576 || request->max_file_bytes > UINT64_C(17179869184) ||
        request->max_generation_bytes < UINT64_C(268435456) || request->max_generation_bytes > UINT64_C(107374182400) ||
        request->max_output_bytes < 65536 || request->max_output_bytes > 67108864) return false;
    char value[96];
    snprintf(value, sizeof(value), "%llu", (unsigned long long)request->max_processes);
    if (!write_control(root, "pids.max", value)) return false;
    snprintf(value, sizeof(value), "%llu", (unsigned long long)request->memory_bytes);
    if (!write_control(root, "memory.max", value) || !write_control(root, "memory.swap.max", "0")) return false;
    snprintf(value, sizeof(value), "%llu 1000000", (unsigned long long)request->cpu_quota);
    return write_control(root, "cpu.max", value);
}

static bool configure_limits(const struct cliq_worker_packet *request) {
    struct rlimit descriptors = { (rlim_t)request->max_open_files, (rlim_t)request->max_open_files };
    struct rlimit bytes = { (rlim_t)request->max_file_bytes, (rlim_t)request->max_file_bytes };
    struct rlimit core = { 0, 0 };
    return setrlimit(RLIMIT_NOFILE, &descriptors) == 0 && setrlimit(RLIMIT_FSIZE, &bytes) == 0 &&
        setrlimit(RLIMIT_CORE, &core) == 0 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}

static bool close_above_channel(void) { return cliq_close_range(4, UINT_MAX); }

/* Same installed controller image, executed as PID 1 by --as-pid-1. No user
 * source is loaded until all host generation/cgroup/runtime FDs are closed. */
static int namespace_init(void) {
    if (!close_above_channel() || getpid() != 1 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 70;
    struct cliq_worker_packet request;
    int passed[5]; size_t count;
    if (!cliq_receive(3, &request, passed, &count) ||
        (request.command != CLIQ_CREATE_WORKER && request.command != CLIQ_CREATE_WRITE) ||
        count != (request.command == CLIQ_CREATE_WRITE ? 1U : 0U)) return 70;
    bool invocation = request.command == CLIQ_CREATE_WRITE;
    int input = invocation ? passed[0] : -1;
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) return 70;
    pid_t worker = fork();
    if (worker < 0) return 70;
    if (worker == 0) {
        close(channel[0]);
        if (dup2(channel[1], 3) < 0) _exit(70);
        if (!close_above_channel()) _exit(70);
        char *const arguments[] = { invocation ? "/runtime/cliq-linux-edit" : "/runtime/cliq-linux-worker", NULL };
        char *const environment[] = { "LANG=C", "LC_ALL=C", "HOME=/home/cliq", "TMPDIR=/tmp", "PATH=/runtime", NULL };
        execve(arguments[0], arguments, environment);
        _exit(70);
    }
    close(channel[1]);
    bool sent = cliq_send(channel[0], &request, input >= 0 ? &input : NULL, input >= 0 ? 1 : 0);
    if (input >= 0) close(input);
    if (!sent || !readable(channel[0], OBSERVATION_TIMEOUT_MS)) return 70;
    struct cliq_worker_packet ready;
    if (!cliq_receive(channel[0], &ready, passed, &count) || count != 0 || ready.command != CLIQ_WORKER_READY) return 70;
    ready.namespace_init_pid = 1;
    struct stat namespace;
    if (!cliq_process_token(1, ready.init_start_token) || stat("/proc/self/ns/pid", &namespace) != 0) return 70;
    ready.pid_namespace_inode = (uint64_t)namespace.st_ino;
    if (!cliq_send(3, &ready, NULL, 0)) return 70;
    bool active = false;
    for (;;) {
        if (!cliq_receive(3, &request, passed, &count) || count != 0) break;
        if (request.command == CLIQ_ACTIVATE_WORKER && !invocation && !active) {
            if (!cliq_send(channel[0], &request, NULL, 0) || !readable(channel[0], OBSERVATION_TIMEOUT_MS) ||
                !cliq_receive(channel[0], &ready, passed, &count) || count != 0 || ready.command != CLIQ_WORKER_ACTIVATED) break;
            active = true;
            if (!cliq_send(3, &ready, NULL, 0)) break;
        } else if (request.command == CLIQ_RELEASE_WRITE && invocation && !active) {
            active = true;
            if (!cliq_send(channel[0], &request, NULL, 0) || !readable(channel[0], OBSERVATION_TIMEOUT_MS) ||
                !cliq_receive(channel[0], &ready, passed, &count) || count != 0 || ready.command != CLIQ_WRITE_RESULT ||
                !cliq_send(3, &ready, NULL, 0)) break;
            while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {}
        } else break;
    }
    close(channel[0]);
    /* PID 1 exit is a kernel-wide namespace stop, never a death receipt. The
     * out-of-containment controller still observes cgroup zero and reaping. */
    kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) { errno = 0; }
    return 0;
}

static bool inspect_processes(struct scope *scope, const struct cliq_worker_packet *ready) {
    char buffer[MAX_OBSERVATION_PIDS * 12];
    int procs = openat(scope->process_group, "cgroup.procs", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (procs < 0) return false;
    ssize_t length = read(procs, buffer, sizeof(buffer) - 1);
    close(procs);
    if (length <= 0 || (size_t)length == sizeof(buffer) - 1) return false;
    buffer[length] = '\0';
    size_t observed = 0;
    for (char *cursor = buffer; *cursor;) {
        char *end; errno = 0;
        long number = strtol(cursor, &end, 10);
        if (errno || end == cursor || *end != '\n' || number <= 0 || number > INT32_MAX || ++observed > MAX_OBSERVATION_PIDS) return false;
        char token[CLIQ_WORKER_TOKEN_BYTES], namespace_path[64]; struct stat ns; pid_t namespace_pid;
        if (!cliq_process_token((pid_t)number, token)) return false;
        snprintf(namespace_path, sizeof(namespace_path), "/proc/%ld/ns/pid", number);
        if (stat(namespace_path, &ns) == 0 && (uint64_t)ns.st_ino == ready->pid_namespace_inode) {
            if (!cliq_namespace_pid((pid_t)number, &namespace_pid)) return false;
            if (namespace_pid == 1 && strcmp(token, ready->init_start_token) == 0) scope->init = (pid_t)number;
            else if (namespace_pid == 2 && strcmp(token, ready->start_token) == 0) scope->worker = (pid_t)number;
            else return false;
        }
        cursor = end + 1;
    }
    return scope->init > 0 && scope->worker > 0 && scope->init != scope->worker;
}

static bool spawn_worker(struct cliq_worker_packet *request, int passed[5], size_t count,
                          struct cliq_worker_packet *response) {
    response->status = CLIQ_SPAWN_INPUT_GATE;
    if (count != 5) return false;
    bool invocation = request->command == CLIQ_CREATE_WRITE;
    bool parent_ok = invocation ? request->parent > 0 && request->parent < CLIQ_WORKER_MAX_SCOPES &&
        scopes[request->parent].created && scopes[request->parent].active && !scopes[request->parent].stopped &&
        !scopes[request->parent].invocation : request->parent == 0;
    int cgroup_parent = invocation && parent_ok ? scopes[request->parent].cgroup : passed[1];
    int helper_image = passed[invocation ? 1 : 2], executable_image = passed[invocation ? 2 : 3],
        bwrap_image = passed[invocation ? 3 : 4], input = invocation ? passed[4] : -1;
    /* [DEBUG-i1-image-offset] Observe, never rewind, the reused helper before
     * this spawn. A failed READY is distinct when its input already was EOF. */
    struct stat helper_metadata;
    bool helper_at_eof = fstat(helper_image, &helper_metadata) == 0 && helper_metadata.st_size > 0 &&
        lseek(helper_image, 0, SEEK_CUR) == helper_metadata.st_size;
    if (count != 5 || request->scope == 0 || request->scope >= CLIQ_WORKER_MAX_SCOPES || !parent_ok ||
        !valid_cgroup_name(request->cgroup_name) || !cliq_hex_digest(request->nonce) ||
        !cliq_hex_digest(request->activation_nonce) || scopes[request->scope].created ||
        !native_cgroup(cgroup_parent) || !generation_matches(passed[0], request)) return false;
    if (invocation) for (unsigned int i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) {
        if (scopes[i].created && scopes[i].invocation && scopes[i].parent == request->parent && !scopes[i].stopped) return false;
    }
    if (invocation && (request->generation_device != scopes[request->parent].identity.generation_device ||
        request->generation_inode != scopes[request->parent].identity.generation_inode)) return false;
    struct scope *scope = &scopes[request->scope];
    scope->invocation = invocation; scope->parent = request->parent;
    response->status = CLIQ_SPAWN_CGROUP_CREATE;
    if (mkdirat(cgroup_parent, request->cgroup_name, 0700) != 0) return false;
    scope->cgroup = openat(cgroup_parent, request->cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    scope->created = scope->cgroup >= 0;
    response->status = CLIQ_SPAWN_CGROUP_RESOURCES;
    if (!scope->created || !native_cgroup(scope->cgroup) || !cgroup_empty(scope->cgroup) ||
        !resources(scope->cgroup, request)) return false;
    response->status = CLIQ_SPAWN_PROCESS_GROUP;
    if (!invocation && (!write_control(scope->cgroup, "cgroup.subtree_control", "+cpu +memory +pids") ||
        mkdirat(scope->cgroup, "worker", 0700) != 0)) return false;
    scope->process_group = invocation ? fcntl(scope->cgroup, F_DUPFD_CLOEXEC, 0) :
        openat(scope->cgroup, "worker", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scope->process_group < 0 || !native_cgroup(scope->process_group)) return false;
    struct stat cgroup;
    if (fstat(scope->cgroup, &cgroup) != 0) return false;
    response->status = CLIQ_SPAWN_STDIO;
    scope->stdout_fd = memfd_create("cliq-scope-stdout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    scope->stderr_fd = memfd_create("cliq-scope-stderr", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (scope->stdout_fd < 0 || scope->stderr_fd < 0 ||
        ftruncate(scope->stdout_fd, (off_t)(request->max_output_bytes / 2)) != 0 ||
        ftruncate(scope->stderr_fd, (off_t)(request->max_output_bytes / 2)) != 0 ||
        fcntl(scope->stdout_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) != 0 ||
        fcntl(scope->stderr_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) != 0) return false;
    int channel[2], barrier[2];
    response->status = CLIQ_SPAWN_CHANNEL;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) return false;
    if (pipe2(barrier, O_CLOEXEC) != 0) { close(channel[0]); close(channel[1]); return false; }
    response->status = CLIQ_SPAWN_FORK;
    scope->monitor = fork();
    if (scope->monitor < 0) { close(channel[0]); close(channel[1]); close(barrier[0]); close(barrier[1]); return false; }
    if (scope->monitor == 0) {
        close(channel[0]); close(barrier[1]);
        char go;
        if (read(barrier[0], &go, 1) != 1 || go != '1' ||
            dup2(scope->stdout_fd, 1) < 0 || dup2(scope->stderr_fd, 2) < 0 || !configure_limits(request)) _exit(70);
        close(barrier[0]);
        if (dup2(channel[1], 3) < 0) _exit(70);
        int generation = fcntl(passed[0], F_DUPFD, 20), helper = fcntl(helper_image, F_DUPFD, 20),
            worker = fcntl(executable_image, F_DUPFD, 20), bwrap = fcntl(bwrap_image, F_DUPFD_CLOEXEC, 20);
        if (generation < 0 || helper < 0 || worker < 0 || bwrap < 0) _exit(70);
        char source[64], helper_fd[24], worker_fd[24];
        snprintf(source, sizeof(source), "/proc/self/fd/%d", generation);
        snprintf(helper_fd, sizeof(helper_fd), "%d", helper);
        snprintf(worker_fd, sizeof(worker_fd), "%d", worker);
        int keep[] = { generation, helper, worker, bwrap };
        unsigned int first = 4;
        for (size_t i = 0; i < 4; i++) {
            if ((unsigned int)keep[i] < first || !cliq_close_range(first, (unsigned int)keep[i] - 1)) _exit(70);
            first = (unsigned int)keep[i] + 1;
        }
        if (!cliq_close_range(first, UINT_MAX)) _exit(70);
        char *const arguments[] = { "bwrap", "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid",
            "--as-pid-1", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
            "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--clearenv",
            "--tmpfs", "/", "--dir", "/runtime", "--perms", "0555", "--ro-bind-data", helper_fd, "/runtime/cliq-linux-worker-init",
            "--perms", "0555", "--ro-bind-data", worker_fd, invocation ? "/runtime/cliq-linux-edit" : "/runtime/cliq-linux-worker",
            invocation ? "--bind" : "--ro-bind", source, "/work",
            "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/cliq",
            "--chdir", "/work", "--", "/runtime/cliq-linux-worker-init", NULL };
        char *const environment[] = { "LANG=C", "LC_ALL=C", NULL };
        fexecve(bwrap, arguments, environment);
        _exit(70);
    }
    close(channel[1]); close(barrier[0]);
    scope->channel = channel[0];
    response->status = CLIQ_SPAWN_MONITOR_TOKEN;
    if (!cliq_process_token(scope->monitor, scope->monitor_start_token)) { close(barrier[1]); return false; }
    char pid_text[32]; snprintf(pid_text, sizeof(pid_text), "%ld", (long)scope->monitor);
    response->status = CLIQ_SPAWN_MONITOR_PLACEMENT;
    bool placed = write_control(scope->process_group, "cgroup.procs", pid_text);
    bool started = placed && write(barrier[1], "1", 1) == 1;
    close(barrier[1]);
    if (!started) return false;
    response->status = CLIQ_SPAWN_INITIAL_SEND;
    if (!cliq_send(scope->channel, request, input >= 0 ? &input : NULL, input >= 0 ? 1 : 0)) return false;
    response->status = CLIQ_SPAWN_READY_WAIT;
    if (!readable(scope->channel, OBSERVATION_TIMEOUT_MS)) return false;
    struct cliq_worker_packet ready; int extra[5]; size_t extras;
    response->status = CLIQ_SPAWN_READY_RECEIVE;
    if (!cliq_receive(scope->channel, &ready, extra, &extras) || extras != 0 || ready.command != CLIQ_WORKER_READY) {
        if (helper_at_eof) response->status = CLIQ_SPAWN_READY_RECEIVE_IMAGE_EOF;
        return false;
    }
    response->status = CLIQ_SPAWN_PROCESS_INSPECTION;
    if (!inspect_processes(scope, &ready)) return false;
    scope->identity = ready;
    scope->identity.scope = request->scope;
    scope->identity.cgroup_inode = (uint64_t)cgroup.st_ino;
    scope->identity.pid = scope->worker;
    scope->identity.namespace_init_pid = scope->init;
    scope->identity.monitor_pid = scope->monitor;
    memcpy(scope->identity.monitor_start_token, scope->monitor_start_token, sizeof(scope->monitor_start_token));
    memcpy(scope->identity.init_native_start_token, ready.init_start_token, sizeof(ready.init_start_token));
    response->status = CLIQ_SPAWN_IDENTITY_TOKEN;
    char init_start_token[CLIQ_WORKER_TOKEN_BYTES] = {0};
    int token_length = snprintf(init_start_token, sizeof(init_start_token),
        "linux-namespace-init:%ld:%s:monitor:%ld:%s", (long)scope->init,
        ready.init_start_token + strlen("linux-proc-start-ticks:"), (long)scope->monitor,
        scope->monitor_start_token + strlen("linux-proc-start-ticks:"));
    if (token_length < 0 || (size_t)token_length >= sizeof(init_start_token)) return false;
    memcpy(scope->identity.init_start_token, init_start_token, sizeof(init_start_token));
    scope->identity.generation_device = request->generation_device;
    scope->identity.generation_inode = request->generation_inode;
    memcpy(scope->identity.nonce, request->nonce, sizeof(request->nonce));
    memcpy(scope->identity.activation_nonce, request->activation_nonce, sizeof(request->activation_nonce));
    memcpy(scope->identity.cgroup_name, request->cgroup_name, sizeof(request->cgroup_name));
    *response = scope->identity;
    response->status = 0;
    return true;
}

static bool original_process_absent(pid_t pid, const char *token) {
    char current[CLIQ_WORKER_TOKEN_BYTES];
    if (cliq_process_token(pid, current)) return strcmp(current, token) != 0;
    char name[64]; struct stat process;
    snprintf(name, sizeof(name), "/proc/%ld", (long)pid);
    return stat(name, &process) < 0 && errno == ENOENT;
}

static bool stop_retained_subreaper(pid_t pid, const char *token) {
#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    /* Retained authority is a frozen token, never a current numeric PID.
     * Hold the kernel process reference before rechecking it; signal only
     * through that reference, even if the process exits during the checks. */
    int process = (int)syscall(SYS_pidfd_open, pid, 0);
    if (process < 0) return false;
    char current[CLIQ_WORKER_TOKEN_BYTES], filename[64]; struct stat owner;
    snprintf(filename, sizeof(filename), "/proc/%ld", (long)pid);
    bool valid = cliq_process_token(pid, current) && strcmp(current, token) == 0 &&
        stat(filename, &owner) == 0 && owner.st_uid == geteuid() &&
        cliq_process_token(pid, current) && strcmp(current, token) == 0 &&
        syscall(SYS_pidfd_send_signal, process, SIGTERM, NULL, 0) == 0;
    if (close(process) != 0) valid = false;
    return valid;
#else
    (void)pid; (void)token; errno = ENOSYS; return false;
#endif
}

struct tracked_process { pid_t pid; char token[CLIQ_WORKER_TOKEN_BYTES]; };
struct tracked_set { size_t count; struct tracked_process process[MAX_OBSERVATION_PIDS]; };

static bool track_process(struct tracked_set *set, pid_t pid, const char *token) {
    if (pid <= 0 || !*token) return false;
    for (size_t i = 0; i < set->count; i++) {
        if (set->process[i].pid == pid) return strcmp(set->process[i].token, token) == 0;
    }
    if (set->count == MAX_OBSERVATION_PIDS) return false;
    set->process[set->count].pid = pid;
    memcpy(set->process[set->count++].token, token, CLIQ_WORKER_TOKEN_BYTES); return true;
}

/* Snapshot every currently populated descendant cgroup before kill. Known
 * original monitor/init/worker tokens are added separately, because Linux's
 * populated flag and cgroup.procs intentionally omit zombies. */
static bool collect_processes(int directory, struct tracked_set *set, unsigned int depth) {
    if (depth > 4 || !native_cgroup(directory)) return false;
    char buffer[MAX_OBSERVATION_PIDS * 12];
    int fd = openat(directory, "cgroup.procs", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1); close(fd);
    if (length < 0 || (size_t)length == sizeof(buffer) - 1) return false;
    buffer[length] = '\0';
    for (char *cursor = buffer; *cursor;) {
        char *end; errno = 0; long pid = strtol(cursor, &end, 10);
        if (errno || end == cursor || *end != '\n' || pid <= 0 || pid > INT32_MAX) return false;
        char token[CLIQ_WORKER_TOKEN_BYTES] = {0};
        if (!cliq_process_token((pid_t)pid, token)) {
            char filename[64]; struct stat process; snprintf(filename, sizeof(filename), "/proc/%ld", pid);
            if (stat(filename, &process) == 0 || errno != ENOENT) return false;
        } else if (!track_process(set, (pid_t)pid, token)) return false;
        cursor = end + 1;
    }
    int duplicate = fcntl(directory, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) return false;
    DIR *entries = fdopendir(duplicate);
    if (!entries) { close(duplicate); return false; }
    bool valid = true; size_t directories = 0;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) valid = false; break; }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        struct stat metadata;
        if (fstatat(directory, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) { valid = false; break; }
        if (!S_ISDIR(metadata.st_mode)) continue;
        if (++directories > CLIQ_WORKER_MAX_SCOPES ||
            (strcmp(entry->d_name, "worker") != 0 && !valid_cgroup_name(entry->d_name))) { valid = false; break; }
        int child = openat(directory, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        bool observed = child >= 0 && collect_processes(child, set, depth + 1);
        if (child >= 0) close(child);
        if (!observed) { valid = false; break; }
    }
    closedir(entries); return valid;
}

static bool tracked_absent(const struct tracked_set *set) {
    for (size_t i = 0; i < set->count; i++) {
        if (!original_process_absent(set->process[i].pid, set->process[i].token)) return false;
    }
    return true;
}

static bool stop_scope(unsigned int id, struct cliq_worker_packet *response) {
    if (id == 0 || id >= CLIQ_WORKER_MAX_SCOPES || !scopes[id].created) return false;
    struct scope *scope = &scopes[id];
    if (scope->stopped) { *response = scope->identity; response->command = CLIQ_STOP_SCOPE; return true; }
    scope->active = false;
    struct tracked_set tracked = {0};
    if (!collect_processes(scope->cgroup, &tracked, 0) ||
        !track_process(&tracked, scope->monitor, scope->monitor_start_token) ||
        !track_process(&tracked, scope->init, scope->identity.init_native_start_token) ||
        !track_process(&tracked, scope->worker, scope->identity.start_token)) return false;
    for (unsigned int child = 1; child < CLIQ_WORKER_MAX_SCOPES; child++) {
        struct scope *descendant = &scopes[child];
        if (descendant->created && descendant->parent == id && !descendant->stopped &&
            (!track_process(&tracked, descendant->monitor, descendant->monitor_start_token) ||
             !track_process(&tracked, descendant->init, descendant->identity.init_native_start_token) ||
             !track_process(&tracked, descendant->worker, descendant->identity.start_token))) return false;
    }
    if (scope->channel >= 0) { close(scope->channel); scope->channel = -1; }
    if (!write_control(scope->cgroup, "cgroup.kill", "1")) return false;
    int64_t start = milliseconds(); if (start < 0) return false;
    int64_t deadline = start + OBSERVATION_TIMEOUT_MS;
    for (;;) {
        int64_t now = milliseconds(); if (now < 0 || now > deadline) break;
        int status; pid_t reaped;
        do { reaped = waitpid(-1, &status, WNOHANG); } while (reaped > 0);
        if (cgroup_empty(scope->cgroup) && tracked_absent(&tracked)) {
            scope->stopped = true;
            scope->identity.populated = 0;
            scope->identity.init_reaped = 1;
            scope->identity.remaining_descendants = 0;
            *response = scope->identity;
            response->command = CLIQ_STOP_SCOPE;
            return true;
        }
        struct timespec delay = { 0, 10000000 }; nanosleep(&delay, NULL);
    }
    return false;
}

static bool terminate_retained(struct cliq_worker_packet *request, int directory, struct cliq_worker_packet *response) {
    struct stat metadata;
    if (!native_cgroup(directory) || !valid_cgroup_name(request->cgroup_name)) return false;
    int scope = openat(directory, request->cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scope < 0) return false;
    bool valid = native_cgroup(scope) && fstat(scope, &metadata) == 0 && (uint64_t)metadata.st_ino == request->cgroup_inode;
    struct tracked_set tracked = {0};
    valid = valid && collect_processes(scope, &tracked, 0) &&
        track_process(&tracked, (pid_t)request->pid, request->start_token) &&
        track_process(&tracked, (pid_t)request->namespace_init_pid, request->init_native_start_token) &&
        track_process(&tracked, (pid_t)request->monitor_pid, request->monitor_start_token);
    /* A new controller does not adopt old execution. It only requests old
     * trusted subreaper shutdown, kills the held exact hierarchy, and waits
     * until original process tokens disappear from /proc (including zombies). */
    if (valid && !original_process_absent((pid_t)request->subreaper_pid, request->subreaper_start_token)) {
        valid = stop_retained_subreaper((pid_t)request->subreaper_pid, request->subreaper_start_token);
    }
    if (valid) valid = write_control(scope, "cgroup.kill", "1");
    int64_t start = milliseconds(); if (start < 0) { close(scope); return false; }
    int64_t deadline = start + OBSERVATION_TIMEOUT_MS;
    while (valid) {
        int64_t now = milliseconds(); if (now < 0 || now > deadline) break;
        if (native_cgroup(scope) && cgroup_empty(scope) && tracked_absent(&tracked)) {
            *response = *request; response->populated = 0; response->init_reaped = 1; response->remaining_descendants = 0;
            close(scope); return true;
        }
        struct timespec delay = { 0, 10000000 }; nanosleep(&delay, NULL);
    }
    close(scope); return false;
}

static void stop_everything(void) {
    /* Kill all populated roots first; cleanup is not serial productive work. */
    for (unsigned int id = 1; id < CLIQ_WORKER_MAX_SCOPES; id++) {
        if (scopes[id].created) (void)write_control(scopes[id].cgroup, "cgroup.kill", "1");
    }
    for (unsigned int id = 1; id < CLIQ_WORKER_MAX_SCOPES; id++) {
        if (scopes[id].created) {
            struct cliq_worker_packet ignored;
            (void)stop_scope(id, &ignored);
            /* stop_scope already killed the held hierarchy and may have
             * reaped its monitor. A stale numeric PID is not signal authority. */
        }
    }
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

static int controller(void) {
    umask(0077);
    for (size_t i = 0; i < CLIQ_WORKER_MAX_SCOPES; i++) {
        scopes[i].cgroup = -1; scopes[i].process_group = -1; scopes[i].channel = -1;
        scopes[i].stdout_fd = -1; scopes[i].stderr_fd = -1;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 70;
    struct sigaction action; memset(&action, 0, sizeof(action)); action.sa_handler = request_shutdown;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    struct cliq_worker_packet hello = cliq_packet(CLIQ_CONTROLLER_HELLO);
    hello.pid = getpid();
    if (!cliq_process_token(getpid(), hello.start_token) || !cliq_send(3, &hello, NULL, 0)) return 70;
    while (!shutdown_requested) {
        struct cliq_worker_packet request, response; int passed[5]; size_t count;
        if (!cliq_receive(3, &request, passed, &count)) break;
        response = cliq_packet(request.command); response.scope = request.scope;
        bool ok = false;
        if (request.command == CLIQ_CREATE_WORKER || request.command == CLIQ_CREATE_WRITE) ok = spawn_worker(&request, passed, count, &response);
        else if (request.command == CLIQ_TERMINATE_RETAINED && count == 1) ok = terminate_retained(&request, passed[0], &response);
        else if (request.command == CLIQ_ACTIVATE_WORKER && count == 0 && request.scope > 0 && request.scope < CLIQ_WORKER_MAX_SCOPES) {
            struct scope *scope = &scopes[request.scope];
            if (scope->created && !scope->stopped && !scope->active &&
                strcmp(request.nonce, scope->identity.activation_nonce) == 0) {
                /* The blocked worker receives only its one-use activation capability. */
                memcpy(request.nonce, scope->identity.nonce, sizeof(request.nonce));
                int extra[5]; size_t extras;
                ok = cliq_send(scope->channel, &request, NULL, 0) && readable(scope->channel, OBSERVATION_TIMEOUT_MS) &&
                    cliq_receive(scope->channel, &response, extra, &extras) && extras == 0 && response.command == CLIQ_WORKER_ACTIVATED;
                if (ok) scope->active = true;
            }
        } else if (request.command == CLIQ_RELEASE_WRITE && count == 0 && request.scope > 0 && request.scope < CLIQ_WORKER_MAX_SCOPES) {
            struct scope *scope = &scopes[request.scope];
            if (scope->created && scope->invocation && !scope->stopped && !scope->released &&
                scopes[scope->parent].active && !scopes[scope->parent].stopped &&
                strcmp(request.nonce, scope->identity.nonce) == 0 &&
                scope_process_current(&scopes[scope->parent]) && scope_process_current(scope)) {
                scope->released = true;
                int extra[5]; size_t extras;
                ok = cliq_send(scope->channel, &request, NULL, 0) && readable(scope->channel, OBSERVATION_TIMEOUT_MS) &&
                    cliq_receive(scope->channel, &response, extra, &extras) && extras == 0 && response.command == CLIQ_WRITE_RESULT;
            }
        } else if (request.command == CLIQ_STOP_SCOPE && count == 0) ok = stop_scope(request.scope, &response);
        else if (request.command == CLIQ_STOP_CONTROLLER && count == 0) {
            for (size_t i = 0; i < count; i++) close(passed[i]);
            stop_everything(); return 0;
        }
        for (size_t i = 0; i < count; i++) close(passed[i]);
        if (!ok && request.scope > 0 && request.scope < CLIQ_WORKER_MAX_SCOPES && scopes[request.scope].created) {
            struct cliq_worker_packet ignored; (void)stop_scope(request.scope, &ignored);
        }
        response.status = ok ? 0 : (response.status != 0 ? response.status : 1);
        response.scope = request.scope;
        if (!cliq_send(3, &response, NULL, 0)) break;
    }
    stop_everything();
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 64;
    return getpid() == 1 ? namespace_init() : controller();
}
