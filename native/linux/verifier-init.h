#ifndef CLIQ_VERIFIER_INIT_H
#define CLIQ_VERIFIER_INIT_H

#include "verifier-protocol.h"
#include "verifier-node.h"
#include "verifier-setup.h"
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/mount.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <linux/sched.h>
#include <sys/mount.h>

/* Ubuntu 22.04's fixed musl 1.2.2 syscall table predates mount_setattr.
 * Pin the Linux x86_64 UAPI number, not a permissive fallback: an older kernel
 * still returns ENOSYS and the verifier refuses to reach READY. This same
 * number is also denied after the trusted mount setup below. */
#if defined(__x86_64__) && !defined(__ILP32__)
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr __NR_mount_setattr
#endif
#endif

static bool verifier_mount_attributes(const char *path, unsigned int flags, uint64_t set, uint64_t clear) {
#ifdef SYS_mount_setattr
    struct mount_attr attributes = { .attr_set = set, .attr_clr = clear };
    return syscall(SYS_mount_setattr, AT_FDCWD, path, flags, &attributes, sizeof(attributes)) == 0;
#else
    (void)path; (void)flags; (void)set; (void)clear; errno = ENOSYS; return false;
#endif
}

static bool verifier_drop_capabilities(void) {
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
            SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED) != 0) return false;
    unsigned int count = 0;
    for (; count < 64; count++) {
        int present = prctl(PR_CAPBSET_READ, count, 0, 0, 0);
        if (present < 0) { if (errno == EINVAL) break; return false; }
        if (prctl(PR_CAPBSET_DROP, count, 0, 0, 0) != 0 || prctl(PR_CAPBSET_READ, count, 0, 0, 0) != 0) return false;
    }
    if (count == 64) return false;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct capabilities[2] = {{0}};
    if (syscall(SYS_capset, &header, capabilities) != 0 || syscall(SYS_capget, &header, capabilities) != 0) return false;
    for (size_t i = 0; i < 2; i++) if (capabilities[i].effective || capabilities[i].permitted || capabilities[i].inheritable) return false;
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
}

/* Node needs real threads and child Node processes. This is deliberately not
 * the resident worker's deny-all-clone/exec filter. Mounts remain immutable,
 * every writable/source view is noexec, and all executable mounts are the
 * selected same-image closure. No new namespace, network, ptrace or host-FD
 * acquisition path can undo those facts. */
static bool verifier_filter(void) {
#if !defined(__x86_64__) || defined(__ILP32__)
    return false;
#else
#define CLIQ_DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, UINT32_C(0x40000000), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        CLIQ_DENY_SYSCALL(__NR_mount), CLIQ_DENY_SYSCALL(__NR_umount2),
        CLIQ_DENY_SYSCALL(__NR_pivot_root), CLIQ_DENY_SYSCALL(__NR_chroot),
        CLIQ_DENY_SYSCALL(__NR_unshare), CLIQ_DENY_SYSCALL(__NR_setns),
        CLIQ_DENY_SYSCALL(__NR_socket), CLIQ_DENY_SYSCALL(__NR_connect),
        CLIQ_DENY_SYSCALL(__NR_bind), CLIQ_DENY_SYSCALL(__NR_listen),
        CLIQ_DENY_SYSCALL(__NR_accept), CLIQ_DENY_SYSCALL(__NR_accept4),
        CLIQ_DENY_SYSCALL(__NR_ptrace), CLIQ_DENY_SYSCALL(__NR_process_vm_readv),
        CLIQ_DENY_SYSCALL(__NR_process_vm_writev), CLIQ_DENY_SYSCALL(__NR_open_by_handle_at),
        CLIQ_DENY_SYSCALL(__NR_bpf), CLIQ_DENY_SYSCALL(__NR_perf_event_open),
        CLIQ_DENY_SYSCALL(__NR_keyctl), CLIQ_DENY_SYSCALL(__NR_userfaultfd),
#ifdef __NR_pidfd_getfd
        CLIQ_DENY_SYSCALL(__NR_pidfd_getfd),
#endif
#ifdef __NR_mount_setattr
        CLIQ_DENY_SYSCALL(__NR_mount_setattr),
#endif
#ifdef __NR_open_tree
        CLIQ_DENY_SYSCALL(__NR_open_tree), CLIQ_DENY_SYSCALL(__NR_move_mount),
        CLIQ_DENY_SYSCALL(__NR_fsopen), CLIQ_DENY_SYSCALL(__NR_fsmount), CLIQ_DENY_SYSCALL(__NR_fspick),
#endif
#ifdef __NR_clone3
        /* glibc falls back to clone on ENOSYS; opaque clone3 pointer arguments
         * cannot be safely decoded by a seccomp argument filter. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS |
            CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | UINT32_C(0x80), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
#undef CLIQ_DENY_SYSCALL
    struct sock_fprog program = { .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])), .filter = instructions };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
#endif
}

static bool verifier_read_config(int fd, struct cliq_verifier_config *config) {
    struct stat metadata;
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(fd, F_GET_SEALS);
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_size != (off_t)sizeof(*config) ||
        seals < 0 || (seals & required) != required) return false;
    size_t offset = 0;
    while (offset < sizeof(*config)) {
        ssize_t bytes = pread(fd, (char *)config + offset, sizeof(*config) - offset, (off_t)offset);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        offset += (size_t)bytes;
    }
    return cliq_verifier_config_valid(config);
}

static bool verifier_option(const char *options, const char *wanted) {
    size_t bytes = strlen(wanted);
    for (const char *at = options; at && *at; at = strchr(at, ',')) {
        if (*at == ',') at++;
        if (strncmp(at, wanted, bytes) == 0 && (at[bytes] == '\0' || at[bytes] == ',')) return true;
    }
    return false;
}

static bool verifier_mount_observed(const char *target, bool readonly, bool executable, bool devices) {
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t bound = 262144; char *bytes = malloc(bound); bool valid = bytes != NULL, found = false;
    ssize_t count = valid ? read(fd, bytes, bound - 1) : -1;
    if (count <= 0 || (size_t)count == bound - 1) valid = false;
    if (close(fd) != 0) valid = false;
    if (valid) {
        bytes[count] = '\0'; char *line = bytes;
        while (line && *line) {
            char *end = strchr(line, '\n');
            if (!end) { valid = false; break; }
            *end++ = '\0'; char *field = line;
            for (unsigned int i = 1; i < 5 && field; i++) { field = strchr(field, ' '); if (field) field++; }
            if (!field) { valid = false; break; }
            char *options = strchr(field, ' ');
            if (!options) { valid = false; break; }
            *options++ = '\0'; char *tail = strchr(options, ' ');
            if (!tail) { valid = false; break; }
            *tail = '\0';
            if (strcmp(field, target) == 0) {
                if (found || !verifier_option(options, readonly ? "ro" : "rw") ||
                    verifier_option(options, "noexec") == executable || !verifier_option(options, "nosuid") ||
                    (!devices && !verifier_option(options, "nodev"))) { valid = false; break; }
                found = true;
            }
            line = end;
        }
    }
    free(bytes); return valid && found;
}

static bool verifier_setup_stage(uint32_t scope, uint32_t stage) {
    struct cliq_worker_packet progress = cliq_verifier_setup_packet(scope, stage);
    return cliq_send(3, &progress, NULL, 0);
}

static bool verifier_node_mount(const struct cliq_verifier_config *config, uint32_t scope) {
    if (!verifier_setup_stage(scope, CLIQ_VERIFIER_SETUP_NODE_CHECK)) return false;
    int usr = open("/usr", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int directory = usr >= 0 ? openat(usr, "bin", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    bool valid = directory >= 0;
    if (usr >= 0 && close(usr) != 0) valid = false;
    int image = -1; struct stat held;
    for (uint32_t i = 0; valid && i < config->file_count; i++) {
        if (strcmp(config->files[i].path, "/usr/bin/node") == 0)
            image = cliq_verifier_node_open(directory, config->files[i].byte_count, config->files[i].digest, &held);
    }
    char source[64];
    int length = snprintf(source, sizeof(source), "/proc/self/fd/%d", image);
    valid = valid && image >= 0 && length > 0 && (size_t)length < sizeof(source) &&
        cliq_verifier_node_current(directory, image, &held) && verifier_setup_stage(scope, CLIQ_VERIFIER_SETUP_NODE_BIND) &&
        mount(source, "/usr/bin/node", NULL, MS_BIND, NULL) == 0 &&
        cliq_verifier_node_current(directory, image, &held);
    if (image >= 0 && close(image) != 0) valid = false;
    if (directory >= 0 && close(directory) != 0) valid = false;
    return valid;
}

static bool verifier_confinement(const struct cliq_verifier_config *config, uint32_t scope) {
    if (!verifier_node_mount(config, scope) || !verifier_setup_stage(scope, CLIQ_VERIFIER_SETUP_CONFINEMENT) ||
        !verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0) ||
        !verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/work", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/tmp", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/home/cliq", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0)) return false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        if (!verifier_mount_attributes(config->files[i].path, 0,
            MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC)) return false;
    }
    if (!verifier_mount_observed("/", true, false, false) || !verifier_mount_observed("/work", true, false, false) ||
        !verifier_mount_observed("/tmp", false, false, false) || !verifier_mount_observed("/home/cliq", false, false, false) ||
        !verifier_mount_observed("/proc", true, false, false) || !verifier_mount_observed("/dev", false, false, true)) return false;
    for (uint32_t i = 0; i < config->file_count; i++)
        if (!verifier_mount_observed(config->files[i].path, true, true, false)) return false;
    return verifier_drop_capabilities() && verifier_filter();
}

static int verifier_namespace(struct cliq_worker_packet request, int input) {
    if (!verifier_setup_stage(request.scope, CLIQ_VERIFIER_SETUP_ENTRY)) return 70;
    struct cliq_verifier_config *config = calloc(1, sizeof(*config));
    if (!config) return 70;
    bool valid = verifier_read_config(input, config);
    if (close(input) != 0) valid = false;
    if (!valid || !verifier_confinement(config, request.scope)) { free(config); return 70; }
    int barrier[2], execution[2];
    if (pipe2(barrier, O_CLOEXEC) != 0) { free(config); return 70; }
    if (pipe2(execution, O_CLOEXEC | O_NONBLOCK) != 0) { close(barrier[0]); close(barrier[1]); free(config); return 70; }
    pid_t child = fork();
    if (child < 0) { close(barrier[0]); close(barrier[1]); close(execution[0]); close(execution[1]); free(config); return 70; }
    if (child == 0) {
        close(barrier[1]); close(execution[0]); close(3);
        int blocked = fcntl(barrier[0], F_DUPFD_CLOEXEC, 3), failure = fcntl(execution[1], F_DUPFD_CLOEXEC, 4);
        if (blocked < 0 || failure < 0 || dup2(blocked, 3) < 0 || dup3(failure, 4, O_CLOEXEC) < 0 || !cliq_close_range(5, UINT_MAX)) _exit(70);
        char go; ssize_t received;
        do { received = read(3, &go, 1); } while (received < 0 && errno == EINTR);
        close(3);
        if (received != 1 || go != '1') _exit(70);
        char *arguments[CLIQ_VERIFIER_MAX_ARGS + 1], *environment[CLIQ_VERIFIER_MAX_ENV + 1];
        for (uint32_t i = 0; i < config->argument_count; i++) arguments[i] = config->strings + config->arguments[i];
        arguments[config->argument_count] = NULL;
        for (uint32_t i = 0; i < config->environment_count; i++) environment[i] = config->strings + config->environment[i];
        environment[config->environment_count] = NULL;
        if (chdir(config->cwd) == 0) execve(config->executable, arguments, environment);
        int error = errno; (void)write(4, &error, sizeof(error)); _exit(70);
    }
    close(barrier[0]); close(execution[1]);
    struct cliq_worker_packet ready = request; ready.command = CLIQ_WORKER_READY;
    ready.pid = child; ready.namespace_init_pid = 1;
    struct stat namespace;
    if (!cliq_process_token(child, ready.start_token) || !cliq_process_token(1, ready.init_start_token) ||
        stat("/proc/self/ns/pid", &namespace) != 0) { free(config); return 70; }
    ready.pid_namespace_inode = (uint64_t)namespace.st_ino;
    if (!verifier_setup_stage(request.scope, CLIQ_VERIFIER_SETUP_BEFORE_READY) ||
        !cliq_send(3, &ready, NULL, 0)) { free(config); return 70; }
    size_t count;
    if (!cliq_receive(3, &request, NULL, 0, &count) || request.command != CLIQ_RELEASE_VERIFIER) { free(config); return 70; }
    if (write(barrier[1], "1", 1) != 1 || close(barrier[1]) != 0) { free(config); return 70; }
    int status; pid_t joined;
    do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
    if (joined != child) { free(config); return 70; }
    struct cliq_worker_packet result = request; result.command = CLIQ_VERIFIER_RESULT;
    int exec_error = 0; ssize_t failure_bytes;
    do { failure_bytes = read(execution[0], &exec_error, sizeof(exec_error)); } while (failure_bytes < 0 && errno == EINTR);
    if (close(execution[0]) != 0) { free(config); return 70; }
    if (failure_bytes == (ssize_t)sizeof(exec_error) && exec_error > 0) {
        result.verifier_reason = CLIQ_VERIFIER_SPAWN_ERROR; result.verifier_errno = (uint32_t)exec_error;
    } else if (failure_bytes == 0 && WIFEXITED(status)) {
        result.verifier_reason = CLIQ_VERIFIER_EXIT; result.exit_status = (uint32_t)WEXITSTATUS(status);
    } else if (failure_bytes == 0 && WIFSIGNALED(status)) {
        result.verifier_reason = CLIQ_VERIFIER_SIGNAL; result.verifier_signal = (uint32_t)WTERMSIG(status);
    } else { free(config); return 70; }
    free(config);
    if (!cliq_send(3, &result, NULL, 0)) return 70;
    /* The controller records the real outcome, kills/joins this entire
     * namespace/cgroup and drains output. Main exit alone is not quiescence. */
    while (read(3, &status, sizeof(status)) < 0 && errno == EINTR) {}
    return 0;
}

#endif
