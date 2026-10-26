#ifndef CLIQ_BUILTIN_TOOL_INIT_H
#define CLIQ_BUILTIN_TOOL_INIT_H
#include "builtin-tool-protocol.h"

static bool builtin_read_config(int fd, struct cliq_builtin_config *config) {
    struct stat file; int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size != (off_t)sizeof(*config) || fcntl(fd, F_GET_SEALS) != required) return false;
    size_t offset = 0;
    while (offset < sizeof(*config)) {
        ssize_t count = pread(fd, (char *)config + offset, sizeof(*config) - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return cliq_builtin_config_valid(config);
}
static bool builtin_full_data(int fd, uint64_t expected, const char *digest, bool sealed) {
    struct stat before, after;
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 0 || (uint64_t)before.st_size != expected ||
        (sealed && fcntl(fd, F_GET_SEALS) != required)) return false;
    struct sha256_context hash; sha256_init(&hash); unsigned char bytes[65536]; uint64_t offset = 0;
    while (offset < expected) {
        size_t wanted = expected - offset < sizeof(bytes) ? (size_t)(expected - offset) : sizeof(bytes);
        ssize_t count = pread(fd, bytes, wanted, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > wanted) return false;
        sha256_update(&hash, bytes, (size_t)count); offset += (uint64_t)count;
    }
    unsigned char tail; ssize_t count;
    do { count = pread(fd, &tail, 1, (off_t)expected); } while (count < 0 && errno == EINTR);
    unsigned char observed[32]; char text[65]; static const char hex[] = "0123456789abcdef";
    sha256_final(&hash, observed);
    for (size_t i = 0; i < 32; i++) { text[i * 2] = hex[observed[i] >> 4]; text[i * 2 + 1] = hex[observed[i] & 15]; } text[64] = '\0';
    return count == 0 && !strcmp(text, digest) && fstat(fd, &after) == 0 && cliq_verifier_node_same(&before, &after);
}
static bool builtin_sealed_data(int fd, uint64_t expected, const char *digest) { return builtin_full_data(fd, expected, digest, true); }

/* Freshly copied named executables must be fully read, rebound and remain
 * identical. This does not trust the initial namespace pathname or a cache. */
static bool builtin_bind_runtime(const struct cliq_verifier_config *config, const char *path) {
    const char *parent = !strcmp(path, "/bin/bash") ? "/bin" : "/usr/bin";
    const char *leaf = !strcmp(path, "/bin/bash") ? "bash" : "git";
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), image = -1;
    const char *digest = NULL; uint64_t size = 0;
    for (uint32_t i = 0; i < config->file_count; i++) if (!strcmp(config->files[i].path, path)) {
        digest = config->files[i].digest; size = config->files[i].byte_count;
    }
    if (directory >= 0 && digest) image = openat(directory, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat held, named; bool valid = image >= 0 && fstat(image, &held) == 0 &&
        held.st_nlink == 1 && held.st_uid == geteuid() && held.st_gid == getegid() && (held.st_mode & 07777) == 0555 &&
        builtin_full_data(image, size, digest, false) && fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        cliq_verifier_node_same(&held, &named);
    char source[64]; snprintf(source, sizeof(source), "/proc/self/fd/%d", image);
    if (valid) valid = mount(source, path, NULL, MS_BIND, NULL) == 0 && fstat(image, &named) == 0 &&
        cliq_verifier_node_same(&held, &named) && fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        cliq_verifier_node_same(&held, &named);
    if (image >= 0 && close(image) != 0) valid = false;
    if (directory >= 0 && close(directory) != 0) valid = false;
    return valid;
}
static bool builtin_filter(void) {
#if defined(__x86_64__) && !defined(__ILP32__) && defined(__NR_memfd_create) && defined(__NR_execveat)
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_memfd_create, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = { .len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) == 0;
#else
    return false;
#endif
}
/* This checks the native-captured existing child, never a caller pathname.
 * Absence remains absence; no guard directory is created for a non-Git M. */
static bool builtin_git_current(const struct cliq_builtin_config *config) {
    if (config->tool != CLIQ_BUILTIN_BASH) return true;
    int root = open("/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), git = -1;
    struct stat before, named, actual, after; bool valid = root >= 0 && fstat(root, &before) == 0 && S_ISDIR(before.st_mode);
    if (valid) {
        int found = fstatat(root, ".git", &named, AT_SYMLINK_NOFOLLOW);
        if (config->git_kind == 0) valid = found < 0 && errno == ENOENT;
        else {
            valid = found == 0 && cliq_builtin_git_metadata(&before, &named) &&
                (uint64_t)named.st_dev == config->git_device && (uint64_t)named.st_ino == config->git_inode;
            if (valid) git = openat(root, ".git", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            valid = valid && git >= 0 && fstat(git, &actual) == 0 && cliq_builtin_git_metadata(&before, &actual) &&
                actual.st_dev == named.st_dev && actual.st_ino == named.st_ino && actual.st_mode == named.st_mode &&
                actual.st_uid == named.st_uid && actual.st_gid == named.st_gid && fstatat(root, ".git", &after, AT_SYMLINK_NOFOLLOW) == 0 &&
                actual.st_dev == after.st_dev && actual.st_ino == after.st_ino && actual.st_mode == after.st_mode &&
                actual.st_uid == after.st_uid && actual.st_gid == after.st_gid;
        }
        valid = valid && fstat(root, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
            before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_mode == after.st_mode;
    }
    if (git >= 0 && close(git) != 0) valid = false;
    if (root >= 0 && close(root) != 0) valid = false;
    return valid;
}
static bool builtin_confinement(const struct cliq_builtin_config *fixed, uint32_t scope) {
    const struct cliq_verifier_config *config = &fixed->capture; bool bash = fixed->tool == CLIQ_BUILTIN_BASH;
    int script = open(CLIQ_BUILTIN_SCRIPT_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    bool valid = script >= 0 && builtin_full_data(script, fixed->script_bytes, fixed->script_digest, false);
    if (script >= 0 && close(script) != 0) valid = false;
    if (!valid || !builtin_git_current(fixed) || !verifier_node_mount(config, scope) ||
        (bash && (!builtin_bind_runtime(config, "/usr/bin/git") || !builtin_bind_runtime(config, "/bin/bash"))) ||
        !verifier_setup_stage(scope, CLIQ_VERIFIER_SETUP_CONFINEMENT) ||
        !verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0) ||
        !verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/work", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV | (bash ? 0 : MOUNT_ATTR_RDONLY), 0) ||
        !verifier_mount_attributes("/tmp", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/home/cliq", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0) ||
        !verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, 0)) return false;
    /* Clear readonly on the top bind only. A recursive clear would also
     * unlock the protected existing .git submount. */
    if (bash && !verifier_mount_attributes("/work", 0, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, MOUNT_ATTR_RDONLY)) return false;
    if (fixed->git_kind == 1 && !verifier_mount_attributes("/work/.git", AT_RECURSIVE,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID, 0)) return false;
    for (uint32_t i = 0; i < config->file_count; i++) if (!verifier_mount_attributes(config->files[i].path, 0,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC)) return false;
    if (!verifier_mount_observed("/", true, false, false) || !verifier_mount_observed("/work", !bash, false, false) ||
        !verifier_mount_observed("/tmp", false, false, false) || !verifier_mount_observed("/home/cliq", false, false, false) ||
        !verifier_mount_observed("/proc", true, false, false) || !verifier_mount_observed("/dev", false, false, true) ||
        !verifier_mount_observed(CLIQ_BUILTIN_SCRIPT_PATH, true, false, false)) return false;
    for (uint32_t i = 0; i < config->file_count; i++) if (!verifier_mount_observed(config->files[i].path, true, true, false)) return false;
    if (!builtin_git_current(fixed) || (fixed->git_kind == 1 && !verifier_mount_observed("/work/.git", true, false, false))) return false;
    return verifier_drop_capabilities() && verifier_filter() && builtin_filter();
}

static int builtin_namespace(struct cliq_worker_packet request, int passed[CLIQ_WORKER_MAX_FDS]) {
    if (!verifier_setup_stage(request.scope, CLIQ_VERIFIER_SETUP_ENTRY)) return 70;
    struct cliq_builtin_config *fixed = calloc(1, sizeof(*fixed));
    struct cliq_verifier_config *config = fixed ? &fixed->capture : NULL;
    bool bash = request.command == CLIQ_CREATE_BUILTIN_BASH;
    if (!config) return 70;
    bool valid = builtin_read_config(passed[0], fixed) && (fixed->tool == CLIQ_BUILTIN_BASH) == bash &&
        builtin_sealed_data(passed[1], fixed->input_bytes, fixed->input_digest) &&
        (!bash || builtin_sealed_data(passed[2], fixed->command_bytes, fixed->command_digest));
    if (close(passed[0]) != 0) valid = false;
    if (!valid || !builtin_confinement(fixed, request.scope)) { free(config); return 70; }
    int barrier[2], execution[2];
    if (pipe2(barrier, O_CLOEXEC) != 0) { free(config); return 70; }
    if (pipe2(execution, O_CLOEXEC | O_NONBLOCK) != 0) { close(barrier[0]); close(barrier[1]); free(config); return 70; }
    pid_t child = fork();
    if (child < 0) { close(barrier[0]); close(barrier[1]); close(execution[0]); close(execution[1]); free(config); return 70; }
    if (child == 0) {
        close(barrier[1]); close(execution[0]); close(3);
        int blocked = fcntl(barrier[0], F_DUPFD_CLOEXEC, 10), failure = fcntl(execution[1], F_DUPFD_CLOEXEC, 10);
        int data = independent_image_fd(passed[1], 10), command = bash ? independent_image_fd(passed[2], 10) : -1;
        if (blocked < 0 || failure < 0 || data < 0 || (bash && command < 0) ||
            dup2(data, 3) < 0 || (bash && dup2(command, 4) < 0) || dup3(failure, 5, O_CLOEXEC) < 0 ||
            dup3(blocked, 6, O_CLOEXEC) < 0 || !cliq_close_range(7, UINT_MAX)) _exit(70);
        if (!bash && close(4) != 0 && errno != EBADF) _exit(70);
        char go; ssize_t received;
        do { received = read(6, &go, 1); } while (received < 0 && errno == EINTR);
        if (close(6) != 0 || received != 1 || go != '1') _exit(70);
        char *arguments[CLIQ_VERIFIER_MAX_ARGS + 1], *environment[CLIQ_VERIFIER_MAX_ENV + 1];
        for (uint32_t i = 0; i < config->argument_count; i++) arguments[i] = config->strings + config->arguments[i];
        arguments[config->argument_count] = NULL;
        for (uint32_t i = 0; i < config->environment_count; i++) environment[i] = config->strings + config->environment[i];
        environment[config->environment_count] = NULL;
        if (chdir(config->cwd) == 0) execve(config->executable, arguments, environment);
        int error = errno; if (!cliq_write_exec_diagnostic(5, error)) _exit(70); _exit(70);
    }
    close(barrier[0]); close(execution[1]);
    if (close(passed[1]) != 0 || (bash && close(passed[2]) != 0)) { free(config); return 70; }
    struct cliq_worker_packet ready = request; ready.command = CLIQ_WORKER_READY;
    ready.pid = child; ready.namespace_init_pid = 1;
    struct stat namespace;
    if (!cliq_process_token(child, ready.start_token) || !cliq_process_token(1, ready.init_start_token) ||
        stat("/proc/self/ns/pid", &namespace) != 0) { free(config); return 70; }
    ready.pid_namespace_inode = (uint64_t)namespace.st_ino;
    if (!verifier_setup_stage(request.scope, CLIQ_VERIFIER_SETUP_BEFORE_READY) ||
        !cliq_send(3, &ready, NULL, 0)) { free(config); return 70; }
    size_t count;
    if (!cliq_receive(3, &request, NULL, 0, &count) || request.command != CLIQ_RELEASE_BUILTIN) { free(config); return 70; }
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
