#ifndef CLIQ_MCP_HTTP_ADMIN_INIT_H
#define CLIQ_MCP_HTTP_ADMIN_INIT_H
/*
 * Fixed signed Node/helper in the existing strong empty-root namespace. The only helper IPC is one native-created
 * stream socket. No host state/worktree, credential, URL, network namespace capability or arbitrary program enters.
 */
#include "mcp-http-admin-protocol.h"
static bool
mcp_admin_read_config(int fd, struct cliq_mcp_admin_config *config)
{
    struct stat     file;
    int             seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    return !fstat(fd, &file) && S_ISREG(file.st_mode) && file.st_size == (off_t) sizeof(*config) && fcntl(fd, F_GET_SEALS) == seals &&
        cliq_mcp_admin_read_exact(fd, config, sizeof(*config), 0) && cliq_mcp_admin_config_valid(config);
}
static bool
mcp_admin_script_current(const struct cliq_mcp_admin_config *config)
{
    int             fd = open(CLIQ_MCP_ADMIN_SCRIPT_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat     before, after, named;
    bool            valid = fd >= 0 && !fstat(fd, &before) &&
    S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_uid == geteuid() && (before.st_mode & 07777) == 0444 && before.st_size > 0 && (uint64_t) before.st_size == config->script_bytes;
    struct sha256_context hash;
    sha256_init(&hash);
    unsigned char   bytes[65536];
    uint64_t        at = 0;
    while (valid && at < config->script_bytes) {
        size_t          wanted = config->script_bytes - at < sizeof(bytes) ? (size_t) (config->script_bytes - at) : sizeof(bytes);
        ssize_t         n = pread(fd, bytes, wanted, (off_t) at);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            valid = false;
            break;
        } sha256_update(&hash, bytes, (size_t) n);
        at += (uint64_t) n;
    }
    unsigned char   digest[32];
    char            text[65];
    sha256_final(&hash, digest);
    source_hex(digest, text);
    valid = valid && !strcmp(text, config->script_digest) && !fstat(fd, &after) && source_stat_same(&before, &after) && !lstat(CLIQ_MCP_ADMIN_SCRIPT_PATH, &named) && source_stat_same(&before, &named);
    if (!source_close_fd(&fd))
        valid = false;
    return valid;
}
static bool
mcp_admin_confinement(const struct cliq_mcp_admin_config *config)
{
    /*
     * Reuse only the original pure mapped-image hashing/mount mechanism. This local data copy is not a SourceInput or
     * a source execution capability.
     */
    struct cliq_source_config *images = calloc(1, sizeof(*images));
    if (!images)
        return false;
    images->file_count = config->file_count;
    for (uint32_t i = 0; i < config->file_count; i++) {
        memcpy(images->files[i].path, config->files[i].path, sizeof(images->files[i].path));
        memcpy(images->files[i].digest, config->files[i].digest, 65);
        images->files[i].byte_count = config->files[i].byte_count;
    }
    bool            valid = source_bind_runtime(images, "node");
    free(images);
    valid = valid && mcp_admin_script_current(config) && verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0) &&
        verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0) && verifier_mount_attributes("/scratch", 0, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0) &&
        verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0);
    for (uint32_t i = 0; valid && i < config->file_count; i++)
        valid = verifier_mount_attributes(config->files[i].path, 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC) && verifier_mount_observed(config->files[i].path, true, true, false);
    return valid && verifier_mount_observed("/", true, false, false) && verifier_mount_observed("/scratch", false, false, false) &&
        verifier_mount_observed("/proc", true, false, false) && verifier_mount_observed("/dev", false, false, true) && verifier_drop_capabilities() && verifier_filter();
}
static int
mcp_admin_namespace(struct cliq_worker_packet request, int passed[3])
{
    struct cliq_mcp_admin_config *config = calloc(1, sizeof(*config));
    if (!config)
        return 70;
    bool            valid = mcp_admin_read_config(passed[0], config);
    struct stat     recipe;
    valid = valid && !fstat(passed[1], &recipe) && S_ISREG(recipe.st_mode) && recipe.st_size > 0 &&
        (uint64_t) recipe.st_size == config->recipe_bytes && config->recipe_bytes <= CLIQ_MCP_ADMIN_MAX_CONFIG && fcntl(passed[1], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    if (!source_close_fd(&passed[0]))
        valid = false;
    if (!valid) {
        source_close_fd(&passed[1]);
        source_close_fd(&passed[2]);
        free(config);
        return 70;
    }
    int             barrier[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, barrier)) {
        free(config);
        return 70;
    }
    pid_t           child = fork();
    if (child < 0) {
        close(barrier[0]);
        close(barrier[1]);
        free(config);
        return 70;
    }
    if (child == 0) {
        close(barrier[0]);
        int             control = fcntl(barrier[1], F_DUPFD_CLOEXEC, 10), operation = fcntl(passed[2], F_DUPFD_CLOEXEC, 11);
        if (control < 0 || operation < 0 || !source_close_fd(&passed[1]))
            _exit(70);
        if (dup2(control, 3) < 0 || dup2(operation, 4) < 0 || !cliq_close_range(5, UINT_MAX) || mkdir("/scratch/home", 0700) || mkdir("/scratch/tmp", 0700) || !mcp_admin_confinement(config))
            _exit(70);
        struct cliq_worker_packet ready = request;
        ready.command = CLIQ_WORKER_READY;
        char            path[64];
        struct stat     ns;
        snprintf(path, sizeof(path), "/proc/self/ns/pid");
        if (stat(path, &ns) || !cliq_process_token(getpid(), ready.start_token) || !cliq_process_token(1, ready.init_start_token))
            _exit(70);
        ready.pid_namespace_inode = ns.st_ino;
        if (!cliq_send(3, &ready, NULL, 0))
            _exit(70);
        struct cliq_worker_packet release;
        size_t          count;
        if (!cliq_receive(3, &release, NULL, 0, &count) || count || release.command != CLIQ_MCP_ADMIN_RELEASE_RECIPE || !cliq_mcp_admin_packet_same(&request, &release))
            _exit(70);
        if (dup2(4, 3) < 0 || !cliq_close_range(4, UINT_MAX) || chdir("/scratch"))
            _exit(70);
        char           *const arguments[] = {"/usr/bin/node", "--no-addons", CLIQ_MCP_ADMIN_SCRIPT_PATH, NULL};
        char           *const environment[] = {"LANG=C", "LC_ALL=C", "HOME=/scratch/home", "TMPDIR=/scratch/tmp", "PATH=/usr/bin", NULL};
        execve(arguments[0], arguments, environment);
        _exit(70);
    }
    close(barrier[1]);
    if (!source_close_fd(&passed[2]))
        valid = false;
    struct cliq_worker_packet ready;
    size_t          count;
    valid = valid && readable(barrier[0], 5000) && cliq_receive(barrier[0], &ready, NULL, 0, &count) && !count && ready.command == CLIQ_WORKER_READY && cliq_mcp_admin_packet_same(&request, &ready) && cliq_send(3, &ready, NULL, 0);
    struct cliq_worker_packet release;
    valid = valid && cliq_receive(3, &release, NULL, 0, &count) && !count && release.command == CLIQ_MCP_ADMIN_RELEASE_RECIPE && cliq_mcp_admin_packet_same(&request, &release) && cliq_send(barrier[0], &release, NULL, 0);
    if (!source_close_fd(&barrier[0]))
        valid = false;
    if (!source_close_fd(&passed[1]))
        valid = false;
    int             status = 0;
    pid_t           done;
    do {
        done = waitpid(child, &status, 0);
    } while (done < 0 && errno == EINTR);
    bool            success = valid && done == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {
        errno = 0;
    }
    free(config);
    return success ? 0 : 70;
}
#endif
