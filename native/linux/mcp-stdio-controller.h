#ifndef CLIQ_MCP_STDIO_CONTROLLER_H
#define CLIQ_MCP_STDIO_CONTROLLER_H
/* Closed stdio resource family. Admin and Run have distinct original native
 * inputs; this controller reuses only physical cgroup/READY/stop/ACK machinery. */
#include "mcp-contained-resources.h"
#include <sys/mman.h>
struct mcp_stdio_controller_scope {
    struct mcp_contained_resource resource;
    struct cliq_mcp_stdio_recipe_header recipe;
    bool operation_transferred;
};
static struct mcp_stdio_controller_scope mcp_stdio_scope;
static void mcp_stdio_controller_init(void) {
    memset(&mcp_stdio_scope, 0, sizeof(mcp_stdio_scope));
    mcp_contained_init(&mcp_stdio_scope.resource, MCP_CONTAINED_STDIO_ADMIN);
}
static void mcp_stdio_note_reaped(pid_t pid, int status) {
    mcp_contained_note_reaped(&mcp_stdio_scope.resource, pid, status);
}
static bool mcp_stdio_read_recipe(int fd, const struct cliq_worker_packet *request, struct cliq_mcp_stdio_recipe_header *header) {
    struct stat file;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size < (off_t)sizeof(*header) || (uint64_t)file.st_size > CLIQ_MCP_STDIO_MAX_RECIPE ||
        (uint64_t)file.st_size != request->stdio_recipe_bytes || fcntl(fd, F_GET_SEALS) != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return false;
    unsigned char *bytes = malloc((size_t)file.st_size);
    if (!bytes) return false;
    bool valid = cliq_mcp_admin_read_exact(fd, bytes, (size_t)file.st_size, 0) && cliq_mcp_stdio_recipe_valid(bytes, (size_t)file.st_size, header);
    unsigned char hash[32]; char digest[65];
    if (valid) {
        cliq_mcp_admin_hash(bytes, (size_t)file.st_size, hash); source_hex(hash, digest);
        valid = !strcmp(digest, request->stdio_recipe_digest) && header->purpose == request->stdio_purpose &&
            header->maximum_output_bytes == request->max_output_bytes && header->server_bytes == request->stdio_server_bytes && !strcmp(header->server_digest, request->stdio_server_digest);
    }
    free(bytes); return valid;
}
static bool mcp_stdio_sealed_image(int fd, uint64_t size, const char *expected, bool server) {
    struct stat file;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size < 1 || (uint64_t)file.st_size != size || size > CLIQ_MCP_STDIO_EXECUTABLE_CAP ||
        fcntl(fd, F_GET_SEALS) != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return false;
    struct sha256_context hash; sha256_init(&hash);
    unsigned char bytes[65536]; uint64_t at = 0;
    while (at < size) {
        if (shutdown_requested) return false;
        size_t wanted = size - at < sizeof(bytes) ? (size_t)(size - at) : sizeof(bytes);
        ssize_t n = pread(fd, bytes, wanted, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sha256_update(&hash, bytes, (size_t)n); at += (uint64_t)n;
    }
    unsigned char raw[32]; char digest[65]; sha256_final(&hash, raw); source_hex(raw, digest);
    if (strcmp(digest, expected)) return false;
    if (!server) return true;
    void *mapping = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) return false;
    bool valid = cliq_mcp_stdio_static_elf(mapping, (size_t)size);
    if (munmap(mapping, (size_t)size)) valid = false;
    return valid;
}
static bool mcp_stdio_reserve(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response) {
    struct mcp_contained_resource *scope = &mcp_stdio_scope.resource;
    if (scope->attempted || count != 6 || request->command != CLIQ_MCP_STDIO_RESERVE ||
        mcp_admin_scope.resource.attempted || source_scope.attempted || worker_creation_attempted) return false;
    scope->attempted = true;
    scope->family = request->stdio_purpose == CLIQ_MCP_STDIO_ADMIN ? MCP_CONTAINED_STDIO_ADMIN : request->stdio_purpose == CLIQ_MCP_STDIO_RECOVERY ? MCP_CONTAINED_STDIO_RECOVERY : MCP_CONTAINED_STDIO_RUN;
    struct cliq_mcp_stdio_history history; struct stat birth;
    if (!native_cgroup(passed[0]) || fstat(passed[0], &scope->anchor_identity) || fstat(passed[1], &birth) || !S_ISREG(birth.st_mode) || birth.st_nlink != 1 ||
        birth.st_uid != geteuid() || (birth.st_mode & 07777) != 0600 || !cliq_mcp_stdio_read_history(passed[1], &history, NULL, NULL) || history.count != 1 ||
        history.first.kind != 1 || history.first.controller_pid != getpid() || !cliq_mcp_stdio_packet_same(request, &history.first.packet) ||
        !mcp_stdio_read_recipe(passed[2], request, &mcp_stdio_scope.recipe) ||
        !mcp_stdio_sealed_image(passed[3], request->stdio_init_bytes, request->stdio_init_digest, false) ||
        !mcp_stdio_sealed_image(passed[4], request->stdio_bwrap_bytes, request->stdio_bwrap_digest, false) ||
        !mcp_stdio_sealed_image(passed[5], request->stdio_server_bytes, request->stdio_server_digest, true)) return false;
    char token[CLIQ_WORKER_TOKEN_BYTES];
    if (!cliq_process_token(getpid(), token) || strcmp(token, history.first.controller_start_token)) return false;
    scope->origin.stdio = history.first; scope->identity = *request;
    int *slots[] = {&scope->anchor, &scope->birth, &scope->recipe_fd, &scope->helper, &scope->bwrap, &scope->script};
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) { *slots[i] = fcntl(passed[i], F_DUPFD_CLOEXEC, 4); if (*slots[i] < 0) return false; }
    char name[96], pidns[CLIQ_WORKER_TOKEN_BYTES];
    const char *purpose = request->stdio_purpose == CLIQ_MCP_STDIO_ADMIN ? "admin" : request->stdio_purpose == CLIQ_MCP_STDIO_RECOVERY ? "recovery" : "run";
    int length = snprintf(name, sizeof(name), "cliq-mcp-stdio-%s-%s", purpose, request->nonce);
    int namespace_length = snprintf(pidns, sizeof(pidns), "linux-mcp-stdio:%s:%s", purpose, request->nonce);
    if (length < 0 || (size_t)length >= sizeof(name) || namespace_length < 0 || (size_t)namespace_length >= sizeof(pidns) ||
        strcmp(name, request->cgroup_name) || strcmp(pidns, request->pid_namespace_reservation) || !mcp_contained_step(scope, 2) || mkdirat(scope->anchor, name, 0700)) return false;
    scope->cgroup = openat(scope->anchor, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scope->cgroup < 0 || !native_cgroup(scope->cgroup) || fstat(scope->cgroup, &scope->cgroup_identity)) return false;
    scope->created = true; scope->identity.cgroup_device = scope->cgroup_identity.st_dev; scope->identity.cgroup_inode = scope->cgroup_identity.st_ino;
    if (!mcp_contained_step(scope, 3) || !cgroup_empty(scope->cgroup) || !resources(scope->cgroup, request)) return false;
    *response = scope->identity; response->command = CLIQ_MCP_STDIO_RESERVE; return stamp_observation(response);
}
static void mcp_stdio_bubblewrap(struct mcp_contained_resource *scope) {
    if (scope != &mcp_stdio_scope.resource) _exit(70);
    int keep[] = {scope->helper, scope->bwrap, scope->script};
    if (!retain_descriptors(keep, sizeof(keep) / sizeof(keep[0]))) _exit(70);
    int init = independent_image_fd(scope->helper, 4), bwrap = fcntl(scope->bwrap, F_DUPFD_CLOEXEC, 4), server = independent_image_fd(scope->script, 4);
    if (init < 0 || bwrap < 0 || server < 0) _exit(70);
    int retained[] = {init, bwrap, server}; if (!retain_descriptors(retained, sizeof(retained) / sizeof(retained[0]))) _exit(70);
    char init_fd[24], server_fd[24]; snprintf(init_fd, sizeof(init_fd), "%d", init); snprintf(server_fd, sizeof(server_fd), "%d", server);
    char *arguments[] = {"bwrap", "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid", "--as-pid-1", "--unshare-net", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_SETPCAP",
        "--clearenv", "--size", "535822336", "--tmpfs", "/", "--dir", "/runtime", "--dir", "/home", "--dir", "/home/cliq", "--dir", "/tmp", "--dir", "/work",
        "--perms", "0555", "--ro-bind-data", init_fd, "/runtime/cliq-linux-worker-init", "--perms", "0555", "--file", server_fd, CLIQ_MCP_STDIO_SERVER_PATH,
        "--proc", "/proc", "--dev", "/dev", "--size", "1048576", "--tmpfs", "/scratch", "--chdir", "/scratch", "--", "/runtime/cliq-linux-worker-init", NULL};
    char *const environment[] = {"LANG=C", "LC_ALL=C", NULL}; fexecve(bwrap, arguments, environment); _exit(70);
}
static bool mcp_stdio_update_progress(const struct cliq_worker_packet *request) {
    struct mcp_contained_resource *scope = &mcp_stdio_scope.resource;
    if (request->stdio_phase < scope->identity.stdio_phase || request->stdio_operation_released < scope->identity.stdio_operation_released ||
        request->stdio_protocol_complete < scope->identity.stdio_protocol_complete || request->stdio_response_refused < scope->identity.stdio_response_refused ||
        request->stdio_owner_drained < scope->identity.stdio_owner_drained) return false;
    scope->identity.stdio_phase = request->stdio_phase; scope->identity.stdio_operation_released = request->stdio_operation_released;
    scope->identity.stdio_response_refused = request->stdio_response_refused; scope->identity.stdio_owner_drained = request->stdio_owner_drained;
    if (request->stdio_protocol_complete && !scope->identity.stdio_protocol_complete) {
        if (!scope->released || request->stdio_phase != (scope->identity.stdio_purpose == CLIQ_MCP_STDIO_ADMIN ? 3u : 4u)) return false;
        scope->identity.stdio_protocol_complete = 1;
        if (!mcp_contained_step(scope, 7)) return false;
    }
    return true;
}
static bool mcp_stdio_poll(struct cliq_worker_packet *response) {
    struct mcp_contained_resource *scope = &mcp_stdio_scope.resource;
    if (!scope->attempted || !mcp_contained_root_current(scope)) return false;
    if (scope->blocked && !scope->dead) {
        if (!scope->monitor_joined) {
            int status; pid_t done = waitpid(scope->process.monitor, &status, WNOHANG);
            if (done > 0) mcp_contained_note_reaped(scope, done, status);
            else if (done < 0 && errno != EINTR) return false;
        }
        if (scope->identity.stdio_owner_drained && scope->monitor_joined && held_scope_dead(&scope->process)) {
            if (!source_close_fd(&scope->channel) || !source_close_fd(&scope->operation)) return false;
            scope->process.channel = -1; scope->dead = true; scope->identity.populated = 0; scope->identity.remaining_descendants = 0; scope->identity.init_reaped = 1;
            if (!mcp_contained_step(scope, 8)) return false;
        }
    }
    *response = scope->identity; response->command = CLIQ_MCP_STDIO_POLL; return stamp_observation(response);
}
static bool mcp_stdio_cleanup_retained(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response) {
    if (count != 2 || mcp_stdio_scope.resource.attempted || !request->stdio_checker_owner_epoch ||
        request->stdio_checker_supervisor_pid <= 0 || request->stdio_checker_supervisor_pid > INT32_MAX ||
        !cliq_mcp_admin_digest(request->stdio_original_birth_digest)) return false;
    struct ucred credentials; socklen_t credentials_size = sizeof(credentials);
    char token[CLIQ_WORKER_TOKEN_BYTES];
    if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) || credentials_size != sizeof(credentials) ||
        credentials.pid != request->stdio_checker_supervisor_pid || credentials.uid != geteuid() ||
        !cliq_process_token(credentials.pid, token) || strcmp(token, request->stdio_checker_supervisor_token)) return false;
    int root = passed[0], birth = passed[1], group = -1; passed[0] = passed[1] = -1;
    struct stat root_identity, held, named;
    struct cliq_mcp_stdio_history history = {0}, final;
    unsigned char *snapshot = NULL; size_t bytes = 0;
    bool valid = native_cgroup(root) && !fstat(root, &root_identity) &&
        cliq_mcp_stdio_read_history(birth, &history, &snapshot, &bytes) && history.count && history.last.kind >= 3 &&
        !(history.last.kind == 4 && !history.last.packet.monitor_pid) &&
        cliq_mcp_stdio_packet_same(request, &history.first.packet) && history.first.controller_pid != getpid() &&
        history.first.controller_root.device == (uint64_t)root_identity.st_dev &&
        history.first.controller_root.inode == (uint64_t)root_identity.st_ino && !flock(birth, LOCK_EX | LOCK_NB);
    pid_t supervisor = valid ? (pid_t)(history.purpose == CLIQ_MCP_STDIO_ADMIN ? history.header.admin.supervisor_pid : history.purpose == CLIQ_MCP_STDIO_RECOVERY ? history.header.recovery.supervisor_pid : history.header.run.supervisor_pid) : -1;
    const char *supervisor_token = history.purpose == CLIQ_MCP_STDIO_ADMIN ? history.header.admin.supervisor_start_token : history.purpose == CLIQ_MCP_STDIO_RECOVERY ? history.header.recovery.supervisor_start_token : history.header.run.supervisor_start_token;
    valid = valid && (history.purpose != CLIQ_MCP_STDIO_RECOVERY ||
        (request->stdio_checker_owner_epoch > history.header.recovery.identity.inspectorStateOwnerEpoch &&
         strcmp(request->stdio_checker_supervisor_id, history.header.recovery.identity.inspectorSupervisorInstanceId) &&
         request->stdio_checker_supervisor_pid != supervisor)) && original_process_absent(supervisor, supervisor_token) &&
        original_process_absent((pid_t)history.first.controller_pid, history.first.controller_start_token);
    unsigned char hash[32]; char digest[65];
    if (valid) {
        cliq_mcp_admin_hash(snapshot, bytes, hash); source_hex(hash, digest);
        valid = !strcmp(digest, request->stdio_original_birth_digest);
    }
    free(snapshot); snapshot = NULL;
    const struct cliq_worker_packet *original = &history.last.packet;
    bool present = false;
    if (valid) {
        group = openat(root, original->cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); present = group >= 0;
        valid = present ? native_cgroup(group) && !fstat(group, &held) &&
            (uint64_t)held.st_dev == original->cgroup_device && (uint64_t)held.st_ino == original->cgroup_inode &&
            held.st_uid == geteuid() && held.st_gid == getegid() && (held.st_mode & 07777) == 0700 :
            errno == ENOENT && history.last.kind == 9;
    }
    struct tracked_set tracked = {0};
    if (valid && present) valid = collect_processes(group, &tracked, 0);
    if (valid && original->monitor_pid) valid = track_process(&tracked, (pid_t)original->monitor_pid, original->monitor_start_token);
    if (valid && history.ready.kind == 5)
        valid = track_process(&tracked, (pid_t)history.ready.packet.pid, history.ready.packet.start_token) &&
            track_process(&tracked, (pid_t)history.ready.packet.namespace_init_pid, history.ready.packet.init_native_start_token);
    if (valid && original->monitor_pid && !original_process_absent((pid_t)original->monitor_pid, original->monitor_start_token))
        valid = stop_retained_subreaper((pid_t)original->monitor_pid, original->monitor_start_token);
    if (valid && present) valid = write_control(group, "cgroup.kill", "1");
    int64_t start = milliseconds(); valid = valid && start >= 0;
    while (valid && ((present && !cgroup_empty(group)) || !tracked_absent(&tracked))) {
        int64_t now = milliseconds();
        if (now < start || now - start >= 2000) { valid = false; break; }
        struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
    valid = valid && original_process_absent(supervisor, supervisor_token) &&
        original_process_absent((pid_t)history.first.controller_pid, history.first.controller_start_token) &&
        cliq_mcp_stdio_read_history(birth, &final, &snapshot, &bytes) &&
        final.count == history.count && !memcmp(final.last.digest, history.last.digest, 32);
    if (valid) {
        cliq_mcp_admin_hash(snapshot, bytes, hash); source_hex(hash, digest);
        valid = !strcmp(digest, request->stdio_original_birth_digest);
    }
    free(snapshot);
    if (valid && present)
        valid = !fstat(group, &held) && !fstatat(root, original->cgroup_name, &named, AT_SYMLINK_NOFOLLOW) &&
            source_stat_same(&held, &named) && (uint64_t)held.st_dev == original->cgroup_device &&
            (uint64_t)held.st_ino == original->cgroup_inode && cgroup_empty(group) &&
            !unlinkat(root, original->cgroup_name, AT_REMOVEDIR);
    valid = valid && !fstat(root, &held) && source_stat_same(&held, &root_identity) &&
        fstatat(root, original->cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT && tracked_absent(&tracked);
    if (!source_close_fd(&group) || !source_close_fd(&birth) || !source_close_fd(&root)) valid = false;
    if (!valid) return false;
    *response = *request; response->command = CLIQ_MCP_STDIO_CLEANUP_RETAINED;
    response->populated = 0; response->remaining_descendants = 0;
    response->init_reaped = history.ready.kind == 5 ? 1 : 0;
    response->reservation_observation = history.last.kind;
    return stamp_observation(response);
}
static bool mcp_stdio_command(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response, int *outputs, size_t *output_count) {
    struct mcp_contained_resource *scope = &mcp_stdio_scope.resource;
    if (!cliq_mcp_stdio_packet_closed(request)) return false;
    if (request->command == CLIQ_MCP_STDIO_CLEANUP_RETAINED) return mcp_stdio_cleanup_retained(request, passed, count, response);
    if (request->command == CLIQ_MCP_STDIO_RESERVE) return mcp_stdio_reserve(request, passed, count, response);
    if (!scope->attempted || !cliq_mcp_stdio_packet_same(request, &scope->identity) || count) return false;
    if (!mcp_stdio_update_progress(request)) return false;
    if (request->command == CLIQ_MCP_STDIO_CREATE_BLOCKED) {
        if (!mcp_contained_create_blocked(scope, request, response, mcp_stdio_bubblewrap) || mcp_stdio_scope.operation_transferred) return false;
        outputs[0] = fcntl(scope->operation, F_DUPFD_CLOEXEC, 4);
        if (outputs[0] < 0) return false;
        *output_count = 1;
        if (!source_close_fd(&scope->operation)) return false;
        mcp_stdio_scope.operation_transferred = true;
        return true;
    }
    if (request->command == CLIQ_MCP_STDIO_RELEASE_EXEC) {
        if (!scope->blocked || scope->released || scope->dead || !mcp_contained_root_current(scope) || !mcp_contained_step(scope, 6)) return false;
        struct timespec now;
        if (clock_gettime(CLOCK_REALTIME, &now) || (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 >= scope->identity.stdio_launch_deadline_ms) return false;
        scope->released = true;
        if (!cliq_send(scope->channel, request, NULL, 0)) return false;
        *response = scope->identity; response->command = CLIQ_MCP_STDIO_RELEASE_EXEC; return stamp_observation(response);
    }
    if (request->command == CLIQ_MCP_STDIO_POLL) return mcp_stdio_poll(response);
    if (request->command == CLIQ_MCP_STDIO_STOP) return mcp_contained_stop(scope, response, CLIQ_MCP_STDIO_STOP);
    if (request->command == CLIQ_MCP_STDIO_ACK) return mcp_contained_ack(scope, response, CLIQ_MCP_STDIO_ACK);
    return false;
}
#endif

