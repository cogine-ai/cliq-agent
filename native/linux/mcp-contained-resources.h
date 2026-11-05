#ifndef CLIQ_MCP_CONTAINED_RESOURCES_H
#define CLIQ_MCP_CONTAINED_RESOURCES_H
/* Private physical mechanism shared only by the two closed installed MCP
 * profiles. All grant/input/image/purpose checks stay in their constructors;
 * no caller callback, fd getter or public transport interface enters here. */
#include "mcp-stdio-protocol.h"
enum mcp_contained_family { MCP_CONTAINED_HTTP_ADMIN = 1, MCP_CONTAINED_STDIO_ADMIN = 2, MCP_CONTAINED_STDIO_RUN = 3, MCP_CONTAINED_STDIO_RECOVERY = 4 };
struct mcp_contained_resource {
    enum mcp_contained_family family;
    bool attempted, created, blocked, released, failed, dead, acked, monitor_joined, monitor_success, unreleased_stdio_shutdown;
    int anchor, birth, config_fd, recipe_fd, helper, bwrap, script, files[CLIQ_VERIFIER_MAX_FILES], channel, operation, stdout_fd, stderr_fd, cgroup;
    struct stat anchor_identity, cgroup_identity;
    struct cliq_worker_packet identity;
    union { struct cliq_mcp_admin_progress admin; struct cliq_mcp_stdio_progress stdio; } origin;
    struct scope process;
    int construction[6];
};
static void mcp_contained_init(struct mcp_contained_resource *scope, enum mcp_contained_family family) {
    memset(scope, 0, sizeof(*scope)); scope->family = family;
    int *slots[] = {&scope->anchor, &scope->birth, &scope->config_fd, &scope->recipe_fd, &scope->helper, &scope->bwrap, &scope->script,
        &scope->channel, &scope->operation, &scope->stdout_fd, &scope->stderr_fd, &scope->cgroup};
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) *slots[i] = -1;
    for (size_t i = 0; i < CLIQ_VERIFIER_MAX_FILES; i++) scope->files[i] = -1;
    for (size_t i = 0; i < 6; i++) scope->construction[i] = -1;
}
static void mcp_contained_note_reaped(struct mcp_contained_resource *scope, pid_t pid, int status) {
    if (scope->attempted && !scope->acked && !scope->monitor_joined && pid == scope->process.monitor) {
        scope->monitor_joined = true; scope->monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
}
static bool mcp_contained_root_current(const struct mcp_contained_resource *scope) {
    struct stat root, named;
    return scope->anchor >= 0 && !fstat(scope->anchor, &root) && source_stat_same(&root, &scope->anchor_identity) && native_cgroup(scope->anchor) &&
        (!scope->created || (!fstatat(scope->anchor, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&named, &scope->cgroup_identity)));
}
static bool mcp_contained_step(struct mcp_contained_resource *scope, unsigned kind) {
    if (!mcp_contained_root_current(scope)) return false;
    if (scope->family == MCP_CONTAINED_HTTP_ADMIN) {
        struct cliq_mcp_admin_progress frame = scope->origin.admin; frame.packet = scope->identity;
        return cliq_mcp_admin_append(scope->birth, kind, &frame);
    }
    if (scope->family != MCP_CONTAINED_STDIO_ADMIN && scope->family != MCP_CONTAINED_STDIO_RUN && scope->family != MCP_CONTAINED_STDIO_RECOVERY) return false;
    struct cliq_mcp_stdio_progress frame = scope->origin.stdio; frame.packet = scope->identity;
    return cliq_mcp_stdio_append(scope->birth, kind, &frame);
}
static bool mcp_contained_packet_same(const struct mcp_contained_resource *scope, const struct cliq_worker_packet *left, const struct cliq_worker_packet *right) {
    return scope->family == MCP_CONTAINED_HTTP_ADMIN ? cliq_mcp_admin_packet_same(left, right) : cliq_mcp_stdio_packet_same(left, right);
}
static bool
mcp_contained_create_blocked(struct mcp_contained_resource *scope, struct cliq_worker_packet *request, struct cliq_worker_packet *response, void (*bubblewrap)(struct mcp_contained_resource *))
{
    if (!scope->created || scope->blocked || scope->failed || !mcp_contained_packet_same(scope, request, &scope->identity) || !mcp_contained_root_current(scope) || !cgroup_empty(scope->cgroup))
        return false;
    int            *control = scope->construction, *operation = scope->construction + 2, *barrier = scope->construction + 4;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control))
        return false;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, operation))
        return false;
    if (pipe2(barrier, O_CLOEXEC))
        return false;
    scope->stdout_fd = memfd_create("cliq-mcp-admin-stdout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    scope->stderr_fd = memfd_create("cliq-mcp-admin-stderr", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (scope->stdout_fd < 0 || scope->stderr_fd < 0 || ftruncate(scope->stdout_fd, 65536) || ftruncate(scope->stderr_fd, 65536) ||
        fcntl(scope->stdout_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) || fcntl(scope->stderr_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL))
        return false;
    struct scope   *process = &scope->process;
    if (!mcp_contained_step(scope, 4))
        return false;
    process->monitor = fork();
    if (process->monitor < 0)
        return false;
    if (!process->monitor) {
        close(control[0]);
        close(operation[0]);
        close(operation[1]);
        close(barrier[1]);
        char            go;
        if (read(barrier[0], &go, 1) != 1 || go != '1' || dup2(control[1], 3) < 0 || dup2(scope->stdout_fd, 1) < 0 || dup2(scope->stderr_fd, 2) < 0 || !configure_limits(request))
            _exit(70);
        bubblewrap(scope);
        _exit(70);
    }
    if (!source_close_fd(&control[1]) || !source_close_fd(&barrier[0]))
        return false;
    scope->channel = control[0];
    control[0] = -1;
    scope->operation = operation[0];
    operation[0] = -1;
    process->cgroup = process->process_group = scope->cgroup;
    process->channel = scope->channel;
    if (!cliq_process_token(process->monitor, process->monitor_start_token))
        return false;
    scope->identity.monitor_pid = process->monitor;
    memcpy(scope->identity.monitor_start_token, process->monitor_start_token, sizeof(process->monitor_start_token));
    if (!mcp_contained_step(scope, 4))
        return false;
    char            pid[32];
    snprintf(pid, sizeof(pid), "%ld", (long)process->monitor);
    bool            valid = write_control(scope->cgroup, "cgroup.procs", pid) && write(barrier[1], "1", 1) == 1;
    if (!source_close_fd(&barrier[1]))
        valid = false;
    int             inputs[3]; size_t input_count;
    if (scope->family == MCP_CONTAINED_HTTP_ADMIN) { inputs[0] = scope->config_fd; inputs[1] = scope->recipe_fd; inputs[2] = operation[1]; input_count = 3; }
    else { inputs[0] = scope->recipe_fd; inputs[1] = operation[1]; input_count = 2; }
    struct cliq_worker_packet initial = scope->identity;
    initial.command = scope->family == MCP_CONTAINED_HTTP_ADMIN ? CLIQ_MCP_ADMIN_CREATE_BLOCKED : CLIQ_MCP_STDIO_CREATE_BLOCKED;
    size_t          count;
    struct cliq_worker_packet ready;
    valid = valid && cliq_send(scope->channel, &initial, inputs, input_count) && readable(scope->channel, 5000) && cliq_receive(scope->channel, &ready, NULL, 0, &count) && !count && ready.command == CLIQ_WORKER_READY && mcp_contained_packet_same(scope, &initial, &ready) && inspect_processes(process, &ready);
    if (!source_close_fd(&operation[1]))
        valid = false;
    if (!valid)
        return false;
    /* inspect_processes matched the original proc identities. Validate their
     * complete canonical u64 suffixes before giving snprintf a finite width;
     * the precision must never silently shorten an unchecked token. */
    if (!cliq_source_process_token_valid(ready.init_start_token) || !cliq_source_process_token_valid(process->monitor_start_token))
        return false;
    scope->identity.pid = process->worker;
    scope->identity.namespace_init_pid = process->init;
    scope->identity.pid_namespace_inode = ready.pid_namespace_inode;
    scope->identity.populated = 1;
    memcpy(scope->identity.start_token, ready.start_token, sizeof(ready.start_token));
    memcpy(scope->identity.init_native_start_token, ready.init_start_token, sizeof(ready.init_start_token));
    int             token_length = snprintf(scope->identity.init_start_token, sizeof(scope->identity.init_start_token),
        "linux-namespace-init:%ld:%.20s:monitor:%ld:%.20s", (long)process->init,
        ready.init_start_token + strlen("linux-proc-start-ticks:"), (long)process->monitor,
        process->monitor_start_token + strlen("linux-proc-start-ticks:"));
    if (token_length <= 0 || (size_t)token_length >= sizeof(scope->identity.init_start_token))
        return false;
    process->identity = scope->identity;
    process->created = true;
    scope->blocked = true;
    if (!mcp_contained_step(scope, 5))
        return false;
    int             flags = fcntl(scope->operation, F_GETFL);
    if (flags < 0 || fcntl(scope->operation, F_SETFL, flags | O_NONBLOCK))
        return false;
    *response = scope->identity;
    response->command = scope->family == MCP_CONTAINED_HTTP_ADMIN ? CLIQ_MCP_ADMIN_CREATE_BLOCKED : CLIQ_MCP_STDIO_CREATE_BLOCKED;
    return stamp_observation(response);
}
static bool
mcp_contained_stop(struct mcp_contained_resource *scope, struct cliq_worker_packet *response, unsigned command)
{
    if (!scope->attempted || !mcp_contained_root_current(scope))
        return false;
    if (scope->unreleased_stdio_shutdown && (scope->family == MCP_CONTAINED_HTTP_ADMIN || scope->released)) return false;
    struct scope   *process = &scope->process;
    if (!scope->dead) {
        for (size_t i = 0; i < 6; i++)
            if (!source_close_fd(&scope->construction[i]))
                return false;
        struct tracked_set tracked = {0};
        if (scope->created && !collect_processes(scope->cgroup, &tracked, 0))
            return false;
        if (process->monitor > 0 && !track_process(&tracked, process->monitor, process->monitor_start_token))
            return false;
        if (scope->blocked && (!track_process(&tracked, process->init, scope->identity.init_native_start_token) || !track_process(&tracked, process->worker, scope->identity.start_token)))
            return false;
        int64_t stdio_stop_start = -1;
        if (scope->family != MCP_CONTAINED_HTTP_ADMIN && scope->blocked && !scope->unreleased_stdio_shutdown) {
            stdio_stop_start = milliseconds();
            if (stdio_stop_start < 0) return false;
            if (!original_process_absent(process->init, scope->identity.init_native_start_token)) {
                char token[CLIQ_WORKER_TOKEN_BYTES];
                if (!cliq_process_token(process->init, token) || strcmp(token, scope->identity.init_native_start_token) ||
                    (kill(process->init, SIGTERM) && errno != ESRCH)) return false;
            }
            /* The fixed namespace init first kills only server descendants,
             * then drains both real pipes through native IPC and ACKs. Its
             * actual exit precedes the final empty-cgroup/FD retirement.
             * This is the same Stop2 window, never an additional grace. */
            for (;;) {
                int status; pid_t done;
                while ((done = waitpid(-1, &status, WNOHANG)) > 0) mcp_contained_note_reaped(scope, done, status);
                if (scope->monitor_joined && held_scope_dead(process) && tracked_absent(&tracked)) break;
                int64_t now = milliseconds();
                if (now < stdio_stop_start || now - stdio_stop_start >= 2000) {
                    (void)write_control(scope->cgroup, "cgroup.kill", "1");
                    return false;
                }
                struct timespec pause = {0, 1000000}; nanosleep(&pause, NULL);
            }
        }
        if (scope->created && !write_control(scope->cgroup, "cgroup.kill", "1"))
            return false;
        if (process->monitor > 0 && !scope->monitor_joined && !original_process_absent(process->monitor, process->monitor_start_token)) {
            char            token[CLIQ_WORKER_TOKEN_BYTES];
            if (!cliq_process_token(process->monitor, token) || strcmp(token, process->monitor_start_token) || (kill(process->monitor, SIGKILL) && errno != ESRCH))
                return false;
        }
        if (!source_close_fd(&scope->channel) || !source_close_fd(&scope->operation))
            return false;
        process->channel = -1;
        int64_t         start = scope->family == MCP_CONTAINED_HTTP_ADMIN ? milliseconds() : stdio_stop_start >= 0 ? stdio_stop_start : milliseconds();
        for (;;) {
            int             status;
            pid_t           done;
            while ((done = waitpid(-1, &status, WNOHANG)) > 0)
                if (done == process->monitor) {
                    scope->monitor_joined = true;
                    scope->monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                }
            bool            dead = !scope->created || (scope->blocked ? held_scope_dead(process) : cgroup_empty(scope->cgroup));
            if (dead && tracked_absent(&tracked) && (process->monitor <= 0 || scope->monitor_joined)) {
                scope->dead = true;
                break;
            } if (milliseconds() - start >= 2000)
                return false;
            struct timespec pause = {0, 10000000};
            nanosleep(&pause, NULL);
        }
        scope->identity.populated = 0;
        scope->identity.remaining_descendants = 0;
        scope->identity.init_reaped = scope->blocked ? 1 : 0;
        if (scope->family != MCP_CONTAINED_HTTP_ADMIN && scope->blocked && !scope->unreleased_stdio_shutdown &&
            (!scope->identity.stdio_owner_drained || !scope->monitor_success)) return false;
        if (!mcp_contained_step(scope, 8))
            return false;
    }
    *response = scope->identity;
    response->command = command;
    return stamp_observation(response);
}
static bool
mcp_contained_ack(struct mcp_contained_resource *scope, struct cliq_worker_packet *response, unsigned command)
{
    if (!scope->dead)
        return false;
    if (!scope->acked) {
        int            *slots[] = {&scope->stdout_fd, &scope->stderr_fd, &scope->config_fd, &scope->recipe_fd, &scope->helper, &scope->bwrap, &scope->script};
        for (size_t i = 0; i < sizeof(slots) / sizeof(*slots); i++)
            if (!source_close_fd(slots[i]))
                return false;
        for (size_t i = 0; i < CLIQ_VERIFIER_MAX_FILES; i++)
            if (!source_close_fd(&scope->files[i]))
                return false;
        if (!mcp_contained_root_current(scope) || !source_close_fd(&scope->cgroup) || unlinkat(scope->anchor, scope->identity.cgroup_name, AT_REMOVEDIR))
            return false;
        scope->created = false;
        if (!mcp_contained_step(scope, 9))
            return false;
        scope->acked = true;
    }
    *response = scope->identity;
    response->command = command;
    bool            valid = stamp_observation(response);
    if (!source_close_fd(&scope->birth) || !source_close_fd(&scope->anchor))
        valid = false;
    return valid;
}
#endif

