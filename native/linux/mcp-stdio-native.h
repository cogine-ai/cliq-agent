#ifndef CLIQ_MCP_STDIO_NATIVE_H
#define CLIQ_MCP_STDIO_NATIVE_H
#include "mcp-stdio-owner-bridge.h"
#include <sys/mman.h>
static const napi_type_tag MCP_STDIO_ADMIN_CLEANUP_TAG = {UINT64_C(0xa733bff080f24077), UINT64_C(0x98e7385b9459a512)};
static const napi_type_tag MCP_STDIO_RECOVERY_CLEANUP_TAG = {UINT64_C(0x387eba7d38104d03), UINT64_C(0x93414c46b14c136e)};
static const napi_type_tag MCP_STDIO_RUN_CLEANUP_TAG = {UINT64_C(0x1af3de639bc14d1e), UINT64_C(0xbb51452026d459f7)};
struct mcp_stdio_native_scope {
    struct cliq_mcp_stdio_peer bridge;
    struct controller *controller;
    struct cliq_mcp_admin_input *admin;
    struct cliq_mcp_stdio_run_input *run;
    struct cliq_mcp_stdio_recovery_input *recovery;
    napi_ref input_ref, recipe_ref, owner_ref, reserved_value, ready_value, joined_value, cleanup_value;
    struct cliq_worker_packet identity, observation;
    struct cliq_mcp_stdio_launch_binding binding;
    bool bound, reserved, starting, ready, released, stopping, joined, ack_started, acked, retained, io_aborted;
    unsigned pending;
    int operation;
    unsigned char *snapshot;
    size_t snapshot_size;
    unsigned char *cleanup_snapshot;
    size_t cleanup_size;
};
static int mcp_stdio_birth_fd(const struct mcp_stdio_native_scope *scope) {
    return scope->admin ? scope->admin->birth_fd : scope->recovery ? scope->recovery->birth_fd : scope->run ? scope->run->birth_fd : -1;
}
static bool mcp_stdio_retire_input(struct mcp_stdio_native_scope *scope) {
    if (scope->admin) { atomic_store(&scope->admin->execution_joined, true); return !scope->admin->retire(scope->admin); }
    if (scope->recovery) { atomic_store(&scope->recovery->execution_joined, true); return !scope->recovery->retire(scope->recovery); }
    if (scope->run) { atomic_store(&scope->run->execution_joined, true); return !scope->run->retire(scope->run); }
    return false;
}
static bool mcp_stdio_native_current(struct mcp_stdio_native_scope *scope) {
    struct controller *c = scope ? scope->controller : NULL;
    return c && scope->bridge.creator_pid == getpid() && scope->bridge.environment == c->env && syscall(SYS_gettid) == getpid() &&
        !c->retirement_failed && !atomic_load(&native_retirement_failed) &&
        (scope->acked || (c->closed && c->cleanup_queued && !c->cleanup_done) || (!c->closed && anchor_current(c) && controller_placement(c, c->token) &&
        (scope->admin ? scope->admin->assert_current && scope->admin->assert_current(scope->admin) :
        scope->recovery ? scope->recovery->assert_current && scope->recovery->assert_current(scope->recovery) :
        scope->run && scope->run->assert_current && scope->run->assert_current(scope->run))));
}
static bool mcp_stdio_peer_current(struct cliq_mcp_stdio_peer *peer) {
    return peer && peer->abi_version == CLIQ_MCP_STDIO_OWNER_ABI && mcp_stdio_native_current(peer->context);
}
static bool mcp_stdio_request(struct mcp_stdio_native_scope *scope, unsigned command, const int *files, size_t count) {
    if (!mcp_stdio_native_current(scope) || scope->acked || scope->pending || scope->controller->pending) return false;
    struct cliq_worker_packet request = scope->identity; request.command = command;
    if (!begin_request(scope->controller, NULL, &request, files, count)) return false;
    scope->pending = command; return true;
}
static void mcp_stdio_mark_failure(struct mcp_stdio_native_scope *scope) {
    scope->controller->retirement_failed = true; atomic_store(&native_retirement_failed, true);
}
static int mcp_stdio_poll_pending(struct mcp_stdio_native_scope *scope) {
    if (scope->controller->closed) return scope->acked ? 1 : scope->controller->cleanup_done ? -1 : 0;
    if (!scope->pending) return 1;
    struct controller *c = scope->controller;
    if (!mcp_stdio_native_current(scope) || c->pending != scope->pending || c->pending_scope) return -1;
    struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    if (!cliq_receive_flags(c->socket, &response, files, CLIQ_WORKER_MAX_FDS, &count, MSG_DONTWAIT)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        mcp_stdio_mark_failure(scope); return -1;
    }
    unsigned command = scope->pending; scope->pending = 0; c->pending = 0;
    bool valid = response.status == 0 && response.command == command &&
        cliq_mcp_stdio_packet_closed(&response) && cliq_mcp_stdio_packet_same(&response, &scope->identity);
    if (valid && command == CLIQ_MCP_STDIO_RESERVE) {
        valid = !count && response.cgroup_inode && !response.populated;
        if (valid) { scope->reserved = true; scope->identity = response; }
    } else if (valid && command == CLIQ_MCP_STDIO_CREATE_BLOCKED) {
        valid = count == 1 && scope->operation < 0 && response.pid > 0 && response.namespace_init_pid > 0 &&
            response.populated == 1 && !response.init_reaped;
        int kind = 0; socklen_t size = sizeof(kind);
        valid = valid && !getsockopt(files[0], SOL_SOCKET, SO_TYPE, &kind, &size) && size == sizeof(kind) && kind == SOCK_STREAM;
        if (valid) {
            int flags = fcntl(files[0], F_GETFL);
            valid = flags >= 0 && !fcntl(files[0], F_SETFL, flags | O_NONBLOCK);
        }
        if (valid) { scope->operation = files[0]; files[0] = -1; scope->ready = true; scope->identity = response; }
    } else if (valid && command == CLIQ_MCP_STDIO_CLEANUP_RETAINED) {
        valid = !count && scope->retained && !response.populated && !response.remaining_descendants &&
            response.reservation_observation == scope->identity.reservation_observation &&
            response.cgroup_device == scope->identity.cgroup_device && response.cgroup_inode == scope->identity.cgroup_inode &&
            response.stdio_checker_owner_epoch == scope->identity.stdio_checker_owner_epoch &&
            response.stdio_checker_supervisor_pid == scope->identity.stdio_checker_supervisor_pid &&
            !strcmp(response.stdio_checker_supervisor_id, scope->identity.stdio_checker_supervisor_id) &&
            !strcmp(response.stdio_checker_supervisor_token, scope->identity.stdio_checker_supervisor_token) &&
            !strcmp(response.stdio_original_birth_digest, scope->identity.stdio_original_birth_digest);
        if (valid) scope->joined = true;
    } else if (valid && command == CLIQ_MCP_STDIO_RELEASE_EXEC) valid = !count && scope->released;
    else if (valid && (command == CLIQ_MCP_STDIO_POLL || command == CLIQ_MCP_STDIO_STOP)) {
        valid = !count;
        if (valid && !response.populated && !response.remaining_descendants && (!scope->ready || response.init_reaped == 1))
            scope->joined = command == CLIQ_MCP_STDIO_STOP || scope->ready;
    } else if (valid && command == CLIQ_MCP_STDIO_ACK) {
        struct cliq_mcp_stdio_history history;
        valid = !count && scope->joined && atomic_load(&scope->bridge.io_joined) &&
            cliq_mcp_stdio_read_history(mcp_stdio_birth_fd(scope), &history, &scope->snapshot, &scope->snapshot_size) &&
            history.count && history.last.kind == 9 && !history.last.packet.populated && !history.last.packet.remaining_descendants &&
            history.last.packet.stdio_owner_drained;
        struct stat named;
        valid = valid && fstatat(c->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
            retire_descriptor(&scope->operation);
        if (valid) {
            valid = mcp_stdio_retire_input(scope);
        }
        if (valid) {
            scope->acked = true;
            atomic_store(&scope->bridge.physical_joined, true); atomic_store(&scope->bridge.output_retired, true);
            if (scope->owner_ref) { napi_delete_reference(c->env, scope->owner_ref); scope->owner_ref = NULL; }
        }
    } else valid = false;
    if (valid) scope->observation = response;
    for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
    if (!valid) { mcp_stdio_mark_failure(scope); return -1; }
    return 1;
}
static bool mcp_stdio_bind_peer(struct cliq_mcp_stdio_peer *peer, const struct cliq_mcp_stdio_launch_binding *binding) {
    struct mcp_stdio_native_scope *scope = peer->context;
    if (!mcp_stdio_peer_current(peer) || scope->controller->closed || binding->purpose != peer->purpose) return false;
    if (scope->bound) return !memcmp(&scope->binding, binding, sizeof(*binding));
    bool valid;
    if (scope->admin) {
        const struct cliq_mcp_admin_birth *id = &scope->admin->binding;
        const struct cliq_mcp_admin_binding *b = &binding->admin;
        valid = !strcmp(id->operation, b->operation) && !strcmp(id->principal, b->principal) && id->attempt == b->attempt &&
            !strcmp(id->nonce, binding->nonce) && !strcmp(id->target_ref, b->target_ref) && !strcmp(id->target_digest, b->target_digest) &&
            !strcmp(id->core_ref, b->core_ref) && !strcmp(id->core_digest, b->core_digest) && !strcmp(id->plan_ref, b->plan_ref) &&
            !strcmp(id->plan_digest, b->plan_digest) && !strcmp(id->spec_ref, b->spec_ref) && !strcmp(id->spec_digest, b->spec_digest) &&
            b->deadline_ms == scope->identity.stdio_launch_deadline_ms && scope->identity.stdio_call_deadline_ms == b->deadline_ms;
    } else if (scope->recovery) valid = !memcmp(&scope->recovery->binding.identity, &binding->recovery, sizeof(binding->recovery)) &&
        !strcmp(binding->nonce, binding->recovery.nonce) && !strcmp(binding->token_digest, binding->recovery.brokerFenceTokenDigest) &&
        scope->identity.stdio_launch_deadline_ms == binding->recovery.probeDeadlineAtMs &&
        scope->identity.stdio_call_deadline_ms == binding->recovery.probeDeadlineAtMs;
    else valid = scope->run && !memcmp(&scope->run->binding.identity, &binding->run, sizeof(binding->run)) &&
        !strcmp(binding->nonce, binding->run.nonce);
    if (valid) { scope->binding = *binding; scope->bound = true; }
    return valid;
}
static int mcp_stdio_peer_release(struct cliq_mcp_stdio_peer *peer) {
    struct mcp_stdio_native_scope *scope = peer->context;
    if (!mcp_stdio_peer_current(peer) || scope->controller->closed || !scope->bound || !scope->ready || scope->released || scope->stopping ||
        atomic_load(&peer->revoked) || mcp_stdio_poll_pending(scope) != 1) return -1;
    scope->released = true;
    return mcp_stdio_request(scope, CLIQ_MCP_STDIO_RELEASE_EXEC, NULL, 0) ? 1 : -1;
}
static int mcp_stdio_peer_fd(struct cliq_mcp_stdio_peer *peer) {
    struct mcp_stdio_native_scope *scope = peer->context;
    return mcp_stdio_peer_current(peer) && scope->ready ? scope->operation : -1;
}
static int mcp_stdio_peer_cancel(struct cliq_mcp_stdio_peer *peer, bool abort_io) {
    struct mcp_stdio_native_scope *scope = peer->context;
    if (abort_io) {
        // The original producer can still be revoked after currentness or
        // protocol failure. This cannot create missing EOF/ACK observations.
        struct controller *c = scope ? scope->controller : NULL;
        if (!c || peer != &scope->bridge || peer->abi_version != CLIQ_MCP_STDIO_OWNER_ABI ||
            peer->creator_pid != getpid() || c->creator_pid != getpid() || peer->environment != c->env || syscall(SYS_gettid) != getpid()) return -1;
        atomic_store(&peer->revoked, true); scope->stopping = scope->io_aborted = true;
        bool revoked = true;
        if (scope->ready && !scope->joined) {
            // The failed IPC consumer cannot drain/ACK any more. Revoke its
            // exact original namespace init now; waiting for graceful drain
            // would consume Stop2 before controller cleanup could complete.
            // A different PID lifetime is never a signal target or a proof.
            int process = (int)syscall(SYS_pidfd_open, (pid_t)scope->identity.namespace_init_pid, 0);
            int opened_error = process < 0 ? errno : 0;
            struct process_sample current;
            revoked = (process >= 0 || opened_error == ESRCH) &&
                sample_process(c, (pid_t)scope->identity.namespace_init_pid, &current, false);
            if (revoked && !current.absent && !strcmp(current.token, scope->identity.init_native_start_token))
                revoked = process >= 0 && (!syscall(SYS_pidfd_send_signal, process, SIGKILL, NULL, 0) || errno == ESRCH);
            // Pin before observing the start identity, then signal that pin.
            // A PID reused between observation and revocation is never killed.
            if (!retire_descriptor(&process)) revoked = false;
        }
        // Queue the original controller join even if the independent exact
        // revocation observation failed. Neither result creates kind9/ACK.
        bool queued = close_controller(c);
        if (!revoked) mcp_stdio_mark_failure(scope);
        return queued && revoked ? 1 : -1;
    }
    if (!mcp_stdio_peer_current(peer)) return -1;
    atomic_store(&peer->revoked, true); scope->stopping = true;
    if (!scope->ready || scope->joined) return 1;
    struct process_sample current;
    if (!sample_process(scope->controller, (pid_t)scope->identity.namespace_init_pid, &current, false)) return -1;
    if (current.absent || strcmp(current.token, scope->identity.init_native_start_token)) return current.absent ? 1 : -1;
    return !kill((pid_t)scope->identity.namespace_init_pid, SIGTERM) || errno == ESRCH ? 1 : -1;
}
static int mcp_stdio_peer_progress(struct cliq_mcp_stdio_peer *peer, const struct cliq_mcp_stdio_owner_progress *progress) {
    struct mcp_stdio_native_scope *scope = peer->context;
    if (!mcp_stdio_peer_current(peer) || progress->phase > peer->recipe->header.phase_count ||
        progress->phase < scope->identity.stdio_phase || (peer->purpose == CLIQ_MCP_STDIO_RECOVERY ? progress->status_released : progress->effect_released) < !!scope->identity.stdio_operation_released ||
        !cliq_mcp_stdio_release_flags_valid(peer->purpose, progress->effect_released, progress->status_released) ||
        progress->protocol_complete < !!scope->identity.stdio_protocol_complete ||
        progress->response_refused < !!scope->identity.stdio_response_refused || progress->owner_drained < !!scope->identity.stdio_owner_drained) return -1;
    scope->identity.stdio_phase = progress->phase; scope->identity.stdio_operation_released = peer->purpose == CLIQ_MCP_STDIO_RECOVERY ? progress->status_released : progress->effect_released;
    scope->identity.stdio_protocol_complete = progress->protocol_complete; scope->identity.stdio_response_refused = progress->response_refused;
    scope->identity.stdio_owner_drained = progress->owner_drained;
    if (progress->owner_drained) atomic_store(&peer->io_joined, true);
    return 1;
}
static struct mcp_stdio_native_scope *mcp_stdio_receiver(napi_env env, napi_callback_info info, size_t *argc, napi_value *args) {
    napi_value self; struct mcp_stdio_native_scope *scope = NULL;
    if (napi_get_cb_info(env, info, argc, args, &self, NULL) != napi_ok ||
        (!tagged(env, self, &CLIQ_MCP_STDIO_ADMIN_PEER_TAG, (void **)&scope) && !tagged(env, self, &CLIQ_MCP_STDIO_RUN_PEER_TAG, (void **)&scope) && !tagged(env, self, &CLIQ_MCP_STDIO_RECOVERY_PEER_TAG, (void **)&scope) &&
         !tagged(env, self, &MCP_STDIO_ADMIN_CLEANUP_TAG, (void **)&scope) && !tagged(env, self, &MCP_STDIO_RUN_CLEANUP_TAG, (void **)&scope) && !tagged(env, self, &MCP_STDIO_RECOVERY_CLEANUP_TAG, (void **)&scope)) ||
        !scope || scope->bridge.environment != env || !mcp_stdio_native_current(scope)) {
        failure(env, "Invalid genuine MCP stdio scope"); return NULL;
    }
    return scope;
}
static napi_value mcp_stdio_observation(napi_env env, struct mcp_stdio_native_scope *scope, unsigned kind) {
    napi_ref *held = kind == 1 ? &scope->reserved_value : &scope->ready_value;
    napi_value value;
    if (*held) { napi_get_reference_value(env, *held, &value); return value; }
    value = scope_observation(env, kind == 1 ? &scope->identity : &scope->observation);
    if (napi_create_reference(env, value, 1, held) != napi_ok) return NULL;
    return value;
}
static napi_value mcp_stdio_poll_reserved(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    int state = mcp_stdio_poll_pending(scope);
    if (state < 0) return failure(env, "MCP stdio reservation refused");
    return scope->reserved ? mcp_stdio_observation(env, scope, 1) : undefined(env);
}
static napi_value mcp_stdio_create(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (!scope->reserved || scope->starting || scope->stopping || !mcp_stdio_request(scope, CLIQ_MCP_STDIO_CREATE_BLOCKED, NULL, 0))
        return failure(env, "MCP stdio original creation refused");
    scope->starting = true; return undefined(env);
}
static napi_value mcp_stdio_poll_ready(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    int state = mcp_stdio_poll_pending(scope);
    if (state < 0) return failure(env, "MCP stdio actual READY refused");
    return scope->ready ? mcp_stdio_observation(env, scope, 2) : undefined(env);
}
static napi_value mcp_stdio_assert_observation(napi_env env, napi_callback_info info, bool ready) {
    size_t argc = 2; napi_value args[2], actual;
    struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    napi_ref held = ready ? scope->ready_value : scope->reserved_value; bool same = false;
    if (argc != 1 || !held || napi_get_reference_value(env, held, &actual) != napi_ok ||
        napi_strict_equals(env, args[0], actual, &same) != napi_ok || !same || (ready ? !scope->ready : !scope->reserved))
        return failure(env, "MCP stdio observation is not its original native scope");
    return undefined(env);
}
static napi_value mcp_stdio_assert_reserved(napi_env e, napi_callback_info i) { return mcp_stdio_assert_observation(e, i, false); }
static napi_value mcp_stdio_assert_ready(napi_env e, napi_callback_info i) { return mcp_stdio_assert_observation(e, i, true); }
static napi_value mcp_stdio_stop(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (mcp_stdio_peer_cancel(&scope->bridge, false) < 0) return failure(env, "MCP stdio exact init revocation refused");
    return undefined(env);
}
static napi_value mcp_stdio_join_value(napi_env env, struct mcp_stdio_native_scope *scope) {
    napi_value value;
    if (scope->joined_value) { napi_get_reference_value(env, scope->joined_value, &value); return value; }
    napi_create_object(env, &value); napi_value observation = scope_observation(env, &scope->observation), flag;
    napi_set_named_property(env, value, "observation", observation); napi_get_boolean(env, true, &flag); napi_set_named_property(env, value, "deathJoined", flag);
    napi_get_boolean(env, scope->acked, &flag); napi_set_named_property(env, value, "outputAcknowledged", flag); napi_set_named_property(env, value, "outputCustodyRetired", flag);
    napi_object_freeze(env, value);
    if (scope->acked && napi_create_reference(env, value, 1, &scope->joined_value) != napi_ok) return NULL;
    return value;
}
static napi_value mcp_stdio_poll_joined(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (scope->io_aborted) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP stdio original operation failed before complete capture retirement"); return NULL;
    }
    int state = mcp_stdio_poll_pending(scope);
    if (state < 0) return failure(env, "MCP stdio physical retirement refused");
    if (!state) return undefined(env);
    if (!scope->joined && !scope->acked && !scope->controller->closed) {
        if (scope->stopping && (!scope->ready || atomic_load(&scope->bridge.io_joined))) {
            if (!mcp_stdio_request(scope, CLIQ_MCP_STDIO_STOP, NULL, 0)) return failure(env, "MCP stdio original stop dispatch refused");
        } else if (scope->ready && !mcp_stdio_request(scope, CLIQ_MCP_STDIO_POLL, NULL, 0)) return failure(env, "MCP stdio original poll dispatch refused");
    }
    return scope->joined ? mcp_stdio_join_value(env, scope) : undefined(env);
}
static napi_value mcp_stdio_assert_joined(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2], value; bool same = false;
    struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc != 1 || !scope->acked || !scope->joined || !scope->joined_value ||
        !atomic_load(&scope->bridge.io_joined) || !atomic_load(&scope->bridge.output_retired) ||
        napi_get_reference_value(env, scope->joined_value, &value) != napi_ok || napi_strict_equals(env, value, args[0], &same) != napi_ok || !same) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP stdio original scope has not fully retired"); return NULL;
    }
    return undefined(env);
}
static napi_value mcp_stdio_begin_ack(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (scope->retained) {
        if (!scope->joined || scope->pending || scope->ack_started) return failure(env, "MCP stdio current checker has no authenticated cleanup join");
        bool valid;
        valid = mcp_stdio_retire_input(scope);
        if (!valid) { mcp_stdio_mark_failure(scope); return failure(env, "MCP stdio current input custody did not retire"); }
        scope->ack_started = scope->acked = true;
        atomic_store(&scope->bridge.io_joined, true); atomic_store(&scope->bridge.physical_joined, true); atomic_store(&scope->bridge.output_retired, true);
        return undefined(env);
    }
    if (!scope->joined || !atomic_load(&scope->bridge.io_joined) || scope->ack_started || !mcp_stdio_request(scope, CLIQ_MCP_STDIO_ACK, NULL, 0))
        return failure(env, "MCP stdio original output ACK refused");
    scope->ack_started = true; return undefined(env);
}
static napi_value mcp_stdio_poll_ack(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (mcp_stdio_poll_pending(scope) < 0) return failure(env, "MCP stdio output ACK failed");
    napi_value value; napi_get_boolean(env, scope->acked, &value); return value;
}
static napi_value mcp_stdio_snapshot(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (!scope->acked || !scope->snapshot) return undefined(env);
    napi_value value; if (napi_create_buffer_copy(env, scope->snapshot_size, scope->snapshot, NULL, &value) != napi_ok) return NULL;
    return value;
}
static napi_value mcp_stdio_reobserve_admin_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1], self;
    struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc || !scope->admin || scope->retained || scope->io_aborted || !scope->bound || !scope->released || !scope->joined || !scope->acked ||
        scope->pending || scope->operation >= 0 || !scope->snapshot || !atomic_load(&scope->bridge.io_joined) ||
        !atomic_load(&scope->bridge.physical_joined) || !atomic_load(&scope->bridge.output_retired) ||
        napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok)
        return failure(env, "MCP stdio Admin has no complete original retirement to reobserve");
    return mcp_admin_original_value(env, self, scope, scope->controller, scope->admin, scope->snapshot, scope->snapshot_size,
        &scope->binding.admin, CLIQ_MCP_ADMIN_ORIGINAL_STDIO);
}
static napi_value mcp_stdio_assert_admin_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2];
    struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc != 1 || !scope->admin || scope->retained || scope->io_aborted || !scope->joined || !scope->acked || scope->pending || scope->operation >= 0)
        return failure(env, "MCP stdio Admin original current observation is unavailable");
    return mcp_admin_original_assert(env, scope, scope->controller, args[0], CLIQ_MCP_ADMIN_ORIGINAL_STDIO);
}
static void mcp_stdio_native_finalize(napi_env env, void *data, void *hint) {
    (void)hint; struct mcp_stdio_native_scope *scope = data;
    if (!scope->acked) mcp_stdio_mark_failure(scope);
    if (!retire_descriptor(&scope->operation)) mcp_stdio_mark_failure(scope);
    napi_ref refs[] = {scope->input_ref, scope->recipe_ref, scope->owner_ref, scope->reserved_value, scope->ready_value, scope->joined_value, scope->cleanup_value};
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) if (refs[i]) napi_delete_reference(env, refs[i]);
    if (scope->controller->mcp_stdio == scope) scope->controller->mcp_stdio = NULL;
    free(scope->snapshot); free(scope->cleanup_snapshot); controller_release(scope->controller); free(scope);
}
static void mcp_stdio_native_joined(struct controller *c) {
    struct mcp_stdio_native_scope *scope = c->mcp_stdio;
    if (!scope || scope->acked || scope->retained || scope->io_aborted) return;
    struct cliq_mcp_stdio_history history;
    bool valid = cliq_mcp_stdio_read_history(mcp_stdio_birth_fd(scope), &history, &scope->snapshot, &scope->snapshot_size) &&
        history.count && history.last.kind == 9 && !history.last.packet.populated && !history.last.packet.remaining_descendants &&
        (!scope->ready || history.last.packet.init_reaped == 1) && history.last.packet.stdio_owner_drained;
    struct stat named;
    valid = valid && fstatat(c->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (valid) { scope->observation = history.last.packet; scope->joined = scope->acked = true; }
    else c->retirement_failed = true;
}
static void mcp_stdio_native_complete(napi_env env, struct controller *c) {
    struct mcp_stdio_native_scope *scope = c->mcp_stdio;
    if (!scope) return;
    bool operation_closed = c->env == env && c->creator_pid == getpid() && syscall(SYS_gettid) == getpid() &&
        c->closed && c->cleanup_done && retire_descriptor(&scope->operation);
    if (!operation_closed) c->retirement_failed = true;
    else {
        atomic_store(&scope->bridge.operation_closed, true);
        if (scope->owner_ref) { napi_delete_reference(env, scope->owner_ref); scope->owner_ref = NULL; }
    }
    if (!scope->acked || scope->io_aborted) return;
    if (c->env != env || c->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
        !c->closed || !c->cleanup_done || !c->reaped || c->retirement_failed || !scope->joined ||
        !atomic_load(&scope->bridge.io_joined) || !operation_closed) { c->retirement_failed = true; return; }
    if (scope->retained && (scope->pending || !scope->cleanup_snapshot || !scope->cleanup_value)) { c->retirement_failed = true; return; }
    if (!mcp_stdio_retire_input(scope)) c->retirement_failed = true;
    if (scope->pending) {
        if (scope->pending < CLIQ_MCP_STDIO_RESERVE || scope->pending > CLIQ_MCP_STDIO_ACK || c->pending != scope->pending || c->pending_scope) c->retirement_failed = true;
        else { c->pending = 0; scope->pending = 0; }
    }
    if (!c->retirement_failed) { atomic_store(&scope->bridge.physical_joined, true); atomic_store(&scope->bridge.output_retired, true); }
}
static bool mcp_stdio_server_current(napi_env env, const struct cliq_mcp_stdio_server_image *image) {
    return image && image->abi_version == CLIQ_MCP_STDIO_OWNER_ABI && image->creator_pid == getpid() &&
        image->environment == env && syscall(SYS_gettid) == getpid();
}
static void mcp_stdio_server_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct cliq_mcp_stdio_server_image *image = data;
    (void)retire_descriptor(&image->fd); free(image);
}
static napi_value mcp_stdio_server_close(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct cliq_mcp_stdio_server_image *image = NULL;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, NULL) != napi_ok ||
        !tagged(env, self, &CLIQ_MCP_STDIO_SERVER_TAG, (void **)&image) || !mcp_stdio_server_current(env, image))
        return failure(env, "Invalid original MCP stdio server image");
    if (!retire_descriptor(&image->fd)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "MCP server image descriptor did not retire"); return NULL;
    }
    return undefined(env);
}
static napi_value seal_mcp_stdio_server(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2]; uint64_t source;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        syscall(SYS_gettid) != getpid() || !number(env, args[0], &source) || source > INT32_MAX ||
        atomic_load(&native_retirement_failed)) return failure(env, "MCP server seal requires its original held signed file");
    struct stat before, after;
    if (fstat((int)source, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 1 || before.st_size <= 0 ||
        (uint64_t)before.st_size > CLIQ_MCP_STDIO_EXECUTABLE_CAP || (before.st_mode & 0022) ||
        (before.st_uid != geteuid() && before.st_uid != 0)) return failure(env, "Unsafe held MCP server file");
    int sealed = memfd_create("cliq-mcp-stdio-server", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    bool valid = sealed >= 0; unsigned char bytes[65536]; uint64_t at = 0;
    while (valid && at < (uint64_t)before.st_size) {
        size_t wanted = (uint64_t)before.st_size - at < sizeof(bytes) ? (size_t)((uint64_t)before.st_size - at) : sizeof(bytes);
        ssize_t count = pread((int)source, bytes, wanted, (off_t)at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = false; break; }
        for (size_t wrote = 0; wrote < (size_t)count;) {
            ssize_t n = write(sealed, bytes + wrote, (size_t)count - wrote);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { valid = false; break; }
            wrote += (size_t)n;
        }
        at += (uint64_t)count;
    }
    valid = valid && at == (uint64_t)before.st_size && !fstat((int)source, &after) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
        before.st_mode == after.st_mode && before.st_nlink == after.st_nlink && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
        !fchmod(sealed, 0500) && !fcntl(sealed, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    void *mapping = valid ? mmap(NULL, (size_t)before.st_size, PROT_READ, MAP_PRIVATE, sealed, 0) : MAP_FAILED;
    valid = valid && mapping != MAP_FAILED && cliq_mcp_stdio_static_elf(mapping, (size_t)before.st_size);
    if (mapping != MAP_FAILED && munmap(mapping, (size_t)before.st_size)) valid = false;
    struct cliq_mcp_stdio_server_image *image = valid ? calloc(1, sizeof(*image)) : NULL;
    if (!image) valid = false;
    if (valid) {
        image->abi_version = CLIQ_MCP_STDIO_OWNER_ABI; image->creator_pid = getpid(); image->environment = env;
        image->fd = sealed; image->byte_count = (uint64_t)before.st_size;
        valid = mcp_admin_native_hash_fd(sealed, image->byte_count, image->digest);
    }
    napi_value result, identity;
    const napi_property_descriptor method = {"close", NULL, mcp_stdio_server_close, NULL, NULL, NULL, napi_default, NULL};
    if (valid) valid = napi_create_object(env, &result) == napi_ok && napi_create_object(env, &identity) == napi_ok;
    if (valid) {
        set_string(env, identity, "sha256", image->digest); set_number(env, identity, "byteCount", (double)image->byte_count);
        valid = napi_object_freeze(env, identity) == napi_ok && napi_set_named_property(env, result, "identity", identity) == napi_ok &&
            napi_type_tag_object(env, result, &CLIQ_MCP_STDIO_SERVER_TAG) == napi_ok &&
            napi_define_properties(env, result, 1, &method) == napi_ok &&
            napi_wrap(env, result, image, mcp_stdio_server_finalize, NULL, NULL) == napi_ok;
    }
    if (!valid) { (void)retire_descriptor(&sealed); free(image); return failure(env, "Exact static MCP server sealing refused"); }
    napi_object_freeze(env, result); return result;
}
static napi_value reserve_mcp_stdio(napi_env env, napi_callback_info info, unsigned purpose) {
    size_t argc = 7; napi_value args[7], self, result;
    struct controller *c = NULL; struct cliq_mcp_admin_input *admin = NULL; struct cliq_mcp_stdio_run_input *run = NULL; struct cliq_mcp_stdio_recovery_input *recovery = NULL;
    struct image *helper = NULL, *bwrap = NULL; struct cliq_mcp_stdio_recipe *recipe = NULL; struct cliq_mcp_stdio_server_image *server = NULL;
    bool buffer = false; void *bytes = NULL; size_t size = 0;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 6 || syscall(SYS_gettid) != getpid() ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&c) || c->env != env || c->creator_pid != getpid() ||
        c->closed || !c->ready || c->pending || c->scopes || c->mcp_admin || c->mcp_stdio || c->source_requested || c->worker_creation_requested || c->retained_requested ||
        !controller_placement(c, c->token) ||
        !tagged(env, args[1], &IMAGE_TAG, (void **)&helper) || helper->fd < 0 ||
        !tagged(env, args[2], &IMAGE_TAG, (void **)&bwrap) || bwrap->fd < 0 ||
        !tagged(env, args[3], purpose == CLIQ_MCP_STDIO_ADMIN ? &CLIQ_MCP_STDIO_ADMIN_RECIPE_TAG : purpose == CLIQ_MCP_STDIO_RECOVERY ? &CLIQ_MCP_STDIO_RECOVERY_RECIPE_TAG : &CLIQ_MCP_STDIO_RUN_RECIPE_TAG, (void **)&recipe) ||
        recipe->abi_version != CLIQ_MCP_STDIO_OWNER_ABI || recipe->purpose != purpose || recipe->creator_pid != getpid() ||
        recipe->environment != env || recipe->fd < 0 || recipe->consumed || !recipe->register_peer || !recipe->owner_value ||
        !tagged(env, args[4], &CLIQ_MCP_STDIO_SERVER_TAG, (void **)&server) || !mcp_stdio_server_current(env, server) || server->fd < 0 ||
        server->byte_count != recipe->header.server_bytes || strcmp(server->digest, recipe->header.server_digest) ||
        napi_is_buffer(env, args[5], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[5], &bytes, &size) != napi_ok ||
        size != sizeof(struct cliq_mcp_stdio_limits)) return failure(env, "MCP stdio requires exact original purpose inputs and signed images");
    if (purpose == CLIQ_MCP_STDIO_ADMIN) {
        if (!tagged(env, args[0], &CLIQ_MCP_STDIO_ADMIN_INPUT_TAG, (void **)&admin) ||
            admin->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI || admin->creator_pid != getpid() || admin->environment != env ||
            !admin->assert_current || !admin->assert_current(admin) || !admin->retire ||
            admin->binding.magic != CLIQ_MCP_STDIO_ADMIN_BIRTH_MAGIC || atomic_load(&admin->closed) || atomic_load(&admin->execution_claimed))
            return failure(env, "MCP stdio Admin input is not its original execution custody");
    } else if (purpose == CLIQ_MCP_STDIO_RECOVERY) {
        if (!tagged(env, args[0], &CLIQ_MCP_STDIO_RECOVERY_INPUT_TAG, (void **)&recovery) ||
            recovery->abi_version != CLIQ_MCP_STDIO_RECOVERY_INPUT_ABI || recovery->creator_pid != getpid() || recovery->environment != env ||
            !recovery->assert_current || !recovery->assert_current(recovery) || !recovery->retire ||
            recovery->binding.magic != CLIQ_MCP_STDIO_RECOVERY_BIRTH_MAGIC || atomic_load(&recovery->closed) || atomic_load(&recovery->execution_claimed))
            return failure(env, "MCP stdio recovery input is not its original probe custody");
    } else if (purpose != CLIQ_MCP_STDIO_RUN || !tagged(env, args[0], &CLIQ_MCP_STDIO_RUN_INPUT_TAG, (void **)&run) ||
        run->abi_version != CLIQ_MCP_STDIO_RUN_INPUT_ABI || run->creator_pid != getpid() || run->environment != env ||
        !run->assert_current || !run->assert_current(run) || !run->retire ||
        run->binding.magic != CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC || atomic_load(&run->closed) || atomic_load(&run->execution_claimed))
        return failure(env, "MCP stdio Run input is not its original execution custody");
    struct cliq_mcp_stdio_limits limits; memcpy(&limits, bytes, sizeof(limits));
    if (!cliq_mcp_stdio_limits_valid(&limits) || limits.purpose != purpose || limits.max_output_bytes != recipe->header.maximum_output_bytes ||
        (run && (run->binding.identity.launch_deadline_ms != limits.launch_deadline_ms || run->binding.identity.call_deadline_ms != limits.call_deadline_ms)) ||
        (recovery && (recovery->binding.identity.probeDeadlineAtMs != limits.launch_deadline_ms || recovery->binding.identity.probeDeadlineAtMs != limits.call_deadline_ms)))
        return failure(env, "MCP stdio original resource/deadline data differs");
    struct cliq_mcp_stdio_history history;
    int birth_fd = admin ? admin->birth_fd : recovery ? recovery->birth_fd : run->birth_fd;
    if (!cliq_mcp_stdio_read_history(birth_fd, &history, NULL, NULL) || history.count)
        return failure(env, "MCP stdio input already has physical birth progress");
    struct mcp_stdio_native_scope *scope = calloc(1, sizeof(*scope));
    if (!scope) return failure(env, "MCP stdio scope allocation unavailable");
    scope->controller = c; scope->admin = admin; scope->run = run; scope->recovery = recovery; scope->operation = -1;
    scope->bridge.abi_version = CLIQ_MCP_STDIO_OWNER_ABI; scope->bridge.purpose = purpose; scope->bridge.creator_pid = getpid();
    scope->bridge.environment = env; scope->bridge.context = scope; scope->bridge.recipe = recipe;
    scope->bridge.assert_current = mcp_stdio_peer_current; scope->bridge.bind_launch = mcp_stdio_bind_peer;
    scope->bridge.release_exec = mcp_stdio_peer_release; scope->bridge.operation_fd = mcp_stdio_peer_fd;
    scope->bridge.cancel = mcp_stdio_peer_cancel; scope->bridge.progress = mcp_stdio_peer_progress;
    atomic_init(&scope->bridge.revoked, false); atomic_init(&scope->bridge.io_joined, false);
    atomic_init(&scope->bridge.physical_joined, false); atomic_init(&scope->bridge.output_retired, false);
    atomic_init(&scope->bridge.operation_closed, false);
    struct cliq_worker_packet *request = &scope->identity; *request = cliq_packet(CLIQ_MCP_STDIO_RESERVE); request->stdio_purpose = purpose;
    const char *nonce = admin ? admin->binding.nonce : recovery ? recovery->binding.identity.nonce : run->binding.identity.nonce;
    memcpy(request->nonce, nonce, 65);
    memcpy(request->plan_ref, admin ? admin->binding.plan_ref : recovery ? recovery->binding.identity.plannedContainmentRef : run->binding.identity.plan_ref, 65);
    memcpy(request->sandbox_launch_ref, admin ? admin->binding.spec_ref : recovery ? recovery->binding.identity.sandboxLaunchSpecRef : run->binding.identity.spec_ref, 65);
    memcpy(request->sandbox_launch_digest, admin ? admin->binding.spec_digest : recovery ? recovery->binding.identity.sandboxLaunchSpecDigest : run->binding.identity.spec_digest, 65);
    const char *purpose_name = purpose == CLIQ_MCP_STDIO_ADMIN ? "admin" : purpose == CLIQ_MCP_STDIO_RECOVERY ? "recovery" : "run";
    int name = snprintf(request->cgroup_name, sizeof(request->cgroup_name), "cliq-mcp-stdio-%s-%.64s", purpose_name, nonce);
    int ns = snprintf(request->pid_namespace_reservation, sizeof(request->pid_namespace_reservation), "linux-mcp-stdio:%s:%.64s", purpose_name, nonce);
    bool valid = name > 0 && (size_t)name < sizeof(request->cgroup_name) && ns > 0 && (size_t)ns < sizeof(request->pid_namespace_reservation);
    const unsigned char *input_digest = admin ? admin->binding.digest : recovery ? recovery->binding.digest : run->binding.digest;
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { request->stdio_input_digest[i * 2] = alphabet[input_digest[i] >> 4]; request->stdio_input_digest[i * 2 + 1] = alphabet[input_digest[i] & 15]; }
    memcpy(request->stdio_recipe_digest, recipe->digest, 65); request->stdio_recipe_bytes = recipe->size;
    memcpy(request->stdio_server_digest, server->digest, 65); request->stdio_server_bytes = server->byte_count;
    struct stat helper_stat, bwrap_stat;
    valid = valid && !fstat(helper->fd, &helper_stat) && !fstat(bwrap->fd, &bwrap_stat) && helper_stat.st_size > 0 && bwrap_stat.st_size > 0 &&
        (uint64_t)helper_stat.st_size <= CLIQ_MCP_STDIO_EXECUTABLE_CAP && (uint64_t)bwrap_stat.st_size <= CLIQ_MCP_STDIO_EXECUTABLE_CAP;
    request->stdio_init_bytes = valid ? (uint64_t)helper_stat.st_size : 0; request->stdio_bwrap_bytes = valid ? (uint64_t)bwrap_stat.st_size : 0;
    valid = valid && mcp_admin_native_hash_fd(helper->fd, request->stdio_init_bytes, request->stdio_init_digest) &&
        mcp_admin_native_hash_fd(bwrap->fd, request->stdio_bwrap_bytes, request->stdio_bwrap_digest) &&
        (!recovery || !strcmp(request->stdio_init_digest, recovery->binding.identity.adapterExecutableDigest));
    request->max_processes = limits.max_processes; request->memory_bytes = limits.memory_bytes; request->cpu_quota = limits.cpu_quota;
    request->max_open_files = limits.max_open_files; request->max_file_bytes = limits.max_file_bytes;
    request->max_generation_bytes = limits.max_generation_bytes; request->max_output_bytes = limits.max_output_bytes;
    request->stdio_launch_deadline_ms = limits.launch_deadline_ms; request->stdio_call_deadline_ms = limits.call_deadline_ms;
    request->subreaper_pid = c->pid; memcpy(request->subreaper_start_token, c->token, sizeof(request->subreaper_start_token));
    const napi_property_descriptor methods[] = {
        {"pollReserved", NULL, mcp_stdio_poll_reserved, NULL, NULL, NULL, napi_default, NULL},
        {"assertReserved", NULL, mcp_stdio_assert_reserved, NULL, NULL, NULL, napi_default, NULL},
        {"createBlocked", NULL, mcp_stdio_create, NULL, NULL, NULL, napi_default, NULL},
        {"pollReady", NULL, mcp_stdio_poll_ready, NULL, NULL, NULL, napi_default, NULL},
        {"assertReady", NULL, mcp_stdio_assert_ready, NULL, NULL, NULL, napi_default, NULL},
        {"stop", NULL, mcp_stdio_stop, NULL, NULL, NULL, napi_default, NULL},
        {"pollJoined", NULL, mcp_stdio_poll_joined, NULL, NULL, NULL, napi_default, NULL},
        {"assertJoined", NULL, mcp_stdio_assert_joined, NULL, NULL, NULL, napi_default, NULL},
        {"beginOutputAck", NULL, mcp_stdio_begin_ack, NULL, NULL, NULL, napi_default, NULL},
        {"pollOutputAck", NULL, mcp_stdio_poll_ack, NULL, NULL, NULL, napi_default, NULL},
        {"pollLifecycleSnapshot", NULL, mcp_stdio_snapshot, NULL, NULL, NULL, napi_default, NULL}
    };
    const napi_property_descriptor retirement_methods[] = {
        {"reobserveRetirement", NULL, mcp_stdio_reobserve_admin_retirement, NULL, NULL, NULL, napi_default, NULL},
        {"assertRetirementObservation", NULL, mcp_stdio_assert_admin_retirement, NULL, NULL, NULL, napi_default, NULL}
    };
    void *owner_value = NULL;
    valid = valid && recipe->owner_value(recipe, &owner_value) && owner_value &&
        napi_create_object(env, &result) == napi_ok && napi_type_tag_object(env, result, purpose == CLIQ_MCP_STDIO_ADMIN ? &CLIQ_MCP_STDIO_ADMIN_PEER_TAG : purpose == CLIQ_MCP_STDIO_RECOVERY ? &CLIQ_MCP_STDIO_RECOVERY_PEER_TAG : &CLIQ_MCP_STDIO_RUN_PEER_TAG) == napi_ok &&
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) == napi_ok &&
        (purpose != CLIQ_MCP_STDIO_ADMIN || napi_define_properties(env, result, sizeof(retirement_methods) / sizeof(retirement_methods[0]), retirement_methods) == napi_ok) &&
        napi_create_reference(env, args[0], 1, &scope->input_ref) == napi_ok && napi_create_reference(env, args[3], 1, &scope->recipe_ref) == napi_ok &&
        napi_create_reference(env, (napi_value)owner_value, 1, &scope->owner_ref) == napi_ok;
    if (!valid) {
        if (scope->input_ref) napi_delete_reference(env, scope->input_ref);
        if (scope->recipe_ref) napi_delete_reference(env, scope->recipe_ref);
        if (scope->owner_ref) napi_delete_reference(env, scope->owner_ref);
        free(scope); return failure(env, "MCP stdio original scope receiver unavailable");
    }
    bool expected = false; atomic_bool *claimed = admin ? &admin->execution_claimed : recovery ? &recovery->execution_claimed : &run->execution_claimed;
    if (!atomic_compare_exchange_strong(claimed, &expected, true)) {
        napi_delete_reference(env, scope->input_ref); napi_delete_reference(env, scope->recipe_ref); napi_delete_reference(env, scope->owner_ref);
        free(scope); return failure(env, "MCP stdio input already consumed");
    }
    c->references++; c->mcp_stdio = scope;
    if (napi_wrap(env, result, scope, mcp_stdio_native_finalize, NULL, NULL) != napi_ok ||
        !recipe->register_peer(recipe, &scope->bridge, result)) { mcp_stdio_mark_failure(scope); return failure(env, "MCP stdio original scope custody registration refused"); }
    recipe->consumed = true;
    struct cliq_mcp_stdio_progress origin = {0}; origin.packet = *request; origin.controller_pid = c->pid;
    memcpy(origin.controller_start_token, c->token, sizeof(origin.controller_start_token)); memcpy(origin.controller_leaf_name, c->leaf_name, strlen(c->leaf_name) + 1);
#define STDIO_ORIGIN_DIRECTORY(field, actual) do { origin.field.device = (actual).st_dev; origin.field.inode = (actual).st_ino; origin.field.uid = (actual).st_uid; origin.field.gid = (actual).st_gid; origin.field.mode = (actual).st_mode; } while (0)
    STDIO_ORIGIN_DIRECTORY(controller_root, c->root_identity); STDIO_ORIGIN_DIRECTORY(controller_parent, c->parent_identity); STDIO_ORIGIN_DIRECTORY(controller_leaf, c->leaf_identity);
#undef STDIO_ORIGIN_DIRECTORY
    int files[] = {c->anchor_root, birth_fd, recipe->fd, helper->fd, bwrap->fd, server->fd};
    if (!cliq_mcp_stdio_append(birth_fd, 1, &origin) || !mcp_stdio_request(scope, CLIQ_MCP_STDIO_RESERVE, files, 6)) {
        mcp_stdio_mark_failure(scope); return failure(env, "MCP stdio original reservation dispatch is uncertain");
    }
    napi_object_freeze(env, result); return result;
}
static napi_value reserve_mcp_stdio_admin(napi_env e, napi_callback_info i) { return reserve_mcp_stdio(e, i, CLIQ_MCP_STDIO_ADMIN); }
static napi_value reserve_mcp_stdio_run(napi_env e, napi_callback_info i) { return reserve_mcp_stdio(e, i, CLIQ_MCP_STDIO_RUN); }
static napi_value reserve_mcp_stdio_recovery(napi_env e, napi_callback_info i) { return reserve_mcp_stdio(e, i, CLIQ_MCP_STDIO_RECOVERY); }
static bool mcp_stdio_cleanup_snapshot_value(struct mcp_stdio_native_scope *scope) {
    if (scope->cleanup_snapshot) return true;
    if (!scope->retained || !scope->joined || !scope->acked || !scope->snapshot) return false;
    struct cliq_mcp_stdio_cleanup_header header = {0};
    header.magic = CLIQ_MCP_STDIO_CLEANUP_MAGIC; header.version = 1; header.original_bytes = scope->snapshot_size;
    header.checker_owner_epoch = scope->identity.stdio_checker_owner_epoch;
    header.checker_supervisor_pid = getpid(); header.checker_controller_pid = scope->controller->pid;
    memcpy(header.checker_supervisor, scope->identity.stdio_checker_supervisor_id, sizeof(header.checker_supervisor));
    memcpy(header.checker_supervisor_token, scope->identity.stdio_checker_supervisor_token, sizeof(header.checker_supervisor_token));
    memcpy(header.checker_controller_token, scope->controller->token, sizeof(header.checker_controller_token));
    header.retirement = scope->observation;
    struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)&header, offsetof(struct cliq_mcp_stdio_cleanup_header, digest));
    sha256_update(&hash, scope->snapshot, scope->snapshot_size); sha256_final(&hash, header.digest);
    scope->cleanup_size = sizeof(header) + scope->snapshot_size; scope->cleanup_snapshot = malloc(scope->cleanup_size);
    if (!scope->cleanup_snapshot) return false;
    memcpy(scope->cleanup_snapshot, &header, sizeof(header)); memcpy(scope->cleanup_snapshot + sizeof(header), scope->snapshot, scope->snapshot_size);
    struct cliq_mcp_stdio_cleanup_header checked; struct cliq_mcp_stdio_history original;
    return cliq_mcp_stdio_cleanup_bytes(scope->cleanup_snapshot, scope->cleanup_size, &checked, &original);
}
static napi_value mcp_stdio_poll_cleanup(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (!scope->retained || !scope->acked) return undefined(env);
    if (!mcp_stdio_cleanup_snapshot_value(scope)) return failure(env, "MCP stdio current checker audit encoding refused");
    napi_value value;
    if (scope->cleanup_value) { napi_get_reference_value(env, scope->cleanup_value, &value); return value; }
    napi_create_object(env, &value); napi_object_freeze(env, value);
    if (napi_create_reference(env, value, 1, &scope->cleanup_value) != napi_ok) return NULL;
    return value;
}
static napi_value mcp_stdio_assert_cleanup(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2], actual; bool same = false;
    struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, args);
    if (!scope) return NULL;
    if (argc != 1 || !scope->retained || !scope->acked || !scope->joined || !scope->cleanup_value || !scope->cleanup_snapshot ||
        napi_get_reference_value(env, scope->cleanup_value, &actual) != napi_ok || napi_strict_equals(env, actual, args[0], &same) != napi_ok || !same)
        return failure(env, "MCP stdio current checker proof is not its actual original receiver");
    return undefined(env);
}
static napi_value mcp_stdio_cleanup_snapshot(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct mcp_stdio_native_scope *scope = mcp_stdio_receiver(env, info, &argc, NULL);
    if (!scope) return NULL;
    if (!scope->retained || !scope->acked || !scope->cleanup_snapshot) return undefined(env);
    napi_value value; if (napi_create_buffer_copy(env, scope->cleanup_size, scope->cleanup_snapshot, NULL, &value) != napi_ok) return NULL;
    return value;
}
static napi_value cleanup_mcp_stdio(napi_env env, napi_callback_info info, unsigned purpose) {
    size_t argc = 4; napi_value args[4], self, result; struct controller *c = NULL;
    struct cliq_mcp_admin_input *admin = NULL; struct cliq_mcp_stdio_run_input *run = NULL; struct cliq_mcp_stdio_recovery_input *recovery = NULL;
    uint64_t epoch; char supervisor[257]; size_t length = 0;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 3 || syscall(SYS_gettid) != getpid() ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&c) || c->env != env || c->creator_pid != getpid() || c->closed || !c->ready || c->pending ||
        c->mcp_stdio || c->mcp_admin || c->source_requested || c->worker_creation_requested || c->retained_requested ||
        !number(env, args[1], &epoch) || !epoch || napi_get_value_string_utf8(env, args[2], supervisor, sizeof(supervisor), &length) != napi_ok ||
        !length || length >= sizeof(supervisor) || strlen(supervisor) != length || !controller_placement(c, c->token))
        return failure(env, "MCP stdio cleanup requires the exact current dedicated checker");
    if (purpose == CLIQ_MCP_STDIO_ADMIN) {
        if (!tagged(env, args[0], &CLIQ_MCP_STDIO_ADMIN_RETAINED_INPUT_TAG, (void **)&admin) ||
            admin->creator_pid != getpid() || admin->environment != env || admin->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI ||
            !admin->assert_current || !admin->assert_current(admin) || !admin->retire || atomic_load(&admin->execution_claimed))
            return failure(env, "MCP stdio original retained Admin custody refused");
    } else if (purpose == CLIQ_MCP_STDIO_RECOVERY) {
        if (!tagged(env, args[0], &CLIQ_MCP_STDIO_RECOVERY_RETAINED_INPUT_TAG, (void **)&recovery) ||
            recovery->creator_pid != getpid() || recovery->environment != env || recovery->abi_version != CLIQ_MCP_STDIO_RECOVERY_INPUT_ABI ||
            !recovery->assert_current || !recovery->assert_current(recovery) || !recovery->retire || atomic_load(&recovery->execution_claimed) ||
            epoch <= recovery->binding.identity.inspectorStateOwnerEpoch || !strcmp(supervisor, recovery->binding.identity.inspectorSupervisorInstanceId))
            return failure(env, "MCP stdio original retained recovery custody refused");
    } else if (purpose != CLIQ_MCP_STDIO_RUN || !tagged(env, args[0], &CLIQ_MCP_STDIO_RUN_RETAINED_INPUT_TAG, (void **)&run) ||
        run->creator_pid != getpid() || run->environment != env || run->abi_version != CLIQ_MCP_STDIO_RUN_INPUT_ABI ||
        !run->assert_current || !run->assert_current(run) || !run->retire || atomic_load(&run->execution_claimed))
        return failure(env, "MCP stdio original retained Run custody refused");
    struct mcp_stdio_native_scope *scope = calloc(1, sizeof(*scope));
    if (!scope) return failure(env, "MCP stdio checker allocation unavailable");
    scope->controller = c; scope->admin = admin; scope->run = run; scope->recovery = recovery; scope->operation = -1; scope->retained = true;
    struct cliq_mcp_stdio_history history;
    bool valid = cliq_mcp_stdio_read_history(admin ? admin->birth_fd : recovery ? recovery->birth_fd : run->birth_fd, &history, &scope->snapshot, &scope->snapshot_size) &&
        history.purpose == purpose && history.count && history.last.kind >= 3 && history.first.controller_pid != c->pid;
    if (!valid) { free(scope->snapshot); free(scope); return failure(env, "MCP stdio original complete birth is missing or replaced"); }
    scope->ready = history.ready.kind == 5; scope->identity = history.last.packet; scope->identity.command = CLIQ_MCP_STDIO_CLEANUP_RETAINED;
    scope->identity.stdio_checker_owner_epoch = epoch; scope->identity.stdio_checker_supervisor_pid = getpid();
    memcpy(scope->identity.stdio_checker_supervisor_id, supervisor, length + 1);
    valid = cliq_process_token(getpid(), scope->identity.stdio_checker_supervisor_token);
    unsigned char hash[32]; cliq_mcp_admin_hash(scope->snapshot, scope->snapshot_size, hash);
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { scope->identity.stdio_original_birth_digest[i * 2] = alphabet[hash[i] >> 4]; scope->identity.stdio_original_birth_digest[i * 2 + 1] = alphabet[hash[i] & 15]; }
    scope->identity.reservation_observation = history.last.kind;
    scope->bridge.abi_version = CLIQ_MCP_STDIO_OWNER_ABI; scope->bridge.purpose = purpose; scope->bridge.creator_pid = getpid();
    scope->bridge.environment = env; scope->bridge.context = scope;
    atomic_init(&scope->bridge.revoked, false); atomic_init(&scope->bridge.io_joined, false);
    atomic_init(&scope->bridge.physical_joined, false); atomic_init(&scope->bridge.output_retired, false);
    atomic_init(&scope->bridge.operation_closed, false);
    const napi_property_descriptor methods[] = {
        {"stop", NULL, mcp_stdio_stop, NULL, NULL, NULL, napi_default, NULL},
        {"pollJoined", NULL, mcp_stdio_poll_joined, NULL, NULL, NULL, napi_default, NULL},
        {"assertJoined", NULL, mcp_stdio_assert_joined, NULL, NULL, NULL, napi_default, NULL},
        {"beginOutputAck", NULL, mcp_stdio_begin_ack, NULL, NULL, NULL, napi_default, NULL},
        {"pollOutputAck", NULL, mcp_stdio_poll_ack, NULL, NULL, NULL, napi_default, NULL},
        {"pollLifecycleSnapshot", NULL, mcp_stdio_snapshot, NULL, NULL, NULL, napi_default, NULL},
        {"pollCleanupObservation", NULL, mcp_stdio_poll_cleanup, NULL, NULL, NULL, napi_default, NULL},
        {"assertCleanupObservation", NULL, mcp_stdio_assert_cleanup, NULL, NULL, NULL, napi_default, NULL},
        {"pollCleanupSnapshot", NULL, mcp_stdio_cleanup_snapshot, NULL, NULL, NULL, napi_default, NULL}
    };
    valid = valid && napi_create_object(env, &result) == napi_ok &&
        napi_type_tag_object(env, result, purpose == CLIQ_MCP_STDIO_ADMIN ? &MCP_STDIO_ADMIN_CLEANUP_TAG : purpose == CLIQ_MCP_STDIO_RECOVERY ? &MCP_STDIO_RECOVERY_CLEANUP_TAG : &MCP_STDIO_RUN_CLEANUP_TAG) == napi_ok &&
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) == napi_ok &&
        napi_create_reference(env, args[0], 1, &scope->input_ref) == napi_ok;
    if (!valid) { if (scope->input_ref) napi_delete_reference(env, scope->input_ref); free(scope->snapshot); free(scope); return failure(env, "MCP stdio checker receiver unavailable"); }
    bool expected = false; atomic_bool *claimed = admin ? &admin->execution_claimed : recovery ? &recovery->execution_claimed : &run->execution_claimed;
    if (!atomic_compare_exchange_strong(claimed, &expected, true)) { napi_delete_reference(env, scope->input_ref); free(scope->snapshot); free(scope); return failure(env, "MCP stdio retained input already has a checker"); }
    c->references++; c->mcp_stdio = scope;
    if (napi_wrap(env, result, scope, mcp_stdio_native_finalize, NULL, NULL) != napi_ok) { mcp_stdio_mark_failure(scope); return failure(env, "MCP stdio current checker custody unavailable"); }
    int files[] = {c->anchor_root, admin ? admin->birth_fd : recovery ? recovery->birth_fd : run->birth_fd};
    if (!mcp_stdio_request(scope, CLIQ_MCP_STDIO_CLEANUP_RETAINED, files, 2)) { mcp_stdio_mark_failure(scope); return failure(env, "MCP stdio current cleanup dispatch uncertain"); }
    napi_object_freeze(env, result); return result;
}
static napi_value cleanup_mcp_stdio_admin(napi_env e, napi_callback_info i) { return cleanup_mcp_stdio(e, i, CLIQ_MCP_STDIO_ADMIN); }
static napi_value cleanup_mcp_stdio_run(napi_env e, napi_callback_info i) { return cleanup_mcp_stdio(e, i, CLIQ_MCP_STDIO_RUN); }
static napi_value cleanup_mcp_stdio_recovery(napi_env e, napi_callback_info i) { return cleanup_mcp_stdio(e, i, CLIQ_MCP_STDIO_RECOVERY); }
#endif

