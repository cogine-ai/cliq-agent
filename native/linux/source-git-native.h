#ifndef CLIQ_SOURCE_GIT_NATIVE_H
#define CLIQ_SOURCE_GIT_NATIVE_H

#include "source-input-bridge.h"
#include "source-git-protocol.h"
#include "source-git-history.h"
#include "preparation-git-protocol.h"
#include "preparation-input-bridge.h"
#include "preparation-git-stream.h"
#include "source-ready-diagnostic.h"
#include <sys/file.h>

enum source_ready_failure_boundary {
    SOURCE_READY_REQUEST_STATE = 1,
    SOURCE_READY_RECEIVE = 2,
    SOURCE_READY_UNAUTHENTICATED_REPLY = 3,
    SOURCE_READY_AUTHENTICATED_FAILURE = 4,
    SOURCE_READY_KERNEL_OBSERVATION = 5
};

static const napi_type_tag SOURCE_SCOPE_TAG = { UINT64_C(0xe90767ec63984722), UINT64_C(0x94a089abf2cc9f91) };
static const napi_type_tag SOURCE_READER_TAG = { UINT64_C(0xd49f4628b0514b9d), UINT64_C(0x8c269484777eb772) };
struct source_native_scope {
    struct controller *controller;
    struct cliq_source_input *input;
    napi_ref input_ref;
    unsigned int references;
    bool reserved, starting, ready, released, sealed, continued, received, closed, joined, cleanup_valid;
    bool retained, registered_absent, recovery_observed;
    struct cliq_source_history original_history;
    unsigned char *lifecycle_snapshot;
    size_t lifecycle_bytes;
    int cgroup_fd, output[CLIQ_SOURCE_TRANSFER_OUTPUTS];
    uint64_t offsets[CLIQ_SOURCE_TRANSFER_OUTPUTS];
    struct cliq_worker_packet identity, snapshot, result;
    double retired_at_ms;
    bool preparation, preparation_stop_requested, preparation_retirement_requested, preparation_completion;
    bool preparation_leaf_open, preparation_input_complete;
    uint32_t preparation_role;
    uint64_t preparation_leaf_offset, preparation_total_bytes, preparation_bytes[CLIQ_PREPARATION_INPUT_FILES];
    char preparation_digests[CLIQ_PREPARATION_INPUT_FILES][65];
    struct sha256_context preparation_input_hash;
    struct cliq_preparation_input *preparation_input;
    struct cliq_preparation_origin preparation_origin;
    struct cliq_preparation_history preparation_history;
    int preparation_writer;
    uint32_t ready_failure_status, ready_failure_boundary, postready_failure_status;
    bool ready_diagnostic_observed;
    struct cliq_source_ready_diagnostic ready_diagnostic;
};
struct source_native_reader { struct source_native_scope *scope; unsigned int index; };

static void source_scope_release(struct source_native_scope *scope) {
    if (--scope->references != 0) return;
    /* Uncertain native resources deliberately retain the original StateOwner
     * borrow. GC cannot convert missing join into positive release evidence. */
    if (!scope->joined) return;
    if (scope->input_ref) napi_delete_reference(scope->controller->env, scope->input_ref);
    if (scope->controller->source == scope) scope->controller->source = NULL;
    free(scope->lifecycle_snapshot);
    controller_release(scope->controller); free(scope);
}
static bool source_native_close_outputs(struct source_native_scope *scope) {
    bool joined = true;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (!retire_descriptor(&scope->output[i])) joined = false;
    if (!joined) scope->controller->retirement_failed = true;
    return joined;
}
static void source_native_revoke(struct controller *controller) {
    if (!controller->source) return;
    controller->source->closed = true;
    (void)source_native_close_outputs(controller->source);
    if (controller->source->preparation && !retire_descriptor(&controller->source->preparation_writer)) controller->retirement_failed = true;
}
static void source_native_directory(struct cliq_source_directory_identity *target, const struct stat *source) {
    target->device = source->st_dev; target->inode = source->st_ino; target->uid = source->st_uid;
    target->gid = source->st_gid; target->mode = source->st_mode;
}
static bool source_native_controller_frame(struct source_native_scope *scope) {
    struct controller *controller = scope->controller; struct stat birth;
    struct cliq_source_controller_birth frame;
    memset(&frame, 0, sizeof(frame));
    frame.magic = CLIQ_SOURCE_CONTROLLER_MAGIC; frame.version = 1; frame.pid = controller->pid;
    if (!controller->ready || !anchor_current(controller) || !controller_placement(controller, controller->token) ||
        !cliq_source_controller_name(controller->leaf_name) || !scope->input->assert_current(scope->input) ||
        fstat(scope->input->birth_fd, &birth) != 0 || birth.st_size != (off_t)sizeof(struct cliq_source_birth) ||
        flock(scope->input->birth_fd, LOCK_EX | LOCK_NB) != 0) return false;
    source_native_directory(&frame.root, &controller->root_identity); source_native_directory(&frame.parent, &controller->parent_identity);
    source_native_directory(&frame.leaf, &controller->leaf_identity);
    memcpy(frame.leaf_name, controller->leaf_name, strlen(controller->leaf_name) + 1);
    memcpy(frame.process_start_token, controller->token, sizeof(frame.process_start_token));
    memcpy(frame.source_header_digest, scope->input->binding.digest, sizeof(frame.source_header_digest));
    struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)&frame, offsetof(struct cliq_source_controller_birth, digest)); sha256_final(&hash, frame.digest);
    size_t offset = 0;
    while (offset < sizeof(frame)) {
        ssize_t count = pwrite(scope->input->birth_fd, (const unsigned char *)&frame + offset, sizeof(frame) - offset,
            (off_t)sizeof(struct cliq_source_birth) + (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return fsync(scope->input->birth_fd) == 0 && scope->input->assert_current(scope->input) && anchor_current(controller);
}
static bool source_native_absent(struct controller *controller, int64_t pid, const char *token) {
    if (pid <= 0 || pid > INT32_MAX || !*token) return false;
    struct process_sample sample;
    return sample_process(controller, (pid_t)pid, &sample, false) && (sample.absent || strcmp(sample.token, token) != 0);
}
static bool source_native_recovery_joined(struct source_native_scope *scope) {
    struct controller *controller = scope->controller;
    struct cliq_source_history current; struct stat held, named;
    /* Only immutable borrow fields and this controller's exclusively held
     * FDs are read on the worker thread. The StateOwner/staging callback is
     * rechecked on the main thread before publishing retirement. */
    unsigned char *snapshot = NULL; size_t snapshot_bytes = 0;
    bool read = scope->registered_absent ? cliq_source_history_read_sealed(scope->input->birth_fd, &scope->input->binding,
        &current, &snapshot, &snapshot_bytes) : cliq_source_history_read_snapshot(scope->input->birth_fd, &scope->input->binding,
        &current, &snapshot, &snapshot_bytes);
    bool valid = read && scope->recovery_observed && fstat(scope->input->birth_fd, &held) == 0 &&
        held.st_dev == scope->input->birth_identity.st_dev && held.st_ino == scope->input->birth_identity.st_ino && anchor_current(controller) &&
        current.count == scope->original_history.count && memcmp(current.digest, scope->original_history.digest, 32) == 0 &&
        memcmp(&current.creator, &scope->original_history.creator, sizeof(current.creator)) == 0 &&
        cliq_source_directory_matches(&current.creator.root, &controller->root_identity) &&
        source_native_absent(controller, current.creator.pid, current.creator.process_start_token);
    int parent = valid ? openat(controller->anchor_root, "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    valid = valid && parent >= 0 && private_cgroup(parent, &held) && cliq_source_directory_matches(&current.creator.parent, &held) &&
        fstatat(controller->anchor_root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && cliq_source_directory_matches(&current.creator.parent, &named) &&
        fstatat(parent, current.creator.leaf_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (valid && current.monitor.monitor_pid) valid = source_native_absent(controller, current.monitor.monitor_pid, current.monitor.monitor_start_token);
    if (valid && current.ready.pid) valid = source_native_absent(controller, current.ready.pid, current.ready.start_token) &&
        source_native_absent(controller, current.ready.namespace_init_pid, current.ready.init_native_start_token);
    if (!retire_descriptor(&parent)) { controller->retirement_failed = true; valid = false; }
    if (valid && scope->registered_absent) valid = source_native_absent(controller, current.header.supervisor_pid, current.header.supervisor_start_token);
    if (valid) { scope->lifecycle_snapshot = snapshot; scope->lifecycle_bytes = snapshot_bytes; }
    else free(snapshot);
    return valid;
}
/* Worker thread, only after the exclusively owned original controller has
 * been reaped. No JS callbacks, reusable path guesses or source reads occur. */
static void source_native_joined(struct controller *controller) {
    struct source_native_scope *scope = controller->source;
    if (!scope) return;
    if (scope->preparation) { preparation_native_joined(controller); return; }
    scope->cleanup_valid = false;
    if (scope->retained) {
        scope->cleanup_valid = source_native_recovery_joined(scope);
        if (!scope->cleanup_valid) controller->retirement_failed = true;
        return;
    }
    struct stat birth; struct cliq_source_history history;
    bool valid = scope->input && fstat(scope->input->birth_fd, &birth) == 0 && S_ISREG(birth.st_mode) && birth.st_nlink == 1 &&
        (birth.st_mode & 07777) == 0600 && birth.st_uid == geteuid() &&
        birth.st_dev == scope->input->birth_identity.st_dev && birth.st_ino == scope->input->birth_identity.st_ino &&
        cliq_source_history_read(scope->input->birth_fd, &scope->input->binding, &history);
    const struct cliq_source_controller_birth *creator = &history.creator;
    valid = valid && creator->pid == controller->pid && strcmp(creator->process_start_token, controller->token) == 0 &&
        strcmp(creator->leaf_name, controller->leaf_name) == 0 && cliq_source_directory_matches(&creator->root, &controller->root_identity) &&
        cliq_source_directory_matches(&creator->parent, &controller->parent_identity) && cliq_source_directory_matches(&creator->leaf, &controller->leaf_identity);
    if (valid && history.count) valid = cliq_source_same_attempt(&history.first, &scope->identity) &&
        strcmp(history.first.cgroup_name, scope->identity.cgroup_name) == 0;
    if (valid && scope->reserved) valid = history.born.cgroup_inode == scope->identity.cgroup_inode && history.born.cgroup_device == scope->identity.cgroup_device;
    if (valid && scope->starting) valid = cliq_source_same_prepared(&history.blocked, &scope->identity);
    if (valid && scope->ready) valid = history.ready.pid == scope->identity.pid && history.ready.namespace_init_pid == scope->identity.namespace_init_pid &&
        history.ready.monitor_pid == scope->identity.monitor_pid && history.ready.pid_namespace_inode == scope->identity.pid_namespace_inode &&
        strcmp(history.ready.start_token, scope->identity.start_token) == 0 && strcmp(history.ready.init_native_start_token, scope->identity.init_native_start_token) == 0 &&
        strcmp(history.ready.monitor_start_token, scope->identity.monitor_start_token) == 0;
    struct stat named;
    valid = valid && anchor_current(controller) &&
        fstatat(controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    if (valid && history.count == 0) {
        /* The immutable pristine birth plus the original spawner's real join
         * and current absent locator prove no reserve mutation occurred. */
        valid = !scope->reserved && !scope->starting && !scope->ready;
    } else if (valid) {
        const struct cliq_worker_packet *last = &history.last;
        valid = history.kind == 12 && last->populated == 0 && last->remaining_descendants == 0;
        if (valid && last->monitor_pid != 0) valid = source_native_absent(controller, last->monitor_pid, last->monitor_start_token);
        if (valid && last->pid != 0) valid = last->init_reaped == 1 &&
            source_native_absent(controller, last->pid, last->start_token) &&
            source_native_absent(controller, last->namespace_init_pid, last->init_native_start_token) &&
            source_native_absent(controller, last->monitor_pid, last->monitor_start_token);
    }
    if (!retire_descriptor(&scope->cgroup_fd)) valid = false;
    if (!valid) controller->retirement_failed = true;
    /* Preserve the completed original birth before input->retire closes its
     * FD. Replies may have been lost before JS could observe reservation or
     * READY; only this actual joined birth supplies durable closure facts. */
    if (valid) {
        struct cliq_source_history snapshot;
        valid = cliq_source_history_read_snapshot(scope->input->birth_fd, &scope->input->binding,
            &snapshot, &scope->lifecycle_snapshot, &scope->lifecycle_bytes) &&
            snapshot.count == history.count && memcmp(snapshot.digest, history.digest, 32) == 0;
        if (valid) scope->original_history = history;
    }
    if (!valid) controller->retirement_failed = true;
    scope->cleanup_valid = valid;
}
/* Main-thread async completion is the only point that releases the opaque
 * physical input borrow. Missing/partial/contradictory birth remains held. */
static void source_native_complete(napi_env env, struct controller *controller) {
    (void)env; struct source_native_scope *scope = controller->source;
    if (!scope) return;
    if (scope->preparation) { preparation_native_complete(env, controller); return; }
    if (scope->retained && (!scope->input->assert_current || !scope->input->assert_current(scope->input))) controller->retirement_failed = true;
    if (scope->cleanup_valid && controller->reaped && !controller->retirement_failed && !atomic_load(&native_retirement_failed)) {
        atomic_store(&scope->input->execution_joined, true);
        if (!scope->input->retire || scope->input->retire(scope->input) != 0) controller->retirement_failed = true;
        else {
            struct timespec now;
            if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0) controller->retirement_failed = true;
            else {
                scope->retired_at_ms = (double)now.tv_sec * 1000 + now.tv_nsec / 1000000;
                scope->joined = scope->retired_at_ms > 0 && scope->retired_at_ms <= 9007199254740991.0;
                if (!scope->joined) controller->retirement_failed = true;
            }
        }
    }
    source_scope_release(scope);
}
static bool source_native_current(struct source_native_scope *scope) {
    if (scope->closed || scope->controller->closed || scope->controller->retirement_failed || atomic_load(&native_retirement_failed) ||
        (scope->preparation ? !scope->preparation_input->assert_current || !scope->preparation_input->assert_current(scope->preparation_input) :
            !scope->input->assert_current || !scope->input->assert_current(scope->input)) ||
        !controller_placement(scope->controller, scope->controller->token)) return false;
    if (!scope->reserved) return true;
    struct stat held, named;
    if (!private_cgroup(scope->cgroup_fd, &held) || (uint64_t)held.st_dev != scope->identity.cgroup_device ||
        (uint64_t)held.st_ino != scope->identity.cgroup_inode ||
        fstatat(scope->controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_directory(&held, &named)) return false;
    if (!scope->ready || scope->received) return true;
    struct process_sample process; char expected[PATH_MAX + 8];
    int length = snprintf(expected, sizeof(expected), "0::%s/%s\n", scope->controller->root_path + strlen("/sys/fs/cgroup"), scope->identity.cgroup_name);
    if (length <= 0 || (size_t)length >= sizeof(expected) || !sample_process(scope->controller, (pid_t)scope->identity.pid, &process, true) ||
        process.absent || process.uid != geteuid() || strcmp(process.token, scope->identity.start_token) != 0 || strcmp(process.cgroup, expected) != 0) return false;
    char path[128]; struct stat image, runtime, namespace;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)scope->identity.pid);
    if (stat(path, &image) != 0 || !S_ISREG(image.st_mode)) return false;
    snprintf(path, sizeof(path), "/proc/%ld/root/runtime/cliq-linux-worker-init", (long)scope->identity.pid);
    if (stat(path, &runtime) != 0 || runtime.st_dev != image.st_dev || runtime.st_ino != image.st_ino) return false;
    snprintf(path, sizeof(path), "/proc/%ld/ns/pid", (long)scope->identity.pid);
    return stat(path, &namespace) == 0 && (uint64_t)namespace.st_ino == scope->identity.pid_namespace_inode &&
        sample_process(scope->controller, (pid_t)scope->identity.pid, &process, true) && !process.absent &&
        strcmp(process.token, scope->identity.start_token) == 0 && strcmp(process.cgroup, expected) == 0;
}
static struct source_native_scope *source_native_receiver(napi_env env, napi_callback_info info, size_t *argc, napi_value *args, bool allow_closed) {
    napi_value self; struct source_native_scope *scope;
    if (napi_get_cb_info(env, info, argc, args, &self, NULL) != napi_ok ||
        !tagged(env, self, &SOURCE_SCOPE_TAG, (void **)&scope) || (!allow_closed && (scope->closed || scope->controller->closed))) {
        failure(env, "invalid original native source scope"); return NULL;
    }
    return scope;
}
static bool source_native_send(struct source_native_scope *scope, uint32_t command) {
    struct cliq_worker_packet request = scope->identity; request.command = command;
    if (command == CLIQ_SOURCE_CONTINUE_GIT) memcpy(request.source_snapshot_digest, scope->snapshot.source_snapshot_digest, sizeof(request.source_snapshot_digest));
    return begin_request(scope->controller, NULL, &request, NULL, 0);
}
static int source_native_reply(struct source_native_scope *scope, uint32_t command, struct cliq_worker_packet *response, int *files, size_t *count) {
    struct controller *controller = scope->controller;
    if (controller->closed || controller->pending != command || controller->pending_scope != NULL) {
        if (scope->preparation && command == CLIQ_SOURCE_CREATE_BLOCKED) scope->ready_failure_boundary = SOURCE_READY_REQUEST_STATE;
        return -1;
    }
    if (!cliq_receive_flags(controller->socket, response, files, CLIQ_WORKER_MAX_FDS, count, MSG_DONTWAIT)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (scope->preparation && command == CLIQ_SOURCE_CREATE_BLOCKED) scope->ready_failure_boundary = SOURCE_READY_RECEIVE;
        (void)close_controller(controller); return -1;
    }
    bool same_attempt = response->command == command && cliq_fixed_git_same_attempt(&scope->identity, response) &&
        strcmp(scope->identity.cgroup_name, response->cgroup_name) == 0 &&
        (!scope->starting || cliq_fixed_git_same_prepared(&scope->identity, response));
    bool valid = response->status == 0 && same_attempt;
    if (!valid) {
        if (scope->preparation && same_attempt && (command == CLIQ_SOURCE_POLL_SEALED || command == CLIQ_SOURCE_POLL_RESULT))
            scope->postready_failure_status = cliq_preparation_failure_status(&scope->identity, response, command, *count);
        if (scope->preparation && command == CLIQ_SOURCE_CREATE_BLOCKED) scope->ready_failure_boundary = same_attempt ? SOURCE_READY_AUTHENTICATED_FAILURE : SOURCE_READY_UNAUTHENTICATED_REPLY;
        if (scope->preparation && command == CLIQ_SOURCE_CREATE_BLOCKED && same_attempt && *count == 0 && response->status >= 1001 && response->status <= 1014) {
            scope->ready_failure_status = response->status;
            if (response->setup.stage > 0 && response->setup.stage <= 9 && response->setup.poll_result >= 0 && response->setup.poll_result <= 1 &&
                (uint64_t)response->verifier_errno == scope->identity.reservation_uid &&
                (response->setup.poll_result || (!response->setup.poll_revents && !response->setup.poll_errno && !response->setup.elapsed_ms))) {
                scope->ready_diagnostic_observed = true;
                scope->ready_diagnostic = (struct cliq_source_ready_diagnostic) { .stage = response->setup.stage,
                    .uid = response->verifier_signal, .gid = response->verifier_reason, .original_uid = response->verifier_errno,
                    .map_observed = (uint32_t)response->setup.poll_result, .map_start = response->setup.poll_revents,
                    .map_parent = response->setup.poll_errno, .map_count = response->setup.elapsed_ms };
            }
        }
        for (size_t i = 0; i < *count; i++) if (!retire_descriptor(&files[i])) controller->retirement_failed = true;
        *count = 0; (void)close_controller(controller); return -1;
    }
    controller->pending = 0; return 1;
}
static bool source_native_time(const struct cliq_worker_packet *packet) {
    return packet->observed_at_ms > 0 && packet->observed_at_ms <= UINT64_C(9007199254740991);
}
static napi_value source_native_reserved(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->reserved) {
        struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
        int status = source_native_reply(scope, scope->preparation ? CLIQ_PREPARATION_RESERVE : CLIQ_SOURCE_RESERVE, &response, files, &count);
        if (status == 0) return undefined(env);
        struct stat held; bool valid = status == 1 && count == 1 && source_native_time(&response) &&
            private_cgroup(files[0], &held) && (uint64_t)held.st_dev == response.cgroup_device && (uint64_t)held.st_ino == response.cgroup_inode &&
            response.cgroup_inode != 0 && response.subreaper_pid == scope->controller->pid && strcmp(response.subreaper_start_token, scope->controller->token) == 0;
        if (!valid) {
            for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) scope->controller->retirement_failed = true;
            (void)close_controller(scope->controller); return failure(env, "source reservation did not return its exact original resource");
        }
        scope->cgroup_fd = files[0]; scope->identity = response; scope->reserved = true;
    }
    if (!source_native_current(scope)) return failure(env, "source reservation is no longer current");
    napi_value result; napi_create_object(env, &result); char path[PATH_MAX], decimal[32], pending[96], subreaper[CLIQ_WORKER_TOKEN_BYTES];
    int length = snprintf(path, sizeof(path), "%s/%s", scope->controller->root_path, scope->identity.cgroup_name);
    if (length <= 0 || (size_t)length >= sizeof(path)) return failure(env, "source reservation path cannot be represented");
    set_string(env, result, "cgroupPath", path);
    snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)scope->identity.cgroup_device); set_string(env, result, "deviceId", decimal);
    snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)scope->identity.cgroup_inode); set_string(env, result, "fileId", decimal); set_string(env, result, "cgroupId", decimal);
    set_number(env, result, "ownerUid", (double)geteuid()); set_number(env, result, "observedAtMs", (double)scope->identity.observed_at_ms);
    snprintf(pending, sizeof(pending), "%s:%s", scope->preparation ? "preparation-pending" : "source-pending", scope->identity.nonce); set_string(env, result, "pidNamespaceReservationId", pending);
    length = snprintf(subreaper, sizeof(subreaper), "linux-subreaper:%ld:%s", (long)scope->controller->pid, scope->controller->token);
    if (length <= 0 || (size_t)length >= sizeof(subreaper)) return failure(env, "source subreaper lifetime cannot be represented");
    set_string(env, result, "subreaperStartToken", subreaper); napi_object_freeze(env, result); return result;
}
static bool source_native_digest_argument(napi_env env, napi_value argument, char output[65]) {
    size_t count;
    return napi_get_value_string_utf8(env, argument, output, 65, &count) == napi_ok && count == 64 && cliq_source_digest(output);
}
static napi_value source_native_create(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3]; struct source_native_scope *scope = source_native_receiver(env, info, &argc, args, false);
    if (!scope) return NULL;
    if (argc != 3 || !scope->reserved || scope->starting || scope->controller->pending || !source_native_current(scope) ||
        !source_native_digest_argument(env, args[0], scope->identity.plan_ref) || !source_native_digest_argument(env, args[1], scope->identity.sandbox_launch_ref) ||
        !source_native_digest_argument(env, args[2], scope->identity.sandbox_launch_digest)) return failure(env, "source blocked birth requires its exact prepared plan");
    scope->starting = true;
    if (!source_native_send(scope, CLIQ_SOURCE_CREATE_BLOCKED)) return failure(env, "original source blocked birth is indeterminate");
    return undefined(env);
}
static napi_value source_native_ready(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->starting) return failure(env, "source blocked birth was not requested");
    if (!scope->ready) {
        struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
        int status = source_native_reply(scope, CLIQ_SOURCE_CREATE_BLOCKED, &response, files, &count);
        if (status == 0) return undefined(env);
        bool valid = status == 1 && count == 0 && source_native_time(&response) && response.pid > 0 && response.namespace_init_pid > 0 && response.monitor_pid > 0 &&
            response.pid_namespace_inode != 0 && response.cgroup_device == scope->identity.cgroup_device && response.cgroup_inode == scope->identity.cgroup_inode &&
            *response.start_token && *response.init_start_token && *response.init_native_start_token && *response.monitor_start_token;
        for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
        if (!valid) {
            (void)close_controller(scope->controller);
            if (scope->preparation) {
                if (status == 1) scope->ready_failure_boundary = SOURCE_READY_KERNEL_OBSERVATION;
                char message[384]; const struct cliq_source_ready_diagnostic *diagnostic = &scope->ready_diagnostic;
                int length = snprintf(message, sizeof(message), "source blocked birth lacks its original kernel identities: boundary=%u status=%u marker=%u producerStage=%u "
                    "namespaceUid=%u namespaceGid=%u originalUid=%u mapObserved=%u mapStart=%u mapParent=%u mapCount=%u",
                    scope->ready_failure_boundary, scope->ready_failure_status, scope->ready_diagnostic_observed ? 1U : 0U, diagnostic->stage, diagnostic->uid, diagnostic->gid,
                    diagnostic->original_uid, diagnostic->map_observed, diagnostic->map_start, diagnostic->map_parent, diagnostic->map_count);
                return failure(env, length > 0 && (size_t)length < sizeof(message) ? message : "source blocked birth lacks its original kernel identities; numeric diagnosis unavailable");
            }
            return failure(env, "source blocked birth lacks its original kernel identities");
        }
        scope->identity = response; scope->ready = true;
    }
    if (!source_native_current(scope)) return failure(env, "source blocked birth is no longer current");
    return scope_observation(env, &scope->identity);
}
static napi_value source_native_release_capture(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->ready || scope->released || scope->controller->pending || !source_native_current(scope)) return failure(env, "source capture release is not current or was consumed");
    scope->released = true;
    if (!source_native_send(scope, CLIQ_SOURCE_RELEASE_CAPTURE)) return failure(env, "source capture release is indeterminate");
    return undefined(env);
}
static bool source_native_ack(struct source_native_scope *scope, uint32_t command) {
    struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    int status = source_native_reply(scope, command, &response, files, &count);
    bool valid = status >= 0 && count == 0;
    for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
    if (!valid) { (void)close_controller(scope->controller); return false; }
    return status == 1;
}
static napi_value source_native_postready_failure(napi_env env, struct source_native_scope *scope,
    bool result, uint32_t guard) {
    const char *message = result ? "source result lacks its complete original output and whole-domain death" : "source seal observation is invalid";
    if (!scope->preparation) return failure(env, message);
    char diagnostic[192];
    int length = snprintf(diagnostic, sizeof(diagnostic), "%s: status=%u guard=%u", message, scope->postready_failure_status, guard);
    return failure(env, length > 0 && (size_t)length < sizeof(diagnostic) ? diagnostic : message);
}
static napi_value source_native_poll_sealed(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->released || scope->continued) return failure(env, "source capture was not released or already continued");
    if (!scope->sealed) {
        if (scope->controller->pending == CLIQ_SOURCE_RELEASE_CAPTURE && !source_native_ack(scope, CLIQ_SOURCE_RELEASE_CAPTURE))
            return scope->controller->closed ? failure(env, "source capture acknowledgement failed") : undefined(env);
        if (!scope->controller->pending && !source_native_send(scope, CLIQ_SOURCE_POLL_SEALED)) return failure(env, "source seal observation could not be requested");
        struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
        int status = source_native_reply(scope, CLIQ_SOURCE_POLL_SEALED, &response, files, &count);
        if (status == 0) return undefined(env);
        bool valid = status == 1 && count == 0 && response.exit_status <= 1;
        for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
        if (!valid) { (void)close_controller(scope->controller); return source_native_postready_failure(env, scope, false, status == 1 ? 4001 : 0); }
        if (response.exit_status == 0) return undefined(env);
        if (!cliq_source_digest(response.source_snapshot_digest) || response.source_byte_count == 0 ||
            response.source_byte_count > scope->identity.max_generation_bytes || response.source_entry_count == 0 ||
            response.source_entry_count > CLIQ_SOURCE_MAX_ENTRIES || response.source_shard_count == 0 || response.source_shard_count > CLIQ_SOURCE_MAX_SHARDS)
            return failure(env, "source seal observation is outside its exact snapshot limits");
        if (scope->preparation) {
            unsigned char digest[32]; char text[65]; struct sha256_context hash = scope->preparation_input_hash; sha256_final(&hash, digest);
            const char alphabet[] = "0123456789abcdef";
            for (size_t i = 0; i < 32; i++) { text[i * 2] = alphabet[digest[i] >> 4]; text[i * 2 + 1] = alphabet[digest[i] & 15]; } text[64] = '\0';
            if (!scope->preparation_input_complete || scope->preparation_role != CLIQ_PREPARATION_INPUT_FILES ||
                response.source_entry_count != CLIQ_PREPARATION_INPUT_FILES || response.source_shard_count != CLIQ_PREPARATION_INPUT_FILES ||
                response.source_byte_count != scope->preparation_total_bytes || strcmp(text, response.source_snapshot_digest) != 0) {
                (void)close_controller(scope->controller); return failure(env, "preparing input differs from its original complete sealed CAS transfer");
            }
        }
        scope->snapshot = response; scope->sealed = true;
    }
    napi_value result; napi_create_object(env, &result);
    set_string(env, result, "snapshotDigest", scope->snapshot.source_snapshot_digest);
    set_number(env, result, "byteCount", (double)scope->snapshot.source_byte_count);
    set_number(env, result, "entryCount", (double)scope->snapshot.source_entry_count);
    set_number(env, result, "shardCount", (double)scope->snapshot.source_shard_count);
    napi_object_freeze(env, result); return result;
}
static napi_value source_native_continue(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->sealed || scope->continued || scope->controller->pending || !source_native_current(scope)) return failure(env, "source continuation is not the original current sealed scope");
    scope->continued = true;
    if (!source_native_send(scope, CLIQ_SOURCE_CONTINUE_GIT)) return failure(env, "fixed source Git continuation is indeterminate");
    return undefined(env);
}

static uint64_t source_output_size(const struct source_native_scope *scope, unsigned int index) {
    return index == 4 ? scope->result.source_rule_bytes : scope->result.source_output_bytes[index];
}
static const char *source_output_digest(const struct source_native_scope *scope, unsigned int index) {
    return index == 4 ? scope->result.source_rule_digest : scope->result.source_output_digests[index];
}
static bool source_reader_current(struct source_native_reader *reader) {
    struct source_native_scope *scope = reader->scope;
    if (scope->closed || !scope->received || reader->index >= CLIQ_SOURCE_OUTPUTS + scope->result.source_rule_present || scope->output[reader->index] < 0) return false;
    struct stat file; int fd = scope->output[reader->index];
    return fstat(fd, &file) == 0 && S_ISREG(file.st_mode) && file.st_size >= 0 &&
        (uint64_t)file.st_size == source_output_size(scope, reader->index) &&
        fcntl(fd, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
}
static struct source_native_reader *source_reader_receiver(napi_env env, napi_callback_info info) {
    napi_value self; size_t argc = 0; struct source_native_reader *reader;
    if (napi_get_cb_info(env, info, &argc, NULL, &self, NULL) != napi_ok ||
        !tagged(env, self, &SOURCE_READER_TAG, (void **)&reader)) {
        failure(env, "invalid original source output reader"); return NULL;
    }
    return reader;
}
static napi_value source_reader_assert(napi_env env, napi_callback_info info) {
    struct source_native_reader *reader = source_reader_receiver(env, info);
    if (!reader) return NULL;
    return source_reader_current(reader) ? undefined(env) : failure(env, "original source output is closed or changed");
}
static napi_value source_reader_read(napi_env env, napi_callback_info info) {
    struct source_native_reader *reader = source_reader_receiver(env, info);
    if (!reader) return NULL;
    if (!source_reader_current(reader)) return failure(env, "original source output is closed or changed");
    struct source_native_scope *scope = reader->scope; unsigned int at = reader->index;
    uint64_t remaining = source_output_size(scope, at) - scope->offsets[at];
    if (!remaining) return undefined(env);
    unsigned char buffer[65536]; size_t wanted = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
    ssize_t count;
    do { count = pread(scope->output[at], buffer, wanted, (off_t)scope->offsets[at]); } while (count < 0 && errno == EINTR);
    if (count <= 0 || (size_t)count > wanted || !source_reader_current(reader)) return failure(env, "source output did not yield its full original bytes");
    napi_value result;
    if (napi_create_buffer_copy(env, (size_t)count, buffer, NULL, &result) != napi_ok) return NULL;
    scope->offsets[at] += (uint64_t)count; return result;
}
static napi_value source_reader_close(napi_env env, napi_callback_info info) {
    struct source_native_reader *reader = source_reader_receiver(env, info);
    if (!reader) return NULL;
    if (!retire_descriptor(&reader->scope->output[reader->index])) {
        reader->scope->controller->retirement_failed = true;
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "source output reader did not retire"); return NULL;
    }
    return undefined(env);
}
static void source_reader_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct source_native_reader *reader = data;
    if (!retire_descriptor(&reader->scope->output[reader->index])) reader->scope->controller->retirement_failed = true;
    source_scope_release(reader->scope); free(reader);
}
static napi_value source_native_result_object(napi_env env, struct source_native_scope *scope) {
    const char *names[] = { "inspection", "index", "pack", "packIndex", "excludeRule" };
    napi_value result, files; napi_create_object(env, &result); napi_create_object(env, &files);
    napi_value death = scope_observation(env, &scope->result); napi_object_freeze(env, death); napi_set_named_property(env, result, "death", death);
    for (unsigned int i = 0; i < CLIQ_SOURCE_OUTPUTS + scope->result.source_rule_present; i++) {
        struct source_native_reader *reader = calloc(1, sizeof(*reader));
        if (!reader) return failure(env, "source output reader allocation unavailable");
        reader->scope = scope; reader->index = i; napi_value object, identity;
        napi_property_descriptor methods[] = {
            { "readChunk", NULL, source_reader_read, NULL, NULL, NULL, napi_default, NULL },
            { "assertHeld", NULL, source_reader_assert, NULL, NULL, NULL, napi_default, NULL },
            { "close", NULL, source_reader_close, NULL, NULL, NULL, napi_default, NULL }
        };
        if (napi_create_object(env, &object) != napi_ok || napi_create_object(env, &identity) != napi_ok) { free(reader); return NULL; }
        set_string(env, identity, "sha256", source_output_digest(scope, i));
        set_number(env, identity, "byteCount", (double)source_output_size(scope, i));
        if (napi_object_freeze(env, identity) != napi_ok || napi_set_named_property(env, object, "identity", identity) != napi_ok ||
            napi_type_tag_object(env, object, &SOURCE_READER_TAG) != napi_ok || napi_define_properties(env, object, 3, methods) != napi_ok ||
            napi_wrap(env, object, reader, source_reader_finalize, NULL, NULL) != napi_ok) { free(reader); return NULL; }
        scope->references++;
        if (napi_object_freeze(env, object) != napi_ok || napi_set_named_property(env, i == 4 ? result : files, names[i], object) != napi_ok) return NULL;
    }
    if (!scope->result.source_rule_present) { napi_value absent; napi_get_null(env, &absent); napi_set_named_property(env, result, "excludeRule", absent); }
    napi_object_freeze(env, files); napi_set_named_property(env, result, "files", files); napi_object_freeze(env, result); return result;
}
static napi_value source_native_poll_result(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->continued || scope->received) return failure(env, "source result can be borrowed only once after the original continuation");
    if (scope->controller->pending == CLIQ_SOURCE_CONTINUE_GIT && !source_native_ack(scope, CLIQ_SOURCE_CONTINUE_GIT))
        return scope->controller->closed ? failure(env, "source continuation acknowledgement failed") : undefined(env);
    if (!scope->controller->pending && !source_native_send(scope, CLIQ_SOURCE_POLL_RESULT)) return failure(env, "source result observation could not be requested");
    struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    int status = source_native_reply(scope, CLIQ_SOURCE_POLL_RESULT, &response, files, &count);
    if (status == 0) return undefined(env);
    bool valid = status == 1 && response.exit_status <= 1;
    uint32_t guard = status == 1 ? 4001 : 0;
    if (valid && response.exit_status == 0 && count == 0) return undefined(env);
    if (valid) guard = 4002;
    valid = valid && response.exit_status == 1 && cliq_source_rule_result_valid(&response) &&
        count == CLIQ_SOURCE_OUTPUTS + response.source_rule_present && response.init_reaped == 1 && response.populated == 0 &&
        response.remaining_descendants == 0 && source_native_time(&response) && response.pid == scope->identity.pid &&
        response.namespace_init_pid == scope->identity.namespace_init_pid && response.monitor_pid == scope->identity.monitor_pid &&
        response.pid_namespace_inode == scope->identity.pid_namespace_inode && response.cgroup_inode == scope->identity.cgroup_inode &&
        response.cgroup_device == scope->identity.cgroup_device && strcmp(response.start_token, scope->identity.start_token) == 0 &&
        strcmp(response.init_start_token, scope->identity.init_start_token) == 0 && strcmp(response.init_native_start_token, scope->identity.init_native_start_token) == 0 &&
        strcmp(response.monitor_start_token, scope->identity.monitor_start_token) == 0 && strcmp(response.source_snapshot_digest, scope->snapshot.source_snapshot_digest) == 0 &&
        response.source_byte_count == scope->snapshot.source_byte_count && response.source_entry_count == scope->snapshot.source_entry_count &&
        response.source_shard_count == scope->snapshot.source_shard_count;
    for (size_t i = 0; valid && i < CLIQ_SOURCE_OUTPUTS; i++) {
        guard = 4003;
        struct stat file;
        valid = fstat(files[i], &file) == 0 && S_ISREG(file.st_mode) && file.st_size >= 0 && (uint64_t)file.st_size == response.source_output_bytes[i] &&
            (uint64_t)file.st_size <= scope->identity.max_file_bytes && (i != 0 || (uint64_t)file.st_size <= scope->identity.max_output_bytes) &&
            cliq_source_digest(response.source_output_digests[i]) && fcntl(files[i], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    }
    if (valid && response.source_rule_present) {
        guard = 4004;
        struct stat rule;
        valid = fstat(files[4], &rule) == 0 && S_ISREG(rule.st_mode) && rule.st_nlink == 0 && rule.st_size >= 0 &&
            (uint64_t)rule.st_size == response.source_rule_bytes &&
            fcntl(files[4], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    }
    if (!valid) {
        for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) scope->controller->retirement_failed = true;
        (void)close_controller(scope->controller); return source_native_postready_failure(env, scope, true, guard);
    }
    for (size_t i = 0; i < count; i++) scope->output[i] = files[i];
    scope->result = response; scope->received = true;
    napi_value result = source_native_result_object(env, scope);
    if (!result) (void)close_controller(scope->controller);
    return result;
}
static napi_value source_native_stop(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, true);
    if (!scope) return NULL;
    (void)close_controller(scope->controller); return undefined(env);
}
static napi_value source_native_retire(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->received) return failure(env, "source normal retirement requires its original completed result");
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (scope->output[i] >= 0)
        return failure(env, "source output readers must join before resource retirement");
    (void)close_controller(scope->controller); return undefined(env);
}
static napi_value source_native_poll_retired(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, true);
    if (!scope) return NULL;
    if (scope->preparation) return preparation_native_retirement(env, scope);
    if (!scope->controller->closed) return failure(env, "source retirement was not requested");
    if (!scope->controller->cleanup_done) return undefined(env);
    if (!scope->joined || scope->controller->retirement_failed || atomic_load(&native_retirement_failed)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "original source domain or resources did not retire"); return NULL;
    }
    struct cliq_source_retirement_data data;
    if (!cliq_source_retirement_project(&scope->original_history, &data))
        return failure(env, "original source retirement has an incomplete physical birth prefix");
    napi_value result; napi_create_object(env, &result);
    set_number(env, result, "observedAtMs", scope->retired_at_ms);
    set_string(env, result, "inspectionId", scope->input->binding.inspection_id);
    set_string(env, result, "stagingNonceDigest", scope->input->binding.staging_nonce);
    set_string(env, result, "targetRef", scope->input->binding.target_ref);
    set_string(env, result, "inputIntentRef", scope->input->binding.input_intent_ref);
    set_number(env, result, "reserved", data.reserved ? 1 : 0); set_number(env, result, "blocked", data.blocked ? 1 : 0);
    set_number(env, result, "released", data.released ? 1 : 0); set_number(env, result, "continued", data.continued ? 1 : 0);
    {
        set_string(env, result, "origin", scope->registered_absent ? "original_birth_registered_absent_checker" :
            scope->retained ? "original_birth_current_checker" : "original_owner_joined");
        set_number(env, result, "lastBirthKind", data.last_kind);
        set_number(env, result, "originalControllerPid", (double)data.controller_pid);
        set_string(env, result, "originalControllerStartToken", data.controller_token);
        napi_value absent; napi_get_null(env, &absent);
        if (data.reserved) {
            char decimal[32]; snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)data.cgroup_device);
            set_string(env, result, "cgroupDeviceId", decimal);
            snprintf(decimal, sizeof(decimal), "%llu", (unsigned long long)data.cgroup_inode); set_string(env, result, "cgroupId", decimal);
            set_string(env, result, "launchNonceDigest", data.launch_nonce);
        } else {
            napi_set_named_property(env, result, "cgroupDeviceId", absent); napi_set_named_property(env, result, "cgroupId", absent);
            napi_set_named_property(env, result, "launchNonceDigest", absent);
        }
        if (data.plan_ref) {
            set_string(env, result, "containmentPlanRef", data.plan_ref);
            set_string(env, result, "sandboxLaunchRef", data.sandbox_launch_ref);
            set_string(env, result, "sandboxLaunchDigest", data.sandbox_launch_digest);
        } else {
            napi_set_named_property(env, result, "containmentPlanRef", absent); napi_set_named_property(env, result, "sandboxLaunchRef", absent);
            napi_set_named_property(env, result, "sandboxLaunchDigest", absent);
        }
        if (data.containment) {
            struct cliq_worker_packet death = *data.containment;
            death.populated = 0; death.remaining_descendants = 0; death.init_reaped = 1; death.observed_at_ms = (uint64_t)scope->retired_at_ms;
            napi_value containment = scope_observation(env, &death); napi_set_named_property(env, result, "containment", containment);
        } else napi_set_named_property(env, result, "containment", absent);
    }
    if (data.snapshot) {
        set_string(env, result, "snapshotDigest", data.snapshot->source_snapshot_digest);
        set_number(env, result, "byteCount", (double)data.snapshot->source_byte_count);
        set_number(env, result, "entryCount", (double)data.snapshot->source_entry_count);
        set_number(env, result, "shardCount", (double)data.snapshot->source_shard_count);
    }
    napi_object_freeze(env, result); return result;
}
static void source_native_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct source_native_scope *scope = data;
    if (!scope->preparation || !scope->joined) (void)close_controller(scope->controller);
    source_scope_release(scope);
}
static napi_value source_native_lifecycle_snapshot(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, true);
    if (!scope) return NULL;
    if (!scope->controller->cleanup_done) return undefined(env);
    if (!scope->joined || scope->controller->retirement_failed || atomic_load(&native_retirement_failed) ||
        !scope->lifecycle_snapshot || !scope->lifecycle_bytes || scope->lifecycle_bytes > CLIQ_SOURCE_HISTORY_MAX_BYTES)
        return failure(env, "source lifecycle requires its complete actual joined native birth");
    napi_value result;
    return napi_create_buffer_copy(env, scope->lifecycle_bytes, scope->lifecycle_snapshot, NULL, &result) == napi_ok ? result : NULL;
}
/* Read-only receiver for a reserve() that threw after claiming its input.
 * It is retained synchronously before close; no new lifecycle is created. */
static napi_value source_native_construction_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1], self, result; struct controller *controller; struct cliq_source_input *input;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 1 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) ||
        !tagged(env, args[0], &CLIQ_SOURCE_INPUT_TAG, (void **)&input)) return failure(env, "invalid original source construction observer");
    struct source_native_scope *scope = controller->source;
    if (!scope) return undefined(env);
    if (scope->retained || scope->input != input || scope->received) return failure(env, "source construction observer differs from its original input");
    const napi_property_descriptor properties[] = {
        { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "pollLifecycleSnapshot", NULL, source_native_lifecycle_snapshot, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok || napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) != napi_ok)
        return failure(env, "source construction observer allocation unavailable");
    scope->references++; napi_object_freeze(env, result); return result;
}
static napi_value source_native_poll_cleaned(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = source_native_receiver(env, info, &argc, NULL, false);
    if (!scope || !scope->retained) return failure(env, "invalid cleanup-only source observer");
    if (scope->recovery_observed) { napi_value result; napi_get_boolean(env, true, &result); return result; }
    struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    struct controller *controller = scope->controller;
    const uint32_t command = scope->registered_absent ? CLIQ_SOURCE_CHECK_REGISTERED_ABSENT : CLIQ_SOURCE_CLEANUP_RETAINED;
    if (controller->pending != command) return failure(env, "retained source cleanup was not requested");
    if (!cliq_receive_flags(controller->socket, &response, files, CLIQ_WORKER_MAX_FDS, &count, MSG_DONTWAIT)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return undefined(env);
        (void)close_controller(controller); return failure(env, "retained source cleanup response is unavailable");
    }
    bool valid = response.command == command && response.status == 0 && count == 0 && source_native_time(&response) &&
        response.scope == scope->identity.scope && response.reservation_observation == scope->original_history.kind &&
        memcmp(response.source_inspection_id, scope->identity.source_inspection_id, sizeof(response.source_inspection_id)) == 0 &&
        memcmp(response.nonce, scope->identity.nonce, sizeof(response.nonce)) == 0 &&
        memcmp(response.source_target_ref, scope->identity.source_target_ref, sizeof(response.source_target_ref)) == 0 &&
        memcmp(response.source_input_intent_ref, scope->identity.source_input_intent_ref, sizeof(response.source_input_intent_ref)) == 0 &&
        response.populated == 0 && response.remaining_descendants == 0 && response.init_reaped == (scope->ready ? 1U : 0U);
    for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) { controller->retirement_failed = true; valid = false; }
    controller->pending = 0;
    if (!valid) { (void)close_controller(controller); return failure(env, "retained source cleanup was not positively observed"); }
    scope->recovery_observed = true; napi_value result; napi_get_boolean(env, true, &result); return result;
}
static napi_value cleanup_source_git_input(napi_env env, napi_callback_info info, bool registered_absent) {
    size_t argc = 1; napi_value args[1], self, result; struct controller *controller; struct cliq_source_input *input;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 1 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready || controller->pending ||
        controller->source_requested || controller->worker_creation_requested || controller->retained_requested || controller->reservation_bound || controller->inspection_only || controller->scopes ||
        !tagged(env, args[0], registered_absent ? &CLIQ_ABSENT_SOURCE_INPUT_TAG : &CLIQ_RETAINED_SOURCE_INPUT_TAG, (void **)&input) ||
        input->abi_version != CLIQ_SOURCE_INPUT_ABI ||
        atomic_load(&input->closed) || atomic_load(&input->execution_claimed) || !input->assert_current || !input->assert_current(input) ||
        !input->retire || input->root_fd != -1 || input->git_fd != -1 || !controller_placement(controller, controller->token))
        return failure(env, "retained source cleanup requires original birth and current installed controller");
    struct source_native_scope *scope = calloc(1, sizeof(*scope));
    if (!scope) return failure(env, "retained source cleanup receiver allocation unavailable");
    scope->controller = controller; scope->input = input; scope->retained = true; scope->registered_absent = registered_absent; scope->cgroup_fd = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) scope->output[i] = -1;
    const napi_property_descriptor methods[] = {
        { "pollCleaned", NULL, source_native_poll_cleaned, NULL, NULL, NULL, napi_default, NULL },
        { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "pollLifecycleSnapshot", NULL, source_native_lifecycle_snapshot, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, source_native_stop, NULL, NULL, NULL, napi_default, NULL }
    };
    unsigned char *snapshot = NULL; size_t snapshot_bytes = 0;
    bool read = registered_absent ? cliq_source_history_read_sealed(input->birth_fd, &input->binding, &scope->original_history,
        &snapshot, &snapshot_bytes) : cliq_source_history_read_snapshot(input->birth_fd, &input->binding, &scope->original_history,
        &snapshot, &snapshot_bytes);
    free(snapshot);
    bool valid = read &&
        cliq_source_recovery_prefix_complete(&scope->original_history) &&
        cliq_source_directory_matches(&scope->original_history.creator.root, &controller->root_identity) &&
        source_native_absent(controller, scope->original_history.creator.pid, scope->original_history.creator.process_start_token);
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        if (scope->input_ref) napi_delete_reference(env, scope->input_ref);
        free(scope); return failure(env, "original source birth or creator death is incomplete");
    }
    struct cliq_worker_packet request = cliq_packet(registered_absent ? CLIQ_SOURCE_CHECK_REGISTERED_ABSENT : CLIQ_SOURCE_CLEANUP_RETAINED); request.scope = 1;
    memcpy(request.source_inspection_id, input->binding.inspection_id, sizeof(request.source_inspection_id));
    memcpy(request.nonce, input->binding.staging_nonce, sizeof(request.nonce));
    memcpy(request.source_target_ref, input->binding.target_ref, sizeof(request.source_target_ref));
    memcpy(request.source_input_intent_ref, input->binding.input_intent_ref, sizeof(request.source_input_intent_ref));
    snprintf(request.cgroup_name, sizeof(request.cgroup_name), "cliq-source-%s", request.nonce);
    scope->identity = request; scope->reserved = scope->original_history.born.cgroup_inode != 0;
    scope->ready = scope->original_history.ready.pid != 0;
    scope->released = scope->original_history.released;
    scope->continued = scope->original_history.continued;
    scope->sealed = scope->original_history.sealed.source_snapshot_digest[0] != '\0'; scope->snapshot = scope->original_history.sealed;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        napi_delete_reference(env, scope->input_ref); free(scope); return failure(env, "retained source cleanup receiver was consumed");
    }
    controller->source_requested = true; controller->source = scope; controller->references++;
    scope->references = 1;
    if (napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) != napi_ok) {
        (void)close_controller(controller); return failure(env, "retained cleanup lifetime could not be retained");
    }
    scope->references++;
    int descriptors[] = { controller->anchor_root, input->birth_fd };
    if (!begin_request(controller, NULL, &request, descriptors, 2)) {
        (void)close_controller(controller); return failure(env, "retained source cleanup dispatch is indeterminate");
    }
    napi_object_freeze(env, result); return result;
}
static napi_value cleanup_retained_source_git(napi_env env, napi_callback_info info) { return cleanup_source_git_input(env, info, false); }
static napi_value cleanup_registered_absent_source_git(napi_env env, napi_callback_info info) { return cleanup_source_git_input(env, info, true); }
static bool source_native_recipe(napi_env env, napi_value config, struct cliq_worker_packet *request, struct cliq_source_config *projection) {
    const char *keys[] = { "maxProcesses", "memoryBytes", "cpuQuotaMicrosPerSecond", "maxOpenFiles", "maxSingleFileBytes", "maxGenerationBytes",
        "maxInvocationOutputBytes", "maxIpcFrameBytes", "maxQueuedIpcBytes", "launchNonceDigest", "repositoryIdentityDigest", "excludeGrantDigest" };
    napi_value names; uint32_t length; bool array; uint64_t frame, queued;
    if (napi_is_array(env, config, &array) != napi_ok || array ||
        napi_get_all_property_names(env, config, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
        napi_get_array_length(env, names, &length) != napi_ok || length != sizeof(keys) / sizeof(keys[0])) return false;
    for (uint32_t i = 0; i < length; i++) {
        napi_value name; char text[64]; size_t bytes; bool known = false;
        if (napi_get_element(env, names, i, &name) != napi_ok || napi_get_value_string_utf8(env, name, text, sizeof(text), &bytes) != napi_ok ||
            bytes == 0 || bytes >= sizeof(text) || strlen(text) != bytes) return false;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++) if (strcmp(text, keys[j]) == 0) known = true;
        if (!known) return false;
    }
    napi_value rule; napi_valuetype rule_type;
    if (napi_get_named_property(env, config, "excludeGrantDigest", &rule) != napi_ok || napi_typeof(env, rule, &rule_type) != napi_ok ||
        (rule_type != napi_null && (rule_type != napi_string ||
          !field_string(env, config, "excludeGrantDigest", request->source_exclude_grant_digest, sizeof(request->source_exclude_grant_digest)) ||
          !cliq_source_digest(request->source_exclude_grant_digest)))) return false;
    return field_number(env, config, "maxIpcFrameBytes", &frame) && frame == 16777216 &&
        field_number(env, config, "maxQueuedIpcBytes", &queued) && queued == 67108864 &&
        field_number(env, config, "maxProcesses", &request->max_processes) && request->max_processes >= 3 && request->max_processes <= 1024 &&
        field_number(env, config, "memoryBytes", &request->memory_bytes) && request->memory_bytes >= UINT64_C(268435456) && request->memory_bytes <= UINT64_C(34359738368) &&
        field_number(env, config, "cpuQuotaMicrosPerSecond", &request->cpu_quota) && request->cpu_quota >= 10000 && request->cpu_quota <= 1600000 &&
        field_number(env, config, "maxOpenFiles", &request->max_open_files) && request->max_open_files >= 64 && request->max_open_files <= 8192 &&
        field_number(env, config, "maxSingleFileBytes", &request->max_file_bytes) && request->max_file_bytes >= 1048576 && request->max_file_bytes <= UINT64_C(17179869184) &&
        field_number(env, config, "maxGenerationBytes", &request->max_generation_bytes) && request->max_generation_bytes >= UINT64_C(268435456) && request->max_generation_bytes <= UINT64_C(107374182400) &&
        field_number(env, config, "maxInvocationOutputBytes", &request->max_output_bytes) && request->max_output_bytes >= 65536 && request->max_output_bytes <= 67108864 &&
        field_string(env, config, "launchNonceDigest", request->activation_nonce, sizeof(request->activation_nonce)) && cliq_source_digest(request->activation_nonce) &&
        field_string(env, config, "repositoryIdentityDigest", projection->repository_identity_digest, sizeof(projection->repository_identity_digest)) &&
        cliq_source_digest(projection->repository_identity_digest);
}
static napi_value reserve_source_git(napi_env env, napi_callback_info info) {
    size_t argc = 6; napi_value args[6], self, result; struct controller *controller; struct image *helper, *bwrap, *inspector;
    struct cliq_source_input *input; struct cliq_guest_toolchain *guest;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 6 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready || controller->pending ||
        controller->source_requested || controller->worker_creation_requested || controller->retained_requested || controller->reservation_bound || controller->inspection_only || controller->scopes ||
        !tagged(env, args[0], &CLIQ_SOURCE_INPUT_TAG, (void **)&input) || input->abi_version != CLIQ_SOURCE_INPUT_ABI ||
        atomic_load(&input->closed) || atomic_load(&input->execution_claimed) || !input->assert_current || !input->assert_current(input) || !input->retire ||
        !tagged(env, args[1], &IMAGE_TAG, (void **)&helper) || helper->fd < 0 || !tagged(env, args[2], &IMAGE_TAG, (void **)&bwrap) || bwrap->fd < 0 ||
        !tagged(env, args[3], &CLIQ_SOURCE_GUEST_TOOLCHAIN_TAG, (void **)&guest) || guest->abi_version != CLIQ_GUEST_ABI_VERSION || guest->source_recipe_version != 1 ||
        strcmp(guest->node_path, "/usr/bin/node") || strcmp(guest->git_path, "/usr/bin/git") ||
        !atomic_load_explicit(&guest->ready, memory_order_acquire) || atomic_load(&guest->revoked) ||
        guest->file_count < 2 || guest->file_count > CLIQ_SOURCE_MAX_FILES ||
        !tagged(env, args[4], &SOURCE_INSPECTOR_IMAGE_TAG, (void **)&inspector) || inspector->fd < 0 || inspector->byte_count == 0 ||
        inspector->byte_count > CLIQ_SOURCE_MAX_CONFIG || !cliq_source_digest(inspector->digest) ||
        !controller_placement(controller, controller->token)) return failure(env, "source reservation requires its original physical input and signed fixed images");
    struct source_native_scope *scope = calloc(1, sizeof(*scope)); struct cliq_source_config *config = calloc(1, sizeof(*config));
    if (!scope || !config) { free(scope); free(config); return failure(env, "source native owner allocation unavailable"); }
    scope->controller = controller; scope->input = input; scope->cgroup_fd = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) scope->output[i] = -1;
    struct cliq_worker_packet request = cliq_packet(CLIQ_SOURCE_RESERVE); request.scope = 1;
    memcpy(request.source_inspection_id, input->binding.inspection_id, sizeof(request.source_inspection_id));
    memcpy(request.nonce, input->binding.staging_nonce, sizeof(request.nonce));
    memcpy(request.source_target_ref, input->binding.target_ref, sizeof(request.source_target_ref));
    memcpy(request.source_input_intent_ref, input->binding.input_intent_ref, sizeof(request.source_input_intent_ref));
    snprintf(request.cgroup_name, sizeof(request.cgroup_name), "cliq-source-%s", request.nonce);
    config->magic = CLIQ_SOURCE_CONFIG_MAGIC; config->version = 1; config->file_count = guest->file_count;
    config->inspector_bytes = inspector->byte_count; memcpy(config->inspector_digest, inspector->digest, sizeof(config->inspector_digest));
    struct stat init;
    bool valid = fstat(helper->fd, &init) == 0 && S_ISREG(init.st_mode) && init.st_size > 0 && init.st_size <= 268435456;
    config->init_bytes = valid ? (uint64_t)init.st_size : 0;
    valid = valid && source_native_recipe(env, args[5], &request, config);
    int files[CLIQ_WORKER_MAX_FDS] = { controller->anchor_root, input->root_fd, input->git_fd, input->birth_fd, -1, helper->fd, bwrap->fd, inspector->fd };
    for (uint32_t i = 0; valid && i < guest->file_count; i++) {
        struct stat file;
        valid = fstat(guest->files[i].fd, &file) == 0 && S_ISREG(file.st_mode) && file.st_size > 0 &&
            (uint64_t)file.st_size == guest->files[i].byte_count &&
            fcntl(guest->files[i].fd, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        config->files[i].byte_count = guest->files[i].byte_count;
        memcpy(config->files[i].path, guest->files[i].path, sizeof(config->files[i].path));
        memcpy(config->files[i].digest, guest->files[i].digest, sizeof(config->files[i].digest)); files[8 + i] = guest->files[i].fd;
    }
    uint64_t root_budget, storage_reserve;
    valid = valid && cliq_source_request_valid(&request) && cliq_source_storage_reserve(config, &request, &root_budget, &storage_reserve);
    int config_fd = valid ? memfd_create("cliq-source-fixed-config", MFD_CLOEXEC | MFD_ALLOW_SEALING) : -1;
    if (config_fd < 0 || write(config_fd, config, sizeof(*config)) != (ssize_t)sizeof(*config) || fchmod(config_fd, 0400) != 0 ||
        fcntl(config_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) valid = false;
    free(config);
    napi_property_descriptor methods[] = {
        { "pollReserved", NULL, source_native_reserved, NULL, NULL, NULL, napi_default, NULL },
        { "createBlocked", NULL, source_native_create, NULL, NULL, NULL, napi_default, NULL },
        { "pollReady", NULL, source_native_ready, NULL, NULL, NULL, napi_default, NULL },
        { "releaseCapture", NULL, source_native_release_capture, NULL, NULL, NULL, napi_default, NULL },
        { "pollSealed", NULL, source_native_poll_sealed, NULL, NULL, NULL, napi_default, NULL },
        { "continueFixedGit", NULL, source_native_continue, NULL, NULL, NULL, napi_default, NULL },
        { "pollResult", NULL, source_native_poll_result, NULL, NULL, NULL, napi_default, NULL },
        { "stop", NULL, source_native_stop, NULL, NULL, NULL, napi_default, NULL },
        { "pollStopped", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "retire", NULL, source_native_retire, NULL, NULL, NULL, napi_default, NULL },
        { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "pollLifecycleSnapshot", NULL, source_native_lifecycle_snapshot, NULL, NULL, NULL, napi_default, NULL }
    };
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        if (!retire_descriptor(&config_fd)) controller->retirement_failed = true;
        if (scope->input_ref) napi_delete_reference(env, scope->input_ref);
        free(scope); return failure(env, "source recipe or native lifetime receiver is invalid");
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        if (!retire_descriptor(&config_fd)) controller->retirement_failed = true;
        napi_delete_reference(env, scope->input_ref); free(scope); return failure(env, "source physical input was already consumed");
    }
    controller->source_requested = true; controller->source = scope; controller->references++;
    scope->references = 1; scope->identity = request;
    if (napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) != napi_ok) {
        (void)retire_descriptor(&config_fd); (void)close_controller(controller); return failure(env, "source original receiver could not be retained");
    }
    scope->references++; files[4] = config_fd;
    bool sent = source_native_controller_frame(scope) && begin_request(controller, NULL, &request, files, 8 + guest->file_count);
    if (!retire_descriptor(&config_fd)) { controller->retirement_failed = true; sent = false; }
    if (!sent) { (void)close_controller(controller); return failure(env, "source reservation dispatch is indeterminate"); }
    napi_object_freeze(env, result); return result;
}
#endif
