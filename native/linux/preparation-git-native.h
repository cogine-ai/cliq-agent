#ifndef CLIQ_PREPARATION_GIT_NATIVE_H
#define CLIQ_PREPARATION_GIT_NATIVE_H

/* The source and preparing owners share fixed Git byte/process plumbing,
 * never their input tags, grants, durable records or completion capability. */
static bool preparation_native_retained_joined(struct source_native_scope *scope);
static bool preparation_native_origin_matches(struct source_native_scope *scope) {
    const struct cliq_preparation_origin *origin = &scope->preparation_origin; struct controller *controller = scope->controller;
    const struct cliq_preparation_input *input = scope->preparation_input;
    return preparation_origin_valid(origin) && origin->controller_pid == (uint64_t)controller->pid && strcmp(origin->controller_token, controller->token) == 0 &&
        origin->root.device == (uint64_t)controller->root_identity.st_dev && origin->root.inode == (uint64_t)controller->root_identity.st_ino &&
        origin->root.uid == controller->root_identity.st_uid && origin->root.gid == controller->root_identity.st_gid && origin->root.mode == controller->root_identity.st_mode &&
        origin->parent.device == (uint64_t)controller->parent_identity.st_dev && origin->parent.inode == (uint64_t)controller->parent_identity.st_ino &&
        origin->parent.uid == controller->parent_identity.st_uid && origin->parent.gid == controller->parent_identity.st_gid && origin->parent.mode == controller->parent_identity.st_mode &&
        origin->leaf.device == (uint64_t)controller->leaf_identity.st_dev && origin->leaf.inode == (uint64_t)controller->leaf_identity.st_ino &&
        origin->leaf.uid == controller->leaf_identity.st_uid && origin->leaf.gid == controller->leaf_identity.st_gid && origin->leaf.mode == controller->leaf_identity.st_mode &&
        strcmp(origin->controller_leaf, controller->leaf_name) == 0 && strcmp(origin->run_id, input->run_id) == 0 && strcmp(origin->launch_id, input->launch_id) == 0 &&
        origin->supervisor_pid == input->supervisor_pid && strcmp(origin->supervisor_token, input->supervisor_token) == 0 &&
        strcmp(origin->spawn_nonce, input->spawn_nonce) == 0 && strcmp(origin->activation_nonce, input->activation_nonce) == 0 &&
        strcmp(origin->creation_nonce, input->creation_nonce) == 0 && strcmp(origin->generation_ref, input->generation_ref) == 0 &&
        strcmp(origin->input_intent_ref, input->input_intent_ref) == 0 && origin->generation_device == (uint64_t)input->generation_identity.st_dev &&
        origin->generation_inode == (uint64_t)input->generation_identity.st_ino && origin->reservation_device == (uint64_t)input->reservation_identity.st_dev &&
        origin->reservation_inode == (uint64_t)input->reservation_identity.st_ino && origin->reservation_uid == input->reservation_identity.st_uid;
}
static bool preparation_native_absent(struct source_native_scope *scope, const struct cliq_preparation_history *history, bool creator_alive) {
    struct controller *controller = scope->controller; struct stat named;
    if (!preparation_native_origin_matches(scope) || !anchor_current(controller) ||
        (creator_alive ? !controller_placement(controller, controller->token) : !controller->reaped) ||
        fstatat(controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
    const struct cliq_preparation_progress *progress = &history->progress;
    if (progress->monitor_pid && !source_native_absent(controller, (int64_t)progress->monitor_pid, progress->monitor_token)) return false;
    if (progress->worker_pid && (!source_native_absent(controller, (int64_t)progress->worker_pid, progress->worker_token) ||
        !source_native_absent(controller, (int64_t)progress->init_pid, progress->init_native_token))) return false;
    return true;
}
static bool preparation_native_read_closed(struct source_native_scope *scope, struct cliq_preparation_history *history, bool creator_alive) {
    return preparation_history_read(scope->preparation_input->reservation_fd, &scope->preparation_origin, history) &&
        (history->phase == CLIQ_PREPARATION_SCOPE_REMOVED || (!creator_alive && history->phase == CLIQ_PREPARATION_ORIGIN)) &&
        preparation_native_absent(scope, history, creator_alive);
}
static bool preparation_native_stamp(struct source_native_scope *scope) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000) return false;
    scope->retired_at_ms = (double)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    return scope->retired_at_ms > 0 && scope->retired_at_ms <= 9007199254740991.0;
}
static bool preparation_native_join_input(struct source_native_scope *scope) {
    struct cliq_preparation_input *input = scope->preparation_input;
    if (!input->assert_current || !input->assert_current(input)) return false;
    if (!retire_descriptor(&scope->preparation_writer) || !retire_descriptor(&scope->cgroup_fd)) return false;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (scope->output[i] >= 0) return false;
    atomic_store(&input->execution_joined, true);
    if (!input->retire || input->retire(input) != 0 || !preparation_native_stamp(scope)) return false;
    scope->joined = true; scope->controller->preparation_joined = true; return true;
}
static void preparation_native_joined(struct controller *controller) {
    struct source_native_scope *scope = controller->source;
    if (!scope || !scope->preparation || scope->joined) return;
    scope->cleanup_valid = scope->retained ? preparation_native_retained_joined(scope) :
        preparation_native_read_closed(scope, &scope->preparation_history, false);
    if (!retire_descriptor(&scope->cgroup_fd)) scope->cleanup_valid = false;
    if (!scope->cleanup_valid) controller->retirement_failed = true;
}
static void preparation_native_complete(napi_env env, struct controller *controller) {
    (void)env; struct source_native_scope *scope = controller->source;
    if (!scope) return;
    if (!scope->joined && scope->cleanup_valid && controller->reaped && !controller->retirement_failed && !atomic_load(&native_retirement_failed)) {
        if (!preparation_native_join_input(scope)) controller->retirement_failed = true;
    }
    source_scope_release(scope);
}
static struct source_native_scope *preparation_native_receiver(napi_env env, napi_callback_info info, size_t *argc, napi_value *args, bool closed) {
    struct source_native_scope *scope = source_native_receiver(env, info, argc, args, closed);
    if (!scope || !scope->preparation) { failure(env, "invalid original preparing Git scope"); return NULL; }
    return scope;
}
static napi_value preparation_native_create(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->reserved || scope->starting || scope->controller->pending || !source_native_current(scope))
        return failure(env, "preparing child requires its exact original reserved scope");
    scope->starting = true;
    if (!source_native_send(scope, CLIQ_SOURCE_CREATE_BLOCKED)) return failure(env, "preparing child creation is indeterminate");
    return undefined(env);
}
static bool preparation_native_stream_send(struct source_native_scope *scope, const struct cliq_preparation_input_message_data *data, const void *payload) {
    unsigned char header[CLIQ_PREPARATION_INPUT_HEADER]; preparation_stream_encode(header, data);
    struct iovec parts[] = { { .iov_base = header, .iov_len = sizeof(header) }, { .iov_base = (void *)payload, .iov_len = data->length } };
    struct msghdr message = { .msg_iov = parts, .msg_iovlen = data->length ? 2 : 1 };
    ssize_t sent; do { sent = sendmsg(scope->preparation_writer, &message, MSG_DONTWAIT | MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
    if (sent != (ssize_t)(CLIQ_PREPARATION_INPUT_HEADER + data->length)) { (void)close_controller(scope->controller); return false; }
    return true;
}
static napi_value preparation_native_sent(napi_env env, struct source_native_scope *scope, bool sent) {
    if (scope->controller->closed) return failure(env, "original preparing CAS input channel failed");
    napi_value value; napi_get_boolean(env, sent, &value); return value;
}
static bool preparation_native_stream_current(struct source_native_scope *scope) {
    return scope->ready && scope->released && !scope->continued && !scope->preparation_input_complete && scope->preparation_writer >= 0 && source_native_current(scope);
}
static napi_value preparation_native_declare(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3]; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, args, false);
    if (!scope) return NULL;
    struct cliq_preparation_input_message_data data = { .kind = CLIQ_PREPARATION_DECLARE }; uint64_t role, count;
    if (argc != 3 || !preparation_native_stream_current(scope) || scope->preparation_leaf_open ||
        !number(env, args[0], &role) || role != scope->preparation_role || role >= CLIQ_PREPARATION_INPUT_FILES ||
        !source_native_digest_argument(env, args[1], data.digest) || !number(env, args[2], &count) || count == 0 || count > scope->identity.max_file_bytes ||
        (role == 0 && (count > scope->identity.max_output_bytes || strcmp(data.digest, scope->preparation_input->input_intent_ref) != 0)) ||
        scope->preparation_total_bytes > scope->identity.max_generation_bytes || count > scope->identity.max_generation_bytes - scope->preparation_total_bytes)
        return failure(env, "preparing CAS leaf differs from its fixed role, original metadata or resource ceiling");
    data.role = (uint32_t)role; data.byte_count = count;
    bool sent = preparation_native_stream_send(scope, &data, NULL);
    if (sent) { unsigned char header[CLIQ_PREPARATION_INPUT_HEADER]; preparation_stream_encode(header, &data);
        sha256_update(&scope->preparation_input_hash, header, sizeof(header)); scope->preparation_leaf_open = true; scope->preparation_leaf_offset = 0;
        scope->preparation_bytes[role] = count; memcpy(scope->preparation_digests[role], data.digest, sizeof(data.digest)); scope->preparation_total_bytes += count; }
    return preparation_native_sent(env, scope, sent);
}
static napi_value preparation_native_write(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1]; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, args, false);
    if (!scope) return NULL;
    void *bytes = NULL; size_t length; bool buffer;
    if (argc != 1 || !preparation_native_stream_current(scope) || !scope->preparation_leaf_open ||
        napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[0], &bytes, &length) != napi_ok ||
        length == 0 || length > CLIQ_PREPARATION_INPUT_CHUNK || length > scope->preparation_bytes[scope->preparation_role] - scope->preparation_leaf_offset)
        return failure(env, "preparing CAS chunk differs from its original bounded leaf");
    struct cliq_preparation_input_message_data data = { .kind = CLIQ_PREPARATION_CHUNK, .role = scope->preparation_role, .length = (uint32_t)length };
    bool sent = preparation_native_stream_send(scope, &data, bytes);
    if (sent) scope->preparation_leaf_offset += length;
    return preparation_native_sent(env, scope, sent);
}
static napi_value preparation_native_end(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!preparation_native_stream_current(scope) || !scope->preparation_leaf_open ||
        scope->preparation_leaf_offset != scope->preparation_bytes[scope->preparation_role]) return failure(env, "preparing CAS leaf has not reached full original EOF");
    struct cliq_preparation_input_message_data data = { .kind = CLIQ_PREPARATION_END, .role = scope->preparation_role };
    bool sent = preparation_native_stream_send(scope, &data, NULL);
    if (sent) { scope->preparation_leaf_open = false; scope->preparation_role++; }
    return preparation_native_sent(env, scope, sent);
}
static napi_value preparation_native_finish_input(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!preparation_native_stream_current(scope) || scope->preparation_leaf_open || scope->preparation_role != CLIQ_PREPARATION_INPUT_FILES)
        return failure(env, "all four original CAS readers must finish before input completion");
    struct cliq_preparation_input_message_data data = { .kind = CLIQ_PREPARATION_INPUT_COMPLETE, .role = CLIQ_PREPARATION_INPUT_FILES };
    bool sent = preparation_native_stream_send(scope, &data, NULL);
    if (sent) {
        scope->preparation_input_complete = true;
        if (!retire_descriptor(&scope->preparation_writer)) { scope->controller->retirement_failed = true; (void)close_controller(scope->controller); }
    }
    return preparation_native_sent(env, scope, sent);
}
static napi_value preparation_native_finish(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, false);
    if (!scope) return NULL;
    if (!scope->received || scope->controller->pending || !source_native_current(scope)) return failure(env, "preparing completion requires its original completed result");
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (scope->output[i] >= 0)
        return failure(env, "preparing output readers must actually close before completion");
    scope->closed = true; scope->preparation_retirement_requested = true; scope->preparation_completion = true;
    if (!source_native_send(scope, CLIQ_PREPARATION_FINISH)) return failure(env, "preparing final retirement is indeterminate");
    return undefined(env);
}
static napi_value preparation_native_stop(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, true);
    if (!scope) return NULL;
    if (scope->joined) return undefined(env);
    scope->closed = true; scope->preparation_stop_requested = true;
    /* Once the original FINISH is in flight, cancellation only revokes its
     * caller. Join that exact physical operation/receipt; never reinterpret
     * its pending reply as CANCEL or erase its completed resource lifecycle.
     * The cancelled TS owner still cannot mint a completion capability. */
    if (!retire_descriptor(&scope->preparation_writer)) scope->controller->retirement_failed = true;
    /* Only after the original task has joined every actual output/CAS user.
     * An earlier abort revokes TS reads but cannot invoke this close. */
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (scope->output[i] >= 0)
        return failure(env, "preparing cancellation requires joined original output readers");
    if (!scope->reserved || scope->controller->pending == CLIQ_SOURCE_CREATE_BLOCKED || scope->controller->pending == CLIQ_PREPARATION_RESERVE)
        (void)close_controller(scope->controller);
    return undefined(env);
}
static bool preparation_native_progress_cancel(struct source_native_scope *scope) {
    struct controller *controller = scope->controller;
    if (controller->closed) return true;
    if (scope->preparation_retirement_requested) return true;
    if (controller->pending) {
        struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
        uint32_t command = controller->pending;
        int status = source_native_reply(scope, command, &response, files, &count);
        bool joined = true;
        for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) joined = false;
        if (!joined) controller->retirement_failed = true;
        if (status == 0) return false;
        if (status < 0 || !joined) { (void)close_controller(controller); return false; }
    }
    scope->preparation_retirement_requested = true;
    if (!source_native_send(scope, CLIQ_PREPARATION_CANCEL)) { (void)close_controller(controller); return false; }
    return true;
}
static napi_value preparation_native_retirement(napi_env env, struct source_native_scope *scope) {
    struct controller *controller = scope->controller;
    if (scope->retained && !controller->closed) return failure(env, "preparing current checker has not joined");
    if (!scope->joined && scope->preparation_stop_requested && !preparation_native_progress_cancel(scope)) return undefined(env);
    if (!scope->joined && !controller->closed) {
        if (!scope->preparation_retirement_requested) return failure(env, "original preparing retirement was not requested");
        struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
        uint32_t command = scope->preparation_completion ? CLIQ_PREPARATION_FINISH : CLIQ_PREPARATION_CANCEL;
        int status = source_native_reply(scope, command, &response, files, &count); bool valid = count == 0;
        for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
        if (status == 0) return undefined(env);
        valid = valid && status == 1 && response.reservation_observation == (scope->preparation_completion ? 1U : 0U) &&
            source_native_time(&response) && preparation_native_read_closed(scope, &scope->preparation_history, true);
        if (!valid || !preparation_native_join_input(scope)) { controller->retirement_failed = true; (void)close_controller(controller);
            return failure(env, "original preparing resources were not positively retired"); }
        controller->preparation_finished = scope->preparation_completion;
    }
    if (controller->closed && !controller->cleanup_done) return undefined(env);
    if (!scope->joined || controller->retirement_failed || atomic_load(&native_retirement_failed)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "original preparing Git resources did not retire"); return NULL;
    }
    napi_value result; napi_create_object(env, &result);
    const struct cliq_preparation_input *input = scope->preparation_input;
    set_string(env, result, "origin", scope->retained ? "original_birth_current_checker" : "original_owner_joined"); set_number(env, result, "observedAtMs", scope->retired_at_ms);
    set_number(env, result, "completed", scope->preparation_completion ? 1 : 0);
    set_number(env, result, "lastBirthPhase", scope->preparation_history.phase);
    set_string(env, result, "runId", input->run_id); set_string(env, result, "generationId", input->generation_id); set_string(env, result, "launchId", input->launch_id);
    set_string(env, result, "spawnNonceDigest", input->spawn_nonce); set_string(env, result, "activationNonceDigest", input->activation_nonce);
    set_string(env, result, "generationCreationNonceDigest", input->creation_nonce); set_string(env, result, "generationRef", input->generation_ref);
    set_string(env, result, "inputIntentRef", input->input_intent_ref);
    set_number(env, result, "originalControllerPid", (double)scope->preparation_origin.controller_pid);
    set_string(env, result, "originalControllerStartToken", scope->preparation_origin.controller_token);
    set_number(env, result, "originalSupervisorPid", (double)input->supervisor_pid); set_string(env, result, "originalSupervisorStartToken", input->supervisor_token);
    napi_object_freeze(env, result); return result;
}
static void preparation_native_directory(struct cliq_preparation_directory *target, const struct stat *source) {
    target->device = source->st_dev; target->inode = source->st_ino; target->uid = source->st_uid;
    target->gid = source->st_gid; target->mode = source->st_mode;
}
static bool preparation_native_recipe(napi_env env, napi_value value, struct cliq_worker_packet *request,
    struct cliq_source_config *config, struct cliq_preparation_origin *origin) {
    const char *keys[] = { "maxProcesses", "memoryBytes", "cpuQuotaMicrosPerSecond", "maxOpenFiles", "maxSingleFileBytes", "maxGenerationBytes",
        "maxInvocationOutputBytes", "maxIpcFrameBytes", "maxQueuedIpcBytes", "stateOwnerEpoch", "supervisorInstanceId", "stateOwnerRowDigest",
        "sessionId", "sourceCheckpointId", "sourceWorkspaceStateRef", "repositoryIdentityDigest" };
    napi_value names; uint32_t length; bool array;
    if (napi_is_array(env, value, &array) != napi_ok || array ||
        napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
        napi_get_array_length(env, names, &length) != napi_ok || length != sizeof(keys) / sizeof(keys[0])) return false;
    for (uint32_t i = 0; i < length; i++) {
        napi_value name; char text[64]; size_t bytes; bool known = false;
        if (napi_get_element(env, names, i, &name) != napi_ok || napi_get_value_string_utf8(env, name, text, sizeof(text), &bytes) != napi_ok ||
            !bytes || bytes >= sizeof(text) || strlen(text) != bytes) return false;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++) if (strcmp(text, keys[j]) == 0) known = true;
        if (!known) return false;
    }
    if (!field_number(env, value, "maxProcesses", &request->max_processes) || !field_number(env, value, "memoryBytes", &request->memory_bytes) ||
        !field_number(env, value, "cpuQuotaMicrosPerSecond", &request->cpu_quota) || !field_number(env, value, "maxOpenFiles", &request->max_open_files) ||
        !field_number(env, value, "maxSingleFileBytes", &request->max_file_bytes) || !field_number(env, value, "maxGenerationBytes", &request->max_generation_bytes) ||
        !field_number(env, value, "maxInvocationOutputBytes", &request->max_output_bytes) ||
        !field_number(env, value, "maxIpcFrameBytes", &origin->max_ipc_frame_bytes) || !field_number(env, value, "maxQueuedIpcBytes", &origin->max_queued_ipc_bytes) ||
        !field_number(env, value, "stateOwnerEpoch", &origin->owner_epoch) ||
        !field_string(env, value, "supervisorInstanceId", origin->supervisor_id, sizeof(origin->supervisor_id)) ||
        !field_string(env, value, "sessionId", origin->session_id, sizeof(origin->session_id)) ||
        !field_string(env, value, "sourceCheckpointId", origin->checkpoint_id, sizeof(origin->checkpoint_id)) ||
        !field_string(env, value, "stateOwnerRowDigest", origin->state_owner_digest, sizeof(origin->state_owner_digest)) ||
        !field_string(env, value, "sourceWorkspaceStateRef", origin->source_workspace_ref, sizeof(origin->source_workspace_ref)) ||
        !field_string(env, value, "repositoryIdentityDigest", origin->repository_digest, sizeof(origin->repository_digest))) return false;
    origin->max_processes = request->max_processes; origin->memory_bytes = request->memory_bytes; origin->cpu_quota = request->cpu_quota;
    origin->max_open_files = request->max_open_files; origin->max_file_bytes = request->max_file_bytes;
    origin->max_generation_bytes = request->max_generation_bytes; origin->max_output_bytes = request->max_output_bytes;
    memcpy(config->repository_identity_digest, origin->repository_digest, sizeof(config->repository_identity_digest));
    return preparation_origin_valid(origin) && cliq_preparation_request_valid(request);
}
static napi_value preparation_native_construction_retirement(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1], self, result; struct controller *controller; struct cliq_preparation_input *input;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 1 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) ||
        (!tagged(env, args[0], &CLIQ_PREPARATION_INPUT_TAG, (void **)&input) &&
         !tagged(env, args[0], &CLIQ_RETAINED_PREPARATION_INPUT_TAG, (void **)&input))) return failure(env, "invalid original preparing construction observer");
    struct source_native_scope *scope = controller->source;
    if (!scope) return undefined(env);
    if (!scope->preparation || scope->preparation_input != input || scope->received)
        return failure(env, "preparing construction observer differs from its original input");
    napi_property_descriptor property = { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL };
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, 1, &property) != napi_ok || napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) != napi_ok)
        return failure(env, "preparing construction observer allocation unavailable");
    scope->references++; napi_object_freeze(env, result); return result;
}
static napi_value reserve_preparation_git(napi_env env, napi_callback_info info) {
    size_t argc = 6; napi_value args[6], self, result; struct controller *controller; struct image *helper, *bwrap, *inspector;
    struct cliq_preparation_input *input; struct cliq_guest_toolchain *guest;
    char supervisor_token[CLIQ_WORKER_TOKEN_BYTES];
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 6 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready || controller->pending ||
        controller->source_requested || controller->preparation_started || controller->worker_creation_requested || controller->retained_requested ||
        controller->reservation_bound || controller->inspection_only || controller->scopes ||
        !tagged(env, args[0], &CLIQ_PREPARATION_INPUT_TAG, (void **)&input) || input->abi_version != CLIQ_PREPARATION_INPUT_ABI ||
        input->cleanup_only || input->supervisor_pid != (uint64_t)getpid() ||
        !cliq_process_token(getpid(), supervisor_token) || strcmp(supervisor_token, input->supervisor_token) != 0 ||
        atomic_load(&input->closed) || atomic_load(&input->execution_claimed) || !input->assert_current || !input->assert_current(input) || !input->retire ||
        !tagged(env, args[1], &IMAGE_TAG, (void **)&helper) || helper->fd < 0 || !tagged(env, args[2], &IMAGE_TAG, (void **)&bwrap) || bwrap->fd < 0 ||
        !tagged(env, args[3], &CLIQ_SOURCE_GUEST_TOOLCHAIN_TAG, (void **)&guest) || guest->abi_version != CLIQ_GUEST_ABI_VERSION || guest->source_recipe_version != 1 ||
        strcmp(guest->node_path, "/usr/bin/node") || strcmp(guest->git_path, "/usr/bin/git") ||
        !atomic_load_explicit(&guest->ready, memory_order_acquire) || atomic_load(&guest->revoked) || guest->file_count < 2 || guest->file_count > CLIQ_SOURCE_MAX_FILES ||
        !tagged(env, args[4], &SOURCE_INSPECTOR_IMAGE_TAG, (void **)&inspector) || inspector->fd < 0 || !inspector->byte_count ||
        inspector->byte_count > CLIQ_SOURCE_MAX_CONFIG || !cliq_source_digest(inspector->digest) ||
        !controller_placement(controller, controller->token)) return failure(env, "preparing reservation requires its same-lock birth and signed fixed images");
    struct source_native_scope *scope = calloc(1, sizeof(*scope)); struct cliq_source_config *config = calloc(1, sizeof(*config));
    if (!scope || !config) { free(scope); free(config); return failure(env, "preparing native owner allocation unavailable"); }
    scope->controller = controller; scope->preparation = true; scope->preparation_input = input; scope->cgroup_fd = scope->preparation_writer = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) scope->output[i] = -1;
    struct cliq_worker_packet request = cliq_packet(CLIQ_PREPARATION_RESERVE); request.scope = 1;
    request.generation_device = input->generation_identity.st_dev; request.generation_inode = input->generation_identity.st_ino;
    request.reservation_device = input->reservation_identity.st_dev; request.reservation_inode = input->reservation_identity.st_ino;
    request.reservation_uid = input->reservation_identity.st_uid; request.subreaper_pid = controller->pid;
    memcpy(request.subreaper_start_token, controller->token, sizeof(request.subreaper_start_token));
    memcpy(request.nonce, input->spawn_nonce, sizeof(request.nonce)); memcpy(request.activation_nonce, input->activation_nonce, sizeof(request.activation_nonce));
    memcpy(request.generation_ref, input->generation_ref, sizeof(request.generation_ref));
    memcpy(request.preparation_input_intent_ref, input->input_intent_ref, sizeof(request.preparation_input_intent_ref));
    snprintf(request.cgroup_name, sizeof(request.cgroup_name), "cliq-preparation-%s", request.nonce);
    struct cliq_preparation_origin *origin = &scope->preparation_origin;
    origin->controller_pid = controller->pid; origin->supervisor_pid = input->supervisor_pid;
    memcpy(origin->supervisor_token, input->supervisor_token, sizeof(origin->supervisor_token));
    origin->reservation_device = input->reservation_identity.st_dev;
    origin->reservation_inode = input->reservation_identity.st_ino; origin->reservation_uid = input->reservation_identity.st_uid;
    origin->generation_device = input->generation_identity.st_dev; origin->generation_inode = input->generation_identity.st_ino;
    preparation_native_directory(&origin->root, &controller->root_identity); preparation_native_directory(&origin->parent, &controller->parent_identity);
    preparation_native_directory(&origin->leaf, &controller->leaf_identity);
    memcpy(origin->run_id, input->run_id, sizeof(origin->run_id)); memcpy(origin->launch_id, input->launch_id, sizeof(origin->launch_id));
    memcpy(origin->controller_leaf, controller->leaf_name, strlen(controller->leaf_name) + 1); memcpy(origin->controller_token, controller->token, sizeof(origin->controller_token));
    memcpy(origin->creation_nonce, input->creation_nonce, sizeof(origin->creation_nonce)); memcpy(origin->spawn_nonce, input->spawn_nonce, sizeof(origin->spawn_nonce));
    memcpy(origin->activation_nonce, input->activation_nonce, sizeof(origin->activation_nonce)); memcpy(origin->generation_ref, input->generation_ref, sizeof(origin->generation_ref));
    memcpy(origin->input_intent_ref, input->input_intent_ref, sizeof(origin->input_intent_ref));
    config->magic = CLIQ_SOURCE_CONFIG_MAGIC; config->version = 1; config->file_count = guest->file_count;
    config->inspector_bytes = inspector->byte_count; memcpy(config->inspector_digest, inspector->digest, sizeof(config->inspector_digest));
    struct stat init; bool valid = fstat(helper->fd, &init) == 0 && S_ISREG(init.st_mode) && init.st_size > 0 && init.st_size <= 268435456;
    config->init_bytes = valid ? (uint64_t)init.st_size : 0;
    valid = valid && preparation_native_recipe(env, args[5], &request, config, origin);
    int files[CLIQ_WORKER_MAX_FDS] = { controller->anchor_root, input->reservation_fd, -1, -1, -1, helper->fd, bwrap->fd, inspector->fd };
    for (uint32_t i = 0; valid && i < guest->file_count; i++) {
        struct stat file; valid = fstat(guest->files[i].fd, &file) == 0 && S_ISREG(file.st_mode) && file.st_size > 0 &&
            (uint64_t)file.st_size == guest->files[i].byte_count && fcntl(guest->files[i].fd, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        config->files[i].byte_count = guest->files[i].byte_count; memcpy(config->files[i].path, guest->files[i].path, sizeof(config->files[i].path));
        memcpy(config->files[i].digest, guest->files[i].digest, sizeof(config->files[i].digest)); files[8 + i] = guest->files[i].fd;
    }
    uint64_t runtime_budget, storage_reserve; int stream[2] = { -1, -1 }, config_fd = -1, origin_fd = -1;
    valid = valid && cliq_source_storage_reserve(config, &request, &runtime_budget, &storage_reserve) &&
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, stream) == 0 &&
        fcntl(stream[0], F_SETFL, O_NONBLOCK) == 0;
    if (valid) {
        config_fd = memfd_create("cliq-preparing-fixed-config", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        origin_fd = memfd_create("cliq-preparing-original-birth", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        unsigned char body[CLIQ_RESERVATION_BODY]; preparation_origin_encode(body, origin);
        valid = config_fd >= 0 && origin_fd >= 0 && write(config_fd, config, sizeof(*config)) == (ssize_t)sizeof(*config) &&
            write(origin_fd, body, sizeof(body)) == (ssize_t)sizeof(body) && fchmod(config_fd, 0400) == 0 && fchmod(origin_fd, 0400) == 0 &&
            fcntl(config_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0 &&
            fcntl(origin_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0;
    }
    free(config);
    const napi_property_descriptor methods[] = {
        { "pollReserved", NULL, source_native_reserved, NULL, NULL, NULL, napi_default, NULL },
        { "createBlocked", NULL, preparation_native_create, NULL, NULL, NULL, napi_default, NULL },
        { "pollReady", NULL, source_native_ready, NULL, NULL, NULL, napi_default, NULL },
        { "releaseCapture", NULL, source_native_release_capture, NULL, NULL, NULL, napi_default, NULL },
        { "declareInput", NULL, preparation_native_declare, NULL, NULL, NULL, napi_default, NULL },
        { "writeInput", NULL, preparation_native_write, NULL, NULL, NULL, napi_default, NULL },
        { "endInput", NULL, preparation_native_end, NULL, NULL, NULL, napi_default, NULL },
        { "finishInput", NULL, preparation_native_finish_input, NULL, NULL, NULL, napi_default, NULL },
        { "pollSealed", NULL, source_native_poll_sealed, NULL, NULL, NULL, napi_default, NULL },
        { "continueFixedGit", NULL, source_native_continue, NULL, NULL, NULL, napi_default, NULL },
        { "pollResult", NULL, source_native_poll_result, NULL, NULL, NULL, napi_default, NULL },
        { "stop", NULL, preparation_native_stop, NULL, NULL, NULL, napi_default, NULL },
        { "pollStopped", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "retire", NULL, preparation_native_finish, NULL, NULL, NULL, napi_default, NULL },
        { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL }
    };
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        bool joined = retire_descriptor(&config_fd); if (!retire_descriptor(&origin_fd)) joined = false;
        for (size_t i = 0; i < 2; i++) if (!retire_descriptor(&stream[i])) joined = false;
        if (!joined) controller->retirement_failed = true;
        if (scope->input_ref) napi_delete_reference(env, scope->input_ref);
        free(scope); return failure(env, "preparing recipe or original native receiver is invalid");
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        bool joined = retire_descriptor(&config_fd); if (!retire_descriptor(&origin_fd)) joined = false;
        for (size_t i = 0; i < 2; i++) if (!retire_descriptor(&stream[i])) joined = false;
        if (!joined) controller->retirement_failed = true;
        napi_delete_reference(env, scope->input_ref); free(scope); return failure(env, "preparing physical input was already consumed");
    }
    scope->preparation_writer = stream[0]; stream[0] = -1; scope->identity = request; sha256_init(&scope->preparation_input_hash);
    controller->source_requested = controller->preparation_started = true; controller->source = scope; controller->references++; scope->references = 1;
    bool wrapped = napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) == napi_ok;
    if (wrapped) scope->references++;
    files[2] = stream[1]; files[3] = config_fd; files[4] = origin_fd;
    bool sent = wrapped && preparation_native_origin_matches(scope) && begin_request(controller, NULL, &request, files, 8 + guest->file_count);
    if (!retire_descriptor(&stream[1])) { controller->retirement_failed = true; sent = false; }
    if (!retire_descriptor(&config_fd)) { controller->retirement_failed = true; sent = false; }
    if (!retire_descriptor(&origin_fd)) { controller->retirement_failed = true; sent = false; }
    if (!sent) { (void)close_controller(controller); return failure(env, "preparing reservation dispatch is indeterminate"); }
    napi_object_freeze(env, result); return result;
}
static bool preparation_native_cleanup_input_matches(struct source_native_scope *scope) {
    const struct cliq_preparation_origin *origin = &scope->preparation_origin; const struct cliq_preparation_input *input = scope->preparation_input;
    return input->cleanup_only && input->generation_fd == -1 && origin->reservation_device == (uint64_t)input->reservation_identity.st_dev &&
        origin->reservation_inode == (uint64_t)input->reservation_identity.st_ino && origin->reservation_uid == input->reservation_identity.st_uid &&
        origin->generation_device == (uint64_t)input->generation_identity.st_dev && origin->generation_inode == (uint64_t)input->generation_identity.st_ino &&
        strcmp(origin->run_id, input->run_id) == 0 && strcmp(origin->launch_id, input->launch_id) == 0 &&
        strcmp(origin->spawn_nonce, input->spawn_nonce) == 0 && strcmp(origin->activation_nonce, input->activation_nonce) == 0 &&
        strcmp(origin->creation_nonce, input->creation_nonce) == 0 && strcmp(origin->generation_ref, input->generation_ref) == 0 &&
        strcmp(origin->input_intent_ref, input->input_intent_ref) == 0 && origin->supervisor_pid == input->supervisor_pid &&
        strcmp(origin->supervisor_token, input->supervisor_token) == 0;
}
static bool preparation_native_retained_joined(struct source_native_scope *scope) {
    struct controller *controller = scope->controller; const struct cliq_preparation_origin *origin = &scope->preparation_origin;
    struct cliq_preparation_history history; struct stat held, named;
    bool valid = scope->recovery_observed && preparation_native_cleanup_input_matches(scope) && anchor_current(controller) &&
        origin->root.device == (uint64_t)controller->root_identity.st_dev && origin->root.inode == (uint64_t)controller->root_identity.st_ino &&
        origin->root.uid == controller->root_identity.st_uid && origin->root.gid == controller->root_identity.st_gid && origin->root.mode == controller->root_identity.st_mode &&
        preparation_read_cleanup_history(scope->preparation_input->reservation_fd, origin, &history) &&
        history.frames == scope->preparation_history.frames && history.bytes == scope->preparation_history.bytes &&
        memcmp(history.digest, scope->preparation_history.digest, sizeof(history.digest)) == 0 &&
        source_native_absent(controller, (int64_t)origin->supervisor_pid, origin->supervisor_token) &&
        source_native_absent(controller, (int64_t)origin->controller_pid, origin->controller_token);
    int parent = valid ? openat(controller->anchor_root, "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    valid = valid && parent >= 0 && private_cgroup(parent, &held) && (uint64_t)held.st_dev == origin->parent.device && (uint64_t)held.st_ino == origin->parent.inode &&
        held.st_uid == origin->parent.uid && held.st_gid == origin->parent.gid && held.st_mode == origin->parent.mode &&
        fstatat(controller->anchor_root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_directory(&held, &named) &&
        fstatat(parent, origin->controller_leaf, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(controller->anchor_root, scope->identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    const struct cliq_preparation_progress *progress = &history.progress;
    if (valid && progress->monitor_pid) valid = source_native_absent(controller, (int64_t)progress->monitor_pid, progress->monitor_token);
    if (valid && progress->worker_pid) valid = source_native_absent(controller, (int64_t)progress->worker_pid, progress->worker_token) &&
        source_native_absent(controller, (int64_t)progress->init_pid, progress->init_native_token);
    if (!retire_descriptor(&parent)) { controller->retirement_failed = true; valid = false; }
    return valid;
}
static napi_value preparation_native_poll_cleaned(napi_env env, napi_callback_info info) {
    size_t argc = 0; struct source_native_scope *scope = preparation_native_receiver(env, info, &argc, NULL, false);
    if (!scope || !scope->retained) return failure(env, "invalid preparing cleanup-only observer");
    if (scope->recovery_observed) { napi_value value; napi_get_boolean(env, true, &value); return value; }
    struct cliq_worker_packet response; int files[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    int status = source_native_reply(scope, CLIQ_PREPARATION_CLEANUP_RETAINED, &response, files, &count);
    bool valid = status >= 0 && count == 0;
    for (size_t i = 0; i < count; i++) if (!retire_descriptor(&files[i])) valid = false;
    if (status == 0 && valid) return undefined(env);
    valid = valid && status == 1 && source_native_time(&response) && response.reservation_observation == (uint32_t)scope->preparation_history.phase &&
        response.populated == 0 && response.remaining_descendants == 0 && response.init_reaped == (scope->preparation_history.progress.worker_pid ? 1U : 0U);
    if (!valid) { (void)close_controller(scope->controller); return failure(env, "retained preparing cleanup did not positively complete"); }
    scope->recovery_observed = true; napi_value value; napi_get_boolean(env, true, &value); return value;
}
static napi_value cleanup_retained_preparation_git(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2], self, result; struct controller *controller; struct cliq_preparation_input *input;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 2 ||
        !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready || controller->pending ||
        controller->source_requested || controller->worker_creation_requested || controller->retained_requested || controller->reservation_bound || controller->inspection_only || controller->scopes ||
        !tagged(env, args[0], &CLIQ_RETAINED_PREPARATION_INPUT_TAG, (void **)&input) || input->abi_version != CLIQ_PREPARATION_INPUT_ABI || !input->cleanup_only ||
        input->generation_fd != -1 || atomic_load(&input->closed) || atomic_load(&input->execution_claimed) || !input->assert_current ||
        !input->assert_current(input) || !input->retire || !controller_placement(controller, controller->token))
        return failure(env, "retained preparing cleanup requires its original reservation and current installed checker");
    struct source_native_scope *scope = calloc(1, sizeof(*scope)); if (!scope) return failure(env, "retained preparing receiver allocation unavailable");
    scope->controller = controller; scope->preparation_input = input; scope->preparation = scope->retained = true; scope->cgroup_fd = scope->preparation_writer = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) scope->output[i] = -1;
    unsigned char body[CLIQ_RESERVATION_BODY]; size_t offset = 0;
    bool valid = reservation_frame(input->reservation_fd, &offset, CLIQ_PREPARATION_FACT_BASE, body, sizeof(body)) &&
        preparation_origin_decode(body, &scope->preparation_origin) && preparation_native_cleanup_input_matches(scope) &&
        preparation_read_cleanup_history(input->reservation_fd, &scope->preparation_origin, &scope->preparation_history) &&
        source_native_absent(controller, (int64_t)input->supervisor_pid, input->supervisor_token) &&
        source_native_absent(controller, (int64_t)scope->preparation_origin.controller_pid, scope->preparation_origin.controller_token);
    struct cliq_worker_packet request = cliq_packet(CLIQ_PREPARATION_CLEANUP_RETAINED); request.scope = 1;
    request.generation_device = input->generation_identity.st_dev; request.generation_inode = input->generation_identity.st_ino;
    request.reservation_device = input->reservation_identity.st_dev; request.reservation_inode = input->reservation_identity.st_ino; request.reservation_uid = input->reservation_identity.st_uid;
    request.subreaper_pid = (int64_t)scope->preparation_origin.controller_pid; memcpy(request.subreaper_start_token, scope->preparation_origin.controller_token, sizeof(request.subreaper_start_token));
    memcpy(request.nonce, input->spawn_nonce, sizeof(request.nonce)); memcpy(request.activation_nonce, input->activation_nonce, sizeof(request.activation_nonce));
    memcpy(request.generation_ref, input->generation_ref, sizeof(request.generation_ref)); memcpy(request.preparation_input_intent_ref, input->input_intent_ref, sizeof(request.preparation_input_intent_ref));
    snprintf(request.cgroup_name, sizeof(request.cgroup_name), "cliq-preparation-%s", request.nonce);
    struct cliq_preparation_origin selected = scope->preparation_origin; struct cliq_source_config config = {0};
    valid = valid && preparation_native_recipe(env, args[1], &request, &config, &selected) && preparation_origin_same(&selected, &scope->preparation_origin) &&
        selected.root.device == (uint64_t)controller->root_identity.st_dev && selected.root.inode == (uint64_t)controller->root_identity.st_ino &&
        selected.root.uid == controller->root_identity.st_uid && selected.root.gid == controller->root_identity.st_gid && selected.root.mode == controller->root_identity.st_mode;
    const napi_property_descriptor methods[] = {
        { "pollCleaned", NULL, preparation_native_poll_cleaned, NULL, NULL, NULL, napi_default, NULL },
        { "pollRetired", NULL, source_native_poll_retired, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, source_native_stop, NULL, NULL, NULL, napi_default, NULL }
    };
    if (!valid || napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &SOURCE_SCOPE_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok || napi_create_reference(env, args[0], 1, &scope->input_ref) != napi_ok) {
        if (scope->input_ref) napi_delete_reference(env, scope->input_ref);
        free(scope); return failure(env, "retained preparing prefix, owner death or fixed recipe is incomplete");
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong(&input->execution_claimed, &expected, true)) {
        napi_delete_reference(env, scope->input_ref); free(scope); return failure(env, "retained preparing cleanup input is already consumed");
    }
    scope->identity = request; scope->references = 1; controller->source = scope; controller->source_requested = controller->preparation_started = true; controller->references++;
    if (napi_wrap(env, result, scope, source_native_finalize, NULL, NULL) != napi_ok) {
        (void)close_controller(controller); return failure(env, "retained preparing receiver could not be retained");
    }
    scope->references++; int descriptors[] = { controller->anchor_root, input->reservation_fd };
    if (!begin_request(controller, NULL, &request, descriptors, 2)) { (void)close_controller(controller); return failure(env, "retained preparing cleanup dispatch is indeterminate"); }
    napi_object_freeze(env, result); return result;
}
#endif
