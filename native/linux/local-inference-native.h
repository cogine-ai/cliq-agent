#ifndef CLIQ_LOCAL_INFERENCE_NATIVE_H
#define CLIQ_LOCAL_INFERENCE_NATIVE_H
#include "local-inference-input-bridge.h"
#include "local-inference-owner-bridge.h"
static const napi_type_tag LOCAL_CONTROLLER_TAG = {UINT64_C(0x1510526e75bf4aad), UINT64_C(0x85a50c20408da571)};
struct local_native_peer;
struct local_native_service {
  struct controller *controller; struct cliq_local_input *input; napi_ref input_reference;
  struct cliq_local_service_packet last;
  uint32_t pending; bool joined, retired, request_failed, engine_released, active;
  bool retained, cleanup_observed, retirement_evidence_complete;
  pid_t original_supervisor;
  char original_supervisor_start[CLIQ_WORKER_TOKEN_BYTES];
  unsigned char original_history_digest[32];
  struct local_native_peer *connector;
  int cgroup; struct stat cgroup_identity;
  double retired_at_ms;
};
static bool local_native_connector_blocks(const struct local_native_service *scope);
static bool local_native_absent(struct controller *controller, int64_t pid, const char *token);
static struct controller *local_native_receiver(napi_env env, napi_callback_info info, size_t *count, napi_value *arguments) {
  napi_value self; struct controller *controller = NULL;
  if (napi_get_cb_info(env, info, count, arguments, &self, NULL) != napi_ok ||
      !tagged(env, self, &LOCAL_CONTROLLER_TAG, (void **)&controller) || controller->env != env ||
      controller->creator_pid != getpid() || syscall(SYS_gettid) != getpid()) {
    failure(env, "invalid original local-service controller"); return NULL;
  }
  return controller;
}
static bool local_native_live(struct controller *controller) {
  return controller && controller->ready && !controller->closed && !controller->constructor_failed && !controller->retirement_failed &&
    !atomic_load(&native_retirement_failed) && anchor_current(controller) && controller_placement(controller, controller->token);
}
static void local_native_identity(struct cliq_local_birth_identity *identity, const struct stat *actual) {
  identity->device = actual->st_dev; identity->inode = actual->st_ino; identity->uid = actual->st_uid; identity->gid = actual->st_gid; identity->mode = actual->st_mode;
}
static bool local_native_identity_matches(const struct cliq_local_birth_identity *identity, const struct stat *actual) {
  struct cliq_local_birth_identity expected; local_native_identity(&expected, actual);
  return !memcmp(identity, &expected, sizeof(expected));
}
static napi_value local_native_origin(napi_env env, napi_callback_info info) {
  size_t count = 2, size; napi_value arguments[2], result; void *bytes;
  struct controller *controller = local_native_receiver(env, info, &count, arguments);
  if (!controller) return NULL;
  if (count != 1 || !local_native_live(controller) || controller->local_service || controller->pending ||
      napi_get_buffer_info(env, arguments[0], &bytes, &size) != napi_ok || size != sizeof(struct cliq_local_service_input) ||
      !cliq_local_service_input_valid(bytes)) return failure(env, "local-service origin requires its exact current fixed input and unreserved owner");
  const struct cliq_local_service_input *config = bytes; struct cliq_local_birth_frame frame; memset(&frame, 0, sizeof(frame));
  frame.packet.magic = CLIQ_LOCAL_SERVICE_MAGIC; frame.packet.version = 1; frame.packet.command = CLIQ_LOCAL_SERVICE_RESERVE;
  frame.packet.binding = config->binding; frame.packet.resources = config->resources; frame.controller_pid = controller->pid;
  memcpy(frame.controller_start, controller->token, sizeof(frame.controller_start)); struct stat image;
  if (controller->local_helper_fd < 0 || fstat(controller->local_helper_fd, &image)) return failure(env, "local-service original controller image is unavailable");
  frame.controller_device = image.st_dev; frame.controller_inode = image.st_ino; frame.controller_uid = image.st_uid;
  local_native_identity(&frame.controller_anchor, &controller->root_identity); local_native_identity(&frame.controller_parent, &controller->parent_identity);
  local_native_identity(&frame.controller_leaf, &controller->leaf_identity); memcpy(frame.controller_leaf_name, controller->leaf_name, sizeof(frame.controller_leaf_name));
  unsigned char digest[32]; cliq_local_birth_hash(config, size, digest);
  for (size_t i = 0; i < 32; ++i) snprintf(frame.packet.input_digest + i * 2, 3, "%02x", digest[i]);
  return napi_create_buffer_copy(env, sizeof(frame), &frame, NULL, &result) == napi_ok ? result : NULL;
}
static bool local_native_send(struct local_native_service *scope, uint32_t command, const int *descriptors, size_t count) {
  struct controller *controller = scope->controller;
  if (!local_native_live(controller) || scope->pending || scope->retired || scope->request_failed || !scope->input ||
      !scope->input->assert_current(scope->input)) return false;
  struct cliq_local_service_packet request = scope->input->origin.packet; request.command = command;
  scope->pending = command;
  if (cliq_local_service_send(controller->socket, &request, descriptors, count)) return true;
  scope->request_failed = true; (void)close_controller(controller); return false;
}
static napi_value local_native_reserve(napi_env env, napi_callback_info info) {
  size_t count = 4; napi_value arguments[4]; struct controller *controller = local_native_receiver(env, info, &count, arguments);
  if (!controller) return NULL;
  struct cliq_local_input *input = NULL; struct image *bootstrap = NULL, *bwrap = NULL;
  if (count != 3 || !local_native_live(controller) || controller->pending || controller->local_service ||
      !tagged(env, arguments[0], &CLIQ_LOCAL_INPUT_TAG, (void **)&input) || !input || input->abi != CLIQ_LOCAL_INPUT_ABI ||
      input->creator_pid != getpid() || input->environment != env || input->retained || !input->bound ||
      !input->assert_current(input) || atomic_load(&input->execution_claimed) ||
      !tagged(env, arguments[1], &IMAGE_TAG, (void **)&bootstrap) || bootstrap->fd < 0 ||
      !tagged(env, arguments[2], &IMAGE_TAG, (void **)&bwrap) || bwrap->fd < 0 ||
      input->origin.controller_pid != controller->pid || strcmp(input->origin.controller_start, controller->token) ||
      !local_native_identity_matches(&input->origin.controller_anchor, &controller->root_identity) ||
      !local_native_identity_matches(&input->origin.controller_parent, &controller->parent_identity) ||
      !local_native_identity_matches(&input->origin.controller_leaf, &controller->leaf_identity) ||
      strcmp(input->origin.controller_leaf_name, controller->leaf_name))
    return failure(env, "local-service reserve requires the original unclaimed input and exact signed images");
  struct stat image;
  if (controller->local_helper_fd < 0 || fstat(controller->local_helper_fd, &image) || input->origin.controller_device != (uint64_t)image.st_dev ||
      input->origin.controller_inode != (uint64_t)image.st_ino || input->origin.controller_uid != (uint64_t)image.st_uid)
    return failure(env, "local-service original image observation differs");
  struct local_native_service *scope = calloc(1, sizeof(*scope));
  if (!scope) return failure(env, "local-service native ownership allocation failed");
  scope->controller = controller; scope->input = input; scope->cgroup = -1; scope->last = input->origin.packet;
  if (napi_create_reference(env, arguments[0], 1, &scope->input_reference) != napi_ok) { free(scope); return failure(env, "local-service original input borrow is unavailable"); }
  bool unclaimed = false;
  if (!atomic_compare_exchange_strong(&input->execution_claimed, &unclaimed, true)) {
    if (napi_delete_reference(env, scope->input_reference) != napi_ok) controller->retirement_failed = true;
    free(scope); return failure(env, "local-service original input was already claimed");
  }
  controller->local_service = scope; ++controller->references;
  int descriptors[CLIQ_LOCAL_SERVICE_FDS]; size_t descriptor_count = 0;
  descriptors[descriptor_count++] = controller->anchor_root; descriptors[descriptor_count++] = input->birth_fd; descriptors[descriptor_count++] = input->config_fd;
  descriptors[descriptor_count++] = bootstrap->fd; descriptors[descriptor_count++] = bwrap->fd; descriptors[descriptor_count++] = controller->local_helper_fd;
  for (uint32_t i = 0; i < input->config.file_count; ++i) descriptors[descriptor_count++] = input->sources[i];
  if (!local_native_send(scope, CLIQ_LOCAL_SERVICE_RESERVE, descriptors, descriptor_count)) return failure(env, "local-service original reserve send is uncertain; original holder remains joinable");
  return undefined(env);
}
static napi_value local_native_cleanup_retained(napi_env env, napi_callback_info info) {
  size_t count = 4, length; napi_value arguments[4]; uint64_t pid;
  char start[CLIQ_WORKER_TOKEN_BYTES]; struct cliq_local_input *input = NULL;
  struct controller *controller = local_native_receiver(env, info, &count, arguments);
  if (!controller) return NULL;
  if (count != 3 || !local_native_live(controller) || controller->pending || controller->local_service ||
      !tagged(env, arguments[0], &CLIQ_LOCAL_RETAINED_INPUT_TAG, (void **)&input) || !input || input->abi != CLIQ_LOCAL_INPUT_ABI ||
      input->creator_pid != getpid() || input->environment != env || !input->retained || !input->bound ||
      !input->assert_current(input) || atomic_load(&input->execution_claimed) || input->config_fd >= 0 ||
      !number(env, arguments[1], &pid) || !pid || pid > INT32_MAX || pid == (uint64_t)getpid() ||
      napi_get_value_string_utf8(env, arguments[2], start, sizeof(start), &length) != napi_ok || length >= sizeof(start) ||
      strlen(start) != length || !cliq_local_birth_token(start, sizeof(start)) || !local_native_absent(controller, (pid_t)pid, start) ||
      !local_native_absent(controller, input->origin.controller_pid, input->origin.controller_start) ||
      !local_native_identity_matches(&input->origin.controller_anchor, &controller->root_identity) ||
      !local_native_identity_matches(&input->origin.controller_parent, &controller->parent_identity))
    return failure(env, "retained local inference requires original input, old process death and exact current anchor");
  struct cliq_local_birth_history history;
  if (!cliq_local_birth_read(input->birth_fd, &history) || memcmp(&history.first, &input->origin, sizeof(history.first)))
    return failure(env, "retained local inference birth history is incomplete or changed");
  struct local_native_service *scope = calloc(1, sizeof(*scope));
  if (!scope) return failure(env, "retained local inference cleanup allocation failed");
  scope->controller = controller; scope->input = input; scope->cgroup = -1; scope->last = input->origin.packet;
  scope->retained = true; scope->original_supervisor = (pid_t)pid;
  memcpy(scope->original_supervisor_start, start, length + 1);
  memcpy(scope->original_history_digest, history.last.digest, sizeof(scope->original_history_digest));
  if (napi_create_reference(env, arguments[0], 1, &scope->input_reference) != napi_ok) {
    free(scope); return failure(env, "retained local inference original source borrow is unavailable");
  }
  bool unclaimed = false;
  if (!atomic_compare_exchange_strong(&input->execution_claimed, &unclaimed, true)) {
    if (napi_delete_reference(env, scope->input_reference) != napi_ok) controller->retirement_failed = true;
    free(scope); return failure(env, "retained local inference source was consumed");
  }
  controller->local_service = scope; ++controller->references;
  int descriptors[] = {controller->anchor_root, input->birth_fd};
  if (!local_native_send(scope, CLIQ_LOCAL_SERVICE_CLEANUP_ORIGINAL, descriptors, 2))
    return failure(env, "retained local inference original cleanup send is uncertain");
  return undefined(env);
}
static napi_value local_native_command(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self; void *data; struct controller *controller = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, &data) != napi_ok || count ||
      !tagged(env, self, &LOCAL_CONTROLLER_TAG, (void **)&controller) || controller->env != env || controller->creator_pid != getpid() ||
      syscall(SYS_gettid) != getpid() || !controller->local_service || controller->local_service->retained)
    return failure(env, "invalid fixed local-service lifecycle request");
  uint32_t command = (uint32_t)(uintptr_t)data;
  if (command == CLIQ_LOCAL_SERVICE_INSPECT_ACTIVE &&
      (controller->local_service->pending || local_native_connector_blocks(controller->local_service))) {
    napi_throw_error(env, "ERR_CLIQ_LOCAL_SERVICE_BUSY", "original local service observation is busy");
    return NULL;
  }
  if (!(command == CLIQ_LOCAL_SERVICE_PREPARE || command == CLIQ_LOCAL_SERVICE_POLL_PREPARED || command == CLIQ_LOCAL_SERVICE_CREATE_BLOCKED ||
        command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE || command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE || command == CLIQ_LOCAL_SERVICE_STOP || command == CLIQ_LOCAL_SERVICE_INSPECT_ACTIVE) ||
      (command != CLIQ_LOCAL_SERVICE_STOP && local_native_connector_blocks(controller->local_service)) ||
      !local_native_send(controller->local_service, command, NULL, 0)) return failure(env, "local-service lifecycle is busy, closed or uncertain");
  return undefined(env);
}
static napi_value local_native_poll(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, result; struct controller *controller = local_native_receiver(env, info, &count, &argument);
  if (!controller) return NULL;
  struct local_native_service *scope = controller->local_service;
  if (count || !local_native_live(controller) || !scope || !scope->pending || !scope->input->assert_current(scope->input))
    return failure(env, "local-service has no original pending lifecycle request");
  if (scope->pending == CLIQ_LOCAL_SERVICE_CONNECT_HEALTH || scope->pending == CLIQ_LOCAL_SERVICE_CONNECT_MODEL)
    return failure(env, "original local-service connection is owned by its private broker consumer");
  struct cliq_local_service_packet response; size_t extra = 0; bool uncertain = false;
  bool received = cliq_local_service_receive(controller->socket, &response, NULL, 0, &extra, MSG_DONTWAIT, &uncertain);
  if (uncertain) { controller->retirement_failed = true; atomic_store(&native_retirement_failed, true); }
  if (!received && !uncertain && (errno == EAGAIN || errno == EWOULDBLOCK)) { napi_get_null(env, &result); return result; }
  if (!received || uncertain || extra || response.magic != CLIQ_LOCAL_SERVICE_MAGIC || response.version != 1 || response.status ||
      response.command != scope->pending || memcmp(&response.binding, &scope->input->origin.packet.binding, sizeof(response.binding)) ||
      memcmp(&response.resources, &scope->input->origin.packet.resources, sizeof(response.resources)) ||
      memcmp(response.input_digest, scope->input->origin.packet.input_digest, sizeof(response.input_digest)) || !response.observation.observed_at_ms) {
    scope->request_failed = true; (void)close_controller(controller); return failure(env, "local-service original lifecycle reply refused; resources require actual join");
  }
  scope->last = response; scope->pending = 0;
  if (response.command == CLIQ_LOCAL_SERVICE_CLEANUP_ORIGINAL) {
    if (!scope->retained || !response.observation.all_reaped || response.observation.populated || response.observation.remaining_descendants) {
      scope->request_failed = true; (void)close_controller(controller); return failure(env, "retained local inference cleanup observation refused");
    }
    scope->cleanup_observed = true;
  }
  if (response.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE) scope->engine_released = true;
  if (response.command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE) scope->active = true;
  if (response.command == CLIQ_LOCAL_SERVICE_RESERVE) {
    char name[96]; int length = snprintf(name, sizeof(name), "cliq-local-%s", response.binding.native_nonce);
    if (length <= 0 || (size_t)length >= sizeof(name) || scope->cgroup >= 0 ||
        (scope->cgroup = openat(controller->anchor_root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0 ||
        !private_cgroup(scope->cgroup, &scope->cgroup_identity) || (uint64_t)scope->cgroup_identity.st_dev != response.observation.cgroup_device ||
        (uint64_t)scope->cgroup_identity.st_ino != response.observation.cgroup_inode) {
      scope->request_failed = true; (void)close_controller(controller); return failure(env, "local-service original cgroup identity refused");
    }
  }
  return napi_create_buffer_copy(env, sizeof(response), &response, NULL, &result) == napi_ok ? result : NULL;
}
static bool local_native_absent(struct controller *controller, int64_t pid, const char *token) {
  if (pid == 0) return token[0] == '\0';
  if (pid < 1 || pid > INT32_MAX || !token[0] || strnlen(token, 192) == 192) return false;
  struct process_sample observed;
  return sample_process(controller, (pid_t)pid, &observed, false) && (observed.absent || strcmp(observed.token, token));
}
static bool local_native_group_empty(struct controller *controller, int group) {
  char events[256];
  if (!domain_without_internal_processes(controller, group, true) ||
      !read_bounded(controller, group, "cgroup.events", events, sizeof(events))) return false;
  return !strncmp(events, "populated 0\n", sizeof("populated 0\n") - 1);
}
static void local_native_joined(struct controller *controller) {
  struct local_native_service *scope = controller->local_service;
  if (!scope) return;
  struct cliq_local_birth_history history;
  if (!scope->input || atomic_load(&scope->input->closed) || !cliq_local_birth_read(scope->input->birth_fd, &history) ||
      memcmp(&history.first, &scope->input->origin, sizeof(history.first))) {
    controller->retirement_failed = true; return;
  }
  if (scope->retained) {
    if (!scope->cleanup_observed || memcmp(history.last.digest, scope->original_history_digest, sizeof(scope->original_history_digest)) ||
        !local_native_absent(controller, scope->original_supervisor, scope->original_supervisor_start) ||
        !local_native_absent(controller, history.first.controller_pid, history.first.controller_start)) {
      controller->retirement_failed = true; return;
    }
    const struct cliq_local_service_observation *retained = &history.last.packet.observation, *current = &scope->last.observation;
    if (retained->cgroup_device != current->cgroup_device || retained->cgroup_inode != current->cgroup_inode ||
        retained->pid_namespace_inode != current->pid_namespace_inode || retained->preparation_pid != current->preparation_pid ||
        retained->monitor_pid != current->monitor_pid || retained->namespace_init_pid != current->namespace_init_pid ||
        retained->bootstrap_pid != current->bootstrap_pid || strcmp(retained->preparation_start, current->preparation_start) ||
        strcmp(retained->monitor_start, current->monitor_start) || strcmp(retained->namespace_init_start, current->namespace_init_start) ||
        strcmp(retained->bootstrap_start, current->bootstrap_start)) {
      controller->retirement_failed = true; return;
    }
  } else {
    if (history.last.step != CLIQ_LOCAL_BIRTH_FDS_RETIRED || !history.last.packet.observation.all_reaped ||
        history.last.packet.observation.populated || history.last.packet.observation.remaining_descendants) {
      controller->retirement_failed = true; return;
    }
    scope->last = history.last.packet;
  }
  const struct cliq_local_service_observation *observed = &scope->last.observation;
  if (!local_native_absent(controller, observed->preparation_pid, observed->preparation_start) ||
      !local_native_absent(controller, observed->monitor_pid, observed->monitor_start) ||
      !local_native_absent(controller, observed->namespace_init_pid, observed->namespace_init_start) ||
      !local_native_absent(controller, observed->bootstrap_pid, observed->bootstrap_start)) { controller->retirement_failed = true; return; }
  char name[96]; int length = snprintf(name, sizeof(name), "cliq-local-%s", history.first.packet.binding.native_nonce);
  struct stat held, named;
  if (length <= 0 || (size_t)length >= sizeof(name)) { controller->retirement_failed = true; return; }
  if (observed->cgroup_inode) {
    if (scope->cgroup < 0) scope->cgroup = openat(controller->anchor_root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scope->cgroup < 0 || !private_cgroup(scope->cgroup, &held) || (uint64_t)held.st_dev != observed->cgroup_device ||
        (uint64_t)held.st_ino != observed->cgroup_inode || fstatat(controller->anchor_root, name, &named, AT_SYMLINK_NOFOLLOW) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino || !local_native_group_empty(controller, scope->cgroup)) {
      controller->retirement_failed = true; return;
    }
  } else if (fstatat(controller->anchor_root, name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) { controller->retirement_failed = true; return; }
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0) { controller->retirement_failed = true; return; }
  scope->retired_at_ms = (double)now.tv_sec * 1000 + now.tv_nsec / 1000000;
  if (scope->retired_at_ms <= 0 || scope->retired_at_ms > 9007199254740991.0) { controller->retirement_failed = true; return; }
  scope->last.observation.observed_at_ms = (uint64_t)scope->retired_at_ms; scope->joined = true;
  scope->retirement_evidence_complete = !history.namespace_intent || history.ready.step == CLIQ_LOCAL_BIRTH_READY;
}
static void local_native_complete(napi_env env, struct controller *controller) {
  struct local_native_service *scope = controller->local_service; if (!scope) return;
  if (!retire_descriptor(&scope->cgroup)) controller->retirement_failed = true;
  if (!scope->joined || controller->retirement_failed || !scope->input->assert_current(scope->input)) {
    controller->retirement_failed = true; return;
  }
  if (scope->input_reference) {
    napi_ref original = scope->input_reference;
    if (napi_delete_reference(env, original) != napi_ok) { controller->retirement_failed = true; return; }
    scope->input_reference = NULL;
  }
  atomic_store(&scope->input->execution_joined, true); scope->retired = true;
  scope->input = NULL; controller_release(controller);
}
static void local_native_dispose(struct controller *controller) {
  if (controller->local_service && controller->local_service->retired) free(controller->local_service);
}
static napi_value local_native_retirement(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, result; struct controller *controller = local_native_receiver(env, info, &count, &argument);
  if (!controller) return NULL;
  struct local_native_service *scope = controller->local_service;
  if (count || !controller->cleanup_done || !controller->reaped || controller->retirement_failed || !scope || !scope->retired || !scope->joined ||
      atomic_load(&native_retirement_failed)) return failure(env, "local-service original process/resources have no complete retirement observation");
  if (!scope->retirement_evidence_complete) return undefined(env);
  return napi_create_buffer_copy(env, sizeof(scope->last), &scope->last, NULL, &result) == napi_ok ? result : NULL;
}
#endif
