#ifndef CLIQ_LOCAL_INFERENCE_PEER_NATIVE_H
#define CLIQ_LOCAL_INFERENCE_PEER_NATIVE_H
#include <arpa/inet.h>
/* Original controller/connection ownership only; fixed HTTP framing and the
 * permanent model claim remain in the one mature selected model broker. */
struct local_native_peer {
  struct cliq_local_service_peer bridge;
  struct local_native_service *scope;
  napi_ref owner_reference;
  bool closed, cancelled, pending, handed;
};
static bool local_native_connector_blocks(const struct local_native_service *scope) {
  return scope->connector && !scope->connector->handed && !scope->connector->closed;
}
static bool local_peer_context(struct local_native_peer *peer) {
  return peer && peer->bridge.creator_pid == getpid() && syscall(SYS_gettid) == getpid() && peer->bridge.environment && peer->bridge.abi == CLIQ_LOCAL_OWNER_ABI;
}
static bool local_peer_current(struct cliq_local_service_peer *handle) {
  struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_context(peer) || peer->closed || peer->cancelled || !peer->owner_reference || !peer->scope || peer->scope->retired ||
      peer->scope->request_failed || peer->scope->connector != peer || !local_native_live(peer->scope->controller) ||
      !peer->scope->input || !peer->scope->input->assert_current(peer->scope->input) ||
      memcmp(&handle->binding, &peer->scope->input->origin.packet.binding, sizeof(handle->binding))) return false;
  return handle->purpose == CLIQ_LOCAL_PEER_HEALTH ? peer->scope->engine_released : handle->purpose == CLIQ_LOCAL_PEER_MODEL && peer->scope->active;
}
static int local_peer_begin(struct cliq_local_service_peer *handle) {
  struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_current(handle) || !handle->borrowed || peer->pending || peer->handed || peer->scope->pending) return -1;
  uint32_t command = handle->purpose == CLIQ_LOCAL_PEER_HEALTH ? CLIQ_LOCAL_SERVICE_CONNECT_HEALTH : CLIQ_LOCAL_SERVICE_CONNECT_MODEL;
  peer->pending = true;
  if (local_native_send(peer->scope, command, NULL, 0)) return 0;
  return -1;
}
static int local_peer_poll(struct cliq_local_service_peer *handle, int *output) {
  *output = -1; struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_context(peer) || peer->closed || !handle->borrowed || !peer->pending || !peer->scope) return -1;
  struct controller *controller = peer->scope->controller;
  if (controller->closed) return controller->cleanup_done && !controller->retirement_failed && peer->scope->retired ? -1 : 0;
  uint32_t command = handle->purpose == CLIQ_LOCAL_PEER_HEALTH ? CLIQ_LOCAL_SERVICE_CONNECT_HEALTH : CLIQ_LOCAL_SERVICE_CONNECT_MODEL;
  if (peer->scope->pending != command) return -1;
  struct cliq_local_service_packet response; int descriptor[1] = {-1}; size_t count = 0; bool uncertain = false;
  bool received = cliq_local_service_receive(controller->socket, &response, descriptor, 1, &count, MSG_DONTWAIT, &uncertain);
  if (!received && !uncertain && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
  if (uncertain) { controller->retirement_failed = true; atomic_store(&native_retirement_failed, true); }
  bool valid = received && !uncertain && response.magic == CLIQ_LOCAL_SERVICE_MAGIC && response.version == 1 && response.command == command &&
    !memcmp(&response.binding, &handle->binding, sizeof(handle->binding)) &&
    !memcmp(&response.resources, &peer->scope->input->origin.packet.resources, sizeof(response.resources)) &&
    !memcmp(response.input_digest, peer->scope->input->origin.packet.input_digest, sizeof(response.input_digest)) && response.observation.observed_at_ms &&
    ((response.status == 0 && count == 1) || (response.status == 2 && count == 0));
  if (valid) { peer->pending = false; peer->scope->pending = 0; }
  if (valid && !response.status && !peer->cancelled) {
    int type; socklen_t size = sizeof(type); struct sockaddr_in address; socklen_t address_size = sizeof(address);
    valid = !getsockopt(descriptor[0], SOL_SOCKET, SO_TYPE, &type, &size) && type == SOCK_STREAM &&
      !getpeername(descriptor[0], (struct sockaddr *)&address, &address_size) && address_size == sizeof(address) &&
      address.sin_family == AF_INET && address.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && ntohs(address.sin_port) == handle->binding.port;
    if (valid) { peer->handed = true; *output = descriptor[0]; descriptor[0] = -1; }
  }
  if (!retire_descriptor(&descriptor[0])) { controller->retirement_failed = true; valid = false; }
  if (!valid) { peer->scope->request_failed = true; (void)close_controller(controller); return -1; }
  return *output >= 0 ? 1 : !peer->cancelled && response.status == 2 ? CLIQ_LOCAL_PEER_NOT_LISTENING : -1;
}
static int local_peer_cancel(struct cliq_local_service_peer *handle) {
  struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_context(peer) || peer->closed) return -1;
  peer->cancelled = true; return 0;
}
static int local_peer_joined(struct cliq_local_service_peer *handle) {
  struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_context(peer) || peer->closed || !peer->cancelled || !peer->scope) return -1;
  if (!peer->pending) return 1;
  struct controller *controller = peer->scope->controller;
  if (controller->closed) {
    if (!controller->cleanup_done) return 0;
    if (controller->retirement_failed || !peer->scope->retired) return -1;
    peer->pending = false; return 1;
  }
  int descriptor = -1; (void)local_peer_poll(handle, &descriptor);
  if (descriptor >= 0) {
    if (!retire_descriptor(&descriptor)) { controller->retirement_failed = true; return -1; }
    return -1;
  }
  return peer->scope->request_failed || controller->retirement_failed ? -1 : peer->pending ? 0 : 1;
}
static int local_peer_release(struct cliq_local_service_peer *handle) {
  struct local_native_peer *peer = (struct local_native_peer *)handle;
  if (!local_peer_context(peer)) return -1;
  if (peer->closed) return 0;
  if (!peer->cancelled || local_peer_joined(handle) != 1 || !peer->scope || peer->scope->connector != peer) return -1;
  struct controller *controller = peer->scope->controller;
  if (peer->owner_reference && napi_delete_reference((napi_env)handle->environment, peer->owner_reference) != napi_ok) {
    controller->retirement_failed = true; atomic_store(&native_retirement_failed, true); return -1;
  }
  peer->owner_reference = NULL; peer->scope->connector = NULL; peer->scope = NULL; peer->closed = true; handle->borrowed = false; return 0;
}
static struct local_native_peer *local_peer_receiver(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self; struct local_native_peer *peer = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
      (!tagged(env, self, &CLIQ_LOCAL_HEALTH_PEER_TAG, (void **)&peer) && !tagged(env, self, &CLIQ_LOCAL_MODEL_PEER_TAG, (void **)&peer)) ||
      !local_peer_context(peer) || peer->bridge.environment != env) { failure(env, "invalid original local-service connection peer"); return NULL; }
  return peer;
}
static napi_value local_peer_assert_call(napi_env env, napi_callback_info info) {
  struct local_native_peer *peer = local_peer_receiver(env, info); if (!peer) return NULL;
  return local_peer_current(&peer->bridge) ? undefined(env) : failure(env, "original local-service peer is closed, revoked or mismatched");
}
static napi_value local_peer_close_call(napi_env env, napi_callback_info info) {
  struct local_native_peer *peer = local_peer_receiver(env, info); if (!peer) return NULL;
  if (peer->closed) return undefined(env);
  if (peer->bridge.borrowed || local_peer_cancel(&peer->bridge) || local_peer_release(&peer->bridge)) return failure(env, "original local-service peer remains live or uncertain");
  return undefined(env);
}
static void local_peer_finalize(napi_env env, void *data, void *hint) {
  (void)hint; struct local_native_peer *peer = data;
  if (!local_peer_context(peer) || peer->bridge.environment != env || peer->bridge.borrowed) return;
  if (!peer->closed && (local_peer_cancel(&peer->bridge) || local_peer_release(&peer->bridge))) return;
  free(peer);
}
static napi_value local_peer_create(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; void *data; struct controller *controller = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, &data) != napi_ok || count ||
      !tagged(env, self, &LOCAL_CONTROLLER_TAG, (void **)&controller) || !local_native_live(controller) || controller->env != env ||
      controller->creator_pid != getpid() || syscall(SYS_gettid) != getpid() || !controller->local_service ||
      !controller->local_service->input || !controller->local_service->input->assert_current(controller->local_service->input))
    return failure(env, "original local-service connection owner is closed or unavailable");
  if (controller->local_service->pending || controller->local_service->connector) {
    napi_throw_error(env, "ERR_CLIQ_LOCAL_SERVICE_BUSY", "original local-service connection capacity is occupied"); return NULL;
  }
  uint32_t purpose = (uint32_t)(uintptr_t)data;
  if (!((purpose == CLIQ_LOCAL_PEER_HEALTH && controller->local_service->engine_released) ||
      (purpose == CLIQ_LOCAL_PEER_MODEL && controller->local_service->active)))
    return failure(env, "original local-service connection purpose is not released");
  struct local_native_peer *peer = calloc(1, sizeof(*peer)); if (!peer) return failure(env, "local-service peer allocation failed");
  peer->scope = controller->local_service; peer->bridge.abi = CLIQ_LOCAL_OWNER_ABI; peer->bridge.purpose = purpose;
  peer->bridge.creator_pid = getpid(); peer->bridge.environment = env; peer->bridge.binding = peer->scope->input->origin.packet.binding;
  peer->bridge.assert_current = local_peer_current; peer->bridge.begin_connection = local_peer_begin; peer->bridge.poll_connection = local_peer_poll;
  peer->bridge.cancel = local_peer_cancel; peer->bridge.poll_joined = local_peer_joined; peer->bridge.release = local_peer_release;
  const napi_property_descriptor methods[] = {
    {"assertHeld", NULL, local_peer_assert_call, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, local_peer_close_call, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_create_reference(env, self, 1, &peer->owner_reference) != napi_ok || napi_create_object(env, &result) != napi_ok ||
      napi_type_tag_object(env, result, purpose == CLIQ_LOCAL_PEER_HEALTH ? &CLIQ_LOCAL_HEALTH_PEER_TAG : &CLIQ_LOCAL_MODEL_PEER_TAG) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, peer, local_peer_finalize, NULL, NULL) != napi_ok) {
    if (peer->owner_reference && napi_delete_reference(env, peer->owner_reference) != napi_ok) {
      controller->retirement_failed = true; atomic_store(&native_retirement_failed, true); return failure(env, "local-service peer construction reference did not retire");
    }
    free(peer); return failure(env, "local-service original peer construction failed");
  }
  peer->scope->connector = peer; return result;
}
#endif
