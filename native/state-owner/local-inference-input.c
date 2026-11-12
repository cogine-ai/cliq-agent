/* Original local-service resource bookmark. The sole StateOwner retains all
 * original CAS sources and the private witness. This is not Run admission,
 * a model claim, a zero-cost grant or a substitute for physical inspection. */
#ifdef __linux__
#include "../linux/local-inference-input-bridge.h"
#include <sys/mman.h>
#include <sys/syscall.h>
struct local_inference_input {
  struct cliq_local_input bridge;
  state_lock *owner;
  napi_ref owner_reference;
  int owner_pin, retirement_error;
  int parent_fd, cas_fd;
  struct stat parent, cas, sources[CLIQ_LOCAL_SERVICE_FILES];
  struct local_inference_input *next;
};
static struct local_inference_input *local_inference_inputs;
static void local_input_poison(struct local_inference_input *input, int error) {
  input->retirement_error = error ? error : EIO;
  if (input->owner) input->owner->migration_retirement_error = input->retirement_error;
  atomic_store(&current_process_retirement_failed, 1);
}
static bool local_input_context(struct cliq_local_input *bridge) {
  return bridge->creator_pid == getpid() && syscall(SYS_gettid) == getpid();
}
static bool local_input_identity(const struct cliq_local_birth_identity *identity, const struct stat *actual) {
  return identity->device == (uint64_t)actual->st_dev && identity->inode == (uint64_t)actual->st_ino &&
    identity->uid == (uint64_t)actual->st_uid && identity->gid == (uint64_t)actual->st_gid && identity->mode == (uint64_t)actual->st_mode;
}
static void local_input_capture_identity(struct cliq_local_birth_identity *identity, const struct stat *actual) {
  identity->device = actual->st_dev; identity->inode = actual->st_ino;
  identity->uid = actual->st_uid; identity->gid = actual->st_gid; identity->mode = actual->st_mode;
}
static bool local_input_current(struct cliq_local_input *bridge) {
  struct local_inference_input *input = (struct local_inference_input *)bridge;
  struct stat parent, file, named, cas;
  if (!local_input_context(bridge) || bridge->abi != CLIQ_LOCAL_INPUT_ABI || atomic_load(&bridge->closed) ||
      !input->owner || !input->owner_pin || !input->owner->migration_bindings || input->owner->migration_retirement_error ||
      !lock_is_held(input->owner) || input->parent_fd < 0 || bridge->birth_fd < 0 ||
      fstat(input->parent_fd, &parent) || !private_directory(&parent) || !same_inode(&parent, &input->parent) ||
      fstatat(input->owner->runtime_fd, "local-inference", &named, AT_SYMLINK_NOFOLLOW) || !private_directory(&named) || !same_inode(&named, &parent) ||
      fstat(bridge->birth_fd, &file) || !private_lock_file(&file) || !same_inode(&file, &bridge->birth_identity) ||
      fstatat(input->parent_fd, bridge->config.binding.native_nonce, &named, AT_SYMLINK_NOFOLLOW) || !private_lock_file(&named) || !same_inode(&file, &named) ||
      !local_input_identity(&bridge->origin.state_root, &input->owner->root) || !local_input_identity(&bridge->origin.runtime, &input->owner->runtime) ||
      !local_input_identity(&bridge->origin.private_parent, &parent) || !local_input_identity(&bridge->origin.birth, &file)) return false;
  struct cliq_local_birth_frame first;
  if (!cliq_local_birth_read_exact(bridge->birth_fd, &first, sizeof(first), 0) || memcmp(&first, &bridge->origin, sizeof(first))) return false;
  if (bridge->retained) return true;
  if (input->cas_fd < 0 || fstat(input->cas_fd, &cas) || !private_directory(&cas) || !same_inode(&cas, &input->cas) ||
      fstatat(input->owner->root_fd, "cas", &named, AT_SYMLINK_NOFOLLOW) || !private_directory(&named) || !same_inode(&named, &cas)) return false;
  for (uint32_t i = 0; i < bridge->config.file_count; ++i) {
    if (bridge->sources[i] < 0 || fstat(bridge->sources[i], &file) || !source_metadata_same(&file, &input->sources[i]) ||
        fstatat(input->cas_fd, bridge->config.files[i].digest, &named, AT_SYMLINK_NOFOLLOW) || !source_metadata_same(&file, &named)) return false;
  }
  return bridge->bound && bridge->config_fd >= 0 &&
    fcntl(bridge->config_fd, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
}
static int local_input_retire(struct cliq_local_input *bridge) {
  struct local_inference_input *input = (struct local_inference_input *)bridge;
  if (!local_input_context(bridge)) return EBUSY;
  if (atomic_load(&bridge->closed)) return input->retirement_error;
  if (atomic_load(&bridge->execution_claimed) && !atomic_load(&bridge->execution_joined)) return EBUSY;
  atomic_store(&bridge->closed, true);
  for (uint32_t i = 0; i < CLIQ_LOCAL_SERVICE_FILES; ++i) {
    int original = bridge->sources[i]; bridge->sources[i] = -1;
    if (original >= 0 && close(original)) local_input_poison(input, errno);
  }
  int *slots[] = {&bridge->config_fd, &bridge->birth_fd, &input->cas_fd, &input->parent_fd};
  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i) {
    int original = *slots[i]; *slots[i] = -1;
    if (original >= 0 && close(original)) local_input_poison(input, errno);
  }
  if (input->retirement_error) return input->retirement_error;
  if (input->owner_reference) {
    if (napi_delete_reference((napi_env)bridge->environment, input->owner_reference) != napi_ok) { local_input_poison(input, EIO); return input->retirement_error; }
    input->owner_reference = NULL;
  }
  if (input->owner_pin) {
    if (!input->owner || !input->owner->migration_bindings) { local_input_poison(input, EIO); return input->retirement_error; }
    --input->owner->migration_bindings; input->owner_pin = 0;
  }
  input->owner = NULL;
  return 0;
}
static napi_value local_input_retirement_error(napi_env env) {
  napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "local-service input resources did not retire; original StateOwner remains held"); return NULL;
}
static struct local_inference_input *local_input_receiver(napi_env env, napi_callback_info info) {
  napi_value self; bool current = false, retained = false; struct local_inference_input *input = NULL;
  if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
      napi_check_object_type_tag(env, self, &CLIQ_LOCAL_INPUT_TAG, &current) != napi_ok ||
      napi_check_object_type_tag(env, self, &CLIQ_LOCAL_RETAINED_INPUT_TAG, &retained) != napi_ok || (!current && !retained) ||
      napi_unwrap(env, self, (void **)&input) != napi_ok || !input || input->bridge.environment != env || !local_input_context(&input->bridge)) {
    native_error(env, "invalid original local-service input holder"); return NULL;
  }
  return input;
}
static napi_value local_input_assert(napi_env env, napi_callback_info info) {
  struct local_inference_input *input = local_input_receiver(env, info); napi_value result;
  if (!input) return NULL;
  if (!local_input_current(&input->bridge)) return native_error(env, "original local-service input changed, closed or is unbound");
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value local_input_origin(napi_env env, napi_callback_info info) {
  struct local_inference_input *input = local_input_receiver(env, info); napi_value result;
  if (!input) return NULL;
  if (!local_input_current(&input->bridge)) return native_error(env, "original local-service input origin is unavailable");
  return napi_create_buffer_copy(env, sizeof(input->bridge.origin), &input->bridge.origin, NULL, &result) == napi_ok ? result : NULL;
}
static napi_value local_input_close(napi_env env, napi_callback_info info) {
  struct local_inference_input *input = local_input_receiver(env, info); napi_value result;
  if (!input) return NULL;
  if (local_input_retire(&input->bridge)) return local_input_retirement_error(env);
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void local_input_finalize(napi_env env, void *data, void *hint) {
  (void)hint; struct local_inference_input *input = data;
  if (local_input_retire(&input->bridge)) return;
  struct local_inference_input **link = &local_inference_inputs;
  while (*link && *link != input) link = &(*link)->next;
  if (*link) *link = input->next;
  (void)env; free(input);
}
static bool local_input_write(int descriptor, const void *data, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = pwrite(descriptor, (const unsigned char *)data + offset, size - offset, (off_t)offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += (size_t)count;
  }
  return true;
}
static napi_value local_input_open(napi_env env, napi_callback_info info, bool retained) {
  state_lock *owner = unwrap_lock(env, info); size_t count = 3, config_size, origin_size;
  napi_value arguments[3], self, result; void *config_bytes, *origin_bytes;
  if (!owner || !lock_is_held(owner) || owner->migration_retirement_error || owner->migration_bindings == UINT_MAX || syscall(SYS_gettid) != getpid() ||
      napi_get_cb_info(env, info, &count, arguments, &self, NULL) != napi_ok || count != 2 ||
      napi_get_buffer_info(env, arguments[0], &config_bytes, &config_size) != napi_ok || config_size != sizeof(struct cliq_local_service_input) ||
      napi_get_buffer_info(env, arguments[1], &origin_bytes, &origin_size) != napi_ok || origin_size != sizeof(struct cliq_local_birth_frame))
    return native_error(env, "local-service input requires its original main-thread StateOwner and exact closed data bytes");
  struct local_inference_input *input = calloc(1, sizeof(*input));
  if (!input) return native_error(env, "local-service input allocation failed");
  input->owner = owner; input->parent_fd = input->cas_fd = input->bridge.config_fd = input->bridge.birth_fd = -1;
  for (uint32_t i = 0; i < CLIQ_LOCAL_SERVICE_FILES; ++i) input->bridge.sources[i] = -1;
  input->bridge.abi = CLIQ_LOCAL_INPUT_ABI; input->bridge.creator_pid = getpid(); input->bridge.environment = env;
  input->bridge.retained = retained; input->bridge.assert_current = local_input_current; input->bridge.retire = local_input_retire;
  if (napi_create_reference(env, self, 1, &input->owner_reference) != napi_ok) { free(input); return native_error(env, "local-service original Owner pin is unavailable"); }
  ++owner->migration_bindings; input->owner_pin = 1;
  memcpy(&input->bridge.config, config_bytes, sizeof(input->bridge.config)); memcpy(&input->bridge.origin, origin_bytes, sizeof(input->bridge.origin));
  struct cliq_local_birth_frame *origin = &input->bridge.origin; unsigned char digest[32]; char text[65];
  if (!cliq_local_service_input_valid(&input->bridge.config) ||
      memcmp(&origin->packet.binding, &input->bridge.config.binding, sizeof(origin->packet.binding)) ||
      memcmp(&origin->packet.resources, &input->bridge.config.resources, sizeof(origin->packet.resources)) ||
      origin->controller_pid <= 0 || origin->controller_pid > INT32_MAX || !cliq_local_birth_token(origin->controller_start, sizeof(origin->controller_start)) ||
      !cliq_local_birth_controller_name(origin->controller_leaf_name)) goto failed;
  cliq_local_birth_hash(&input->bridge.config, sizeof(input->bridge.config), digest);
  for (size_t i = 0; i < 32; ++i) snprintf(text + i * 2, 3, "%02x", digest[i]);
  if (strcmp(origin->packet.input_digest, text)) goto failed;
  int created = 0;
  if (!retained) { created = mkdirat(owner->runtime_fd, "local-inference", 0700) == 0; if (!created && errno != EEXIST) goto failed; }
  input->parent_fd = openat(owner->runtime_fd, "local-inference", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (input->parent_fd < 0 || fstat(input->parent_fd, &input->parent) || !private_directory(&input->parent) ||
      (created && (fsync(input->parent_fd) || fsync(owner->runtime_fd)))) goto failed;
  input->bridge.birth_fd = openat(input->parent_fd, input->bridge.config.binding.native_nonce,
    retained ? O_RDONLY | O_NOFOLLOW | O_CLOEXEC : O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (input->bridge.birth_fd < 0 || fstat(input->bridge.birth_fd, &input->bridge.birth_identity) || !private_lock_file(&input->bridge.birth_identity)) goto failed;
  if (retained) {
    struct cliq_local_birth_history history;
    if (!local_input_identity(&origin->state_root, &owner->root) || !local_input_identity(&origin->runtime, &owner->runtime) ||
        !local_input_identity(&origin->private_parent, &input->parent) || !local_input_identity(&origin->birth, &input->bridge.birth_identity) ||
        !cliq_local_birth_read(input->bridge.birth_fd, &history) || memcmp(&history.first, origin, sizeof(*origin))) goto failed;
  } else {
    local_input_capture_identity(&origin->state_root, &owner->root); local_input_capture_identity(&origin->runtime, &owner->runtime);
    local_input_capture_identity(&origin->private_parent, &input->parent); local_input_capture_identity(&origin->birth, &input->bridge.birth_identity);
    origin->step = CLIQ_LOCAL_BIRTH_RESERVED; origin->packet.magic = CLIQ_LOCAL_SERVICE_MAGIC; origin->packet.version = 1;
    origin->packet.command = CLIQ_LOCAL_SERVICE_RESERVE; origin->packet.status = 0; memset(&origin->packet.observation, 0, sizeof(origin->packet.observation));
    input->cas_fd = openat(owner->root_fd, "cas", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (input->cas_fd < 0 || fstat(input->cas_fd, &input->cas) || !private_directory(&input->cas)) goto failed;
    for (uint32_t i = 0; i < input->bridge.config.file_count; ++i) {
      const struct cliq_local_service_file *file = &input->bridge.config.files[i];
      input->bridge.sources[i] = openat(input->cas_fd, file->digest, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (input->bridge.sources[i] < 0 || fstat(input->bridge.sources[i], &input->sources[i]) ||
          !S_ISREG(input->sources[i].st_mode) || input->sources[i].st_uid != geteuid() || input->sources[i].st_gid != getegid() ||
          (input->sources[i].st_mode & 07777) != 0400 || input->sources[i].st_nlink != 1 ||
          input->sources[i].st_size < 1 || (uint64_t)input->sources[i].st_size != file->byte_count) goto failed;
    }
    input->bridge.config_fd = memfd_create("cliq-local-service-config-v1", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (input->bridge.config_fd < 0 || !local_input_write(input->bridge.config_fd, &input->bridge.config, sizeof(input->bridge.config)) ||
        fcntl(input->bridge.config_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) ||
        !cliq_local_birth_append(input->bridge.birth_fd, origin) || fsync(input->parent_fd)) goto failed;
  }
  input->bridge.bound = true;
  if (!local_input_current(&input->bridge)) goto failed;
  const napi_property_descriptor methods[] = {
    {"assertHeld", NULL, local_input_assert, NULL, NULL, NULL, napi_default, NULL},
    {"originBytes", NULL, local_input_origin, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, local_input_close, NULL, NULL, NULL, napi_default, NULL}
  };
  if (napi_create_object(env, &result) != napi_ok ||
      napi_type_tag_object(env, result, retained ? &CLIQ_LOCAL_RETAINED_INPUT_TAG : &CLIQ_LOCAL_INPUT_TAG) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, input, local_input_finalize, NULL, NULL) != napi_ok) goto failed;
  input->next = local_inference_inputs; local_inference_inputs = input; return result;
failed:
  if (local_input_retire(&input->bridge)) {
    input->next = local_inference_inputs; local_inference_inputs = input;
    return local_input_retirement_error(env);
  }
  free(input); return native_error(env, "original local-service input binding or complete source layout refused");
}
static napi_value create_local_inference_input(napi_env env, napi_callback_info info) { return local_input_open(env, info, false); }
static napi_value open_retained_local_inference_input(napi_env env, napi_callback_info info) { return local_input_open(env, info, true); }
#else
static napi_value create_local_inference_input(napi_env env, napi_callback_info info) { (void)info; return native_error(env, "managed local inference requires its qualified Linux native backend"); }
static napi_value open_retained_local_inference_input(napi_env env, napi_callback_info info) { (void)info; return native_error(env, "local inference cleanup requires its qualified Linux native backend"); }
#endif
