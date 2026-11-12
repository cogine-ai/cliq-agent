#ifndef CLIQ_LOCAL_INFERENCE_DATA_H
#define CLIQ_LOCAL_INFERENCE_DATA_H
/* Exact native-layout encoding/decoding of closed data only. These functions
 * create no source holder, process, connection, observation or authority. */
static bool local_data_keys(napi_env env, napi_value value, const char *const *keys, size_t count) {
  napi_valuetype type; napi_value names; uint32_t size;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_object ||
      napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
      napi_get_array_length(env, names, &size) != napi_ok || size != count) return false;
  for (size_t i = 0; i < count; ++i) {
    bool present; napi_value key;
    if (napi_create_string_utf8(env, keys[i], NAPI_AUTO_LENGTH, &key) != napi_ok ||
        napi_has_own_property(env, value, key, &present) != napi_ok || !present) return false;
  }
  return true;
}
static bool local_data_member(napi_env env, napi_value value, const char *key, napi_value *member) {
  return napi_get_named_property(env, value, key, member) == napi_ok;
}
static bool local_data_image(napi_env env, napi_value value, char digest[65], uint64_t *bytes) {
  const char *const keys[] = {"digest", "byteCount"};
  return local_data_keys(env, value, keys, 2) && field_string(env, value, "digest", digest, 65) && cliq_hex_digest(digest) &&
    field_number(env, value, "byteCount", bytes) && *bytes > 0 && *bytes <= UINT64_C(268435456);
}
static napi_value local_data_encode(napi_env env, napi_callback_info info) {
  size_t count = 2; napi_value argument[2], binding, resources, files, bootstrap, image, bwrap, result;
  const char *const keys[] = {"binding", "resources", "bootstrap", "controller", "bubblewrap", "files"};
  if (napi_get_cb_info(env, info, &count, argument, NULL, NULL) != napi_ok || count != 1 || !local_data_keys(env, argument[0], keys, 6) ||
      !local_data_member(env, argument[0], "binding", &binding) || !local_data_member(env, argument[0], "resources", &resources) ||
      !local_data_member(env, argument[0], "files", &files) || !local_data_member(env, argument[0], "bootstrap", &bootstrap) ||
      !local_data_member(env, argument[0], "controller", &image) || !local_data_member(env, argument[0], "bubblewrap", &bwrap))
    return failure(env, "local-service input encoding requires its exact closed data object");
  struct cliq_local_service_input *config = calloc(1, sizeof(*config)); if (!config) return failure(env, "bounded local-service input encoding unavailable");
  config->magic = CLIQ_LOCAL_SERVICE_MAGIC; config->version = 1;
  struct {const char *key; char *output; size_t capacity;} texts[] = {
    {"ownerPrincipalId", config->binding.owner, sizeof(config->binding.owner)}, {"serviceId", config->binding.service, sizeof(config->binding.service)},
    {"serviceLaunchId", config->binding.launch, sizeof(config->binding.launch)}, {"activationCycleId", config->binding.cycle, sizeof(config->binding.cycle)},
    {"supervisorInstanceId", config->binding.supervisor, sizeof(config->binding.supervisor)},
    {"localModelRegistrationRef", config->binding.registration_ref, 65}, {"localModelRegistrationDigest", config->binding.registration_digest, 65},
    {"serviceSpecRef", config->binding.service_ref, 65}, {"serviceSpecDigest", config->binding.service_digest, 65},
    {"runtimeBundleRef", config->binding.runtime_ref, 65}, {"runtimeBundleManifestDigest", config->binding.runtime_digest, 65},
    {"modelManifestRef", config->binding.model_ref, 65}, {"modelManifestDigest", config->binding.model_digest, 65},
    {"objectClosureRef", config->binding.closure_ref, 65}, {"objectClosureDigest", config->binding.closure_digest, 65},
    {"sandboxProfileRef", config->binding.profile_ref, 65}, {"sandboxProfileDigest", config->binding.profile_digest, 65},
    {"containmentPlanRef", config->binding.plan_ref, 65}, {"containmentPlanDigest", config->binding.plan_digest, 65},
    {"sandboxLaunchSpecRef", config->binding.spec_ref, 65}, {"sandboxLaunchSpecDigest", config->binding.spec_digest, 65},
    {"nativeNonce", config->binding.native_nonce, 65}, {"activationNonce", config->binding.activation_nonce, 65},
  };
  const size_t text_count = sizeof(texts) / sizeof(texts[0]); const char *binding_keys[28];
  _Static_assert(sizeof(texts) / sizeof(texts[0]) + 5 == 28, "fixed local binding key count changed");
  for (size_t i = 0; i < text_count; ++i) binding_keys[i] = texts[i].key;
  const char *numeric_keys[] = {"stateOwnerEpoch", "createdAtMs", "activationDeadlineAtMs", "activationAttempt", "port"};
  for (size_t i = 0; i < 5; ++i) binding_keys[text_count + i] = numeric_keys[i];
  bool valid = text_count + 5 == sizeof(binding_keys) / sizeof(binding_keys[0]) && local_data_keys(env, binding, binding_keys, text_count + 5);
  for (size_t i = 0; valid && i < text_count; ++i) valid = field_string(env, binding, texts[i].key, texts[i].output, texts[i].capacity);
  uint64_t attempt, port;
  valid = valid && field_number(env, binding, "stateOwnerEpoch", &config->binding.owner_epoch) &&
    field_number(env, binding, "createdAtMs", &config->binding.created_at_ms) && field_number(env, binding, "activationDeadlineAtMs", &config->binding.activation_deadline_ms) &&
    field_number(env, binding, "activationAttempt", &attempt) && attempt <= UINT32_MAX && field_number(env, binding, "port", &port) && port <= UINT32_MAX;
  if (valid) { config->binding.attempt = (uint32_t)attempt; config->binding.port = (uint32_t)port; }
  struct {const char *key; uint64_t *output;} numbers[] = {
    {"maxProcesses", &config->resources.max_processes}, {"memoryBytes", &config->resources.memory_bytes},
    {"cpuQuotaMicrosPerSecond", &config->resources.cpu_quota}, {"maxOpenFiles", &config->resources.max_open_files},
    {"maxSingleFileBytes", &config->resources.max_file_bytes}, {"maxGenerationBytes", &config->resources.max_generation_bytes},
    {"maxInvocationOutputBytes", &config->resources.max_output_bytes}, {"maxIpcFrameBytes", &config->resources.max_ipc_bytes},
    {"maxQueuedIpcBytes", &config->resources.max_queued_ipc_bytes},
  };
  const char *resource_keys[9]; for (size_t i = 0; i < 9; ++i) resource_keys[i] = numbers[i].key;
  valid = valid && local_data_keys(env, resources, resource_keys, 9);
  for (size_t i = 0; valid && i < 9; ++i) valid = field_number(env, resources, numbers[i].key, numbers[i].output);
  valid = valid && local_data_image(env, bootstrap, config->bootstrap_digest, &config->bootstrap_bytes) &&
    local_data_image(env, image, config->controller_digest, &config->controller_bytes) &&
    local_data_image(env, bwrap, config->bubblewrap_digest, &config->bubblewrap_bytes);
  bool array; uint32_t length;
  valid = valid && napi_is_array(env, files, &array) == napi_ok && array && napi_get_array_length(env, files, &length) == napi_ok && length <= CLIQ_LOCAL_SERVICE_FILES;
  if (valid) config->file_count = length;
  const char *const file_keys[] = {"kind", "byteCount", "artifactRef", "guestPath"};
  for (uint32_t i = 0; valid && i < config->file_count; ++i) {
    napi_value file; char kind[32]; struct cliq_local_service_file *member = &config->files[i];
    valid = napi_get_element(env, files, i, &file) == napi_ok && local_data_keys(env, file, file_keys, 4) &&
      field_string(env, file, "kind", kind, sizeof(kind)) && field_number(env, file, "byteCount", &member->byte_count) &&
      field_string(env, file, "artifactRef", member->digest, 65) && field_string(env, file, "guestPath", member->guest_path, sizeof(member->guest_path));
    if (!valid) break;
    member->kind = !strcmp(kind, "model_manifest") ? CLIQ_LOCAL_FILE_MANIFEST : !strcmp(kind, "model_tokenizer") ? CLIQ_LOCAL_FILE_TOKENIZER :
      !strcmp(kind, "model_file") ? CLIQ_LOCAL_FILE_MODEL : !strcmp(kind, "engine") ? CLIQ_LOCAL_FILE_ENGINE :
      !strcmp(kind, "library") ? CLIQ_LOCAL_FILE_LIBRARY : !strcmp(kind, "helper") ? CLIQ_LOCAL_FILE_HELPER : !strcmp(kind, "loader") ? CLIQ_LOCAL_FILE_LOADER : 0;
    member->mode = member->kind == CLIQ_LOCAL_FILE_ENGINE || member->kind == CLIQ_LOCAL_FILE_HELPER || member->kind == CLIQ_LOCAL_FILE_LOADER ? 0500 : 0400;
    if (member->kind >= CLIQ_LOCAL_FILE_MANIFEST && member->kind <= CLIQ_LOCAL_FILE_MODEL) ++config->model_mount_count;
  }
  valid = valid && cliq_local_service_input_valid(config);
  napi_status status = valid ? napi_create_buffer_copy(env, sizeof(*config), config, NULL, &result) : napi_invalid_arg;
  free(config); return status == napi_ok ? result : failure(env, "closed local-service data differs from its fixed native recipe");
}
#endif
