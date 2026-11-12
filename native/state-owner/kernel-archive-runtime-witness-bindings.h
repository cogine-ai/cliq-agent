/* Fixed methods of the original kernel_archive receiver. The TS caller
 * selects each complete original retired launch and independently validates
 * its native source evidence. These operations have no execution authority. */
static int karw_ready(kernel_archive *held, napi_env env) {
    return ka_main_check(held, env) == 0 && held->phase == KA_SEALED && !held->failed &&
        !atomic_load(&held->cancelled) && !kernel_archive_active;
}
static napi_value karw_count(napi_env env, kernel_archive *held, int result, const char *message) {
    if (result < 0) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    if (result < 0) return ka_error(env, held, message);
    napi_value value; return napi_get_boolean(env, result != 0, &value) == napi_ok ? value : NULL;
}
static napi_value karw_begin(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    napi_value args[2]; size_t count = 2; double entries = 0;
    int valid = karw_ready(held, env) && kam_verified(held) && !held->cas && held->runtime_witnesses &&
        napi_get_cb_info(env, info, &count, args, NULL, NULL) == napi_ok && count == 1 &&
        napi_get_value_double(env, args[0], &entries) == napi_ok && entries >= 0 && entries <= RW_MAX_COUNT &&
        entries == (uint64_t)entries && kam_payload_bytes(held) <= KERNEL_ARCHIVE_MAX_BYTES - held->byte_count &&
        rw_begin_capture(held->runtime_witnesses, (uint64_t)entries,
            KERNEL_ARCHIVE_MAX_BYTES - held->byte_count - kam_payload_bytes(held)) == 0;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "runtime witness capture requires the original bounded retired launch cut");
}
static napi_value karw_begin_entry(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    napi_value args[2]; size_t count = 2, size = 0; const unsigned char *bytes;
    int valid = karw_ready(held, env) && !held->cas && held->runtime_witnesses &&
        napi_get_cb_info(env, info, &count, args, NULL, NULL) == napi_ok && count == 1 && ca_buffer(env, args[0], &bytes, &size) == 0 &&
        rw_begin_entry(held->runtime_witnesses, bytes, size) == 0;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "runtime witness differs from its exact original retired launch packet");
}
static napi_value karw_begin_observe(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = karw_ready(held, env) && !held->cas &&
        rw_begin_observation_arguments(env, info, held->runtime_witnesses) == 0;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "runtime witness observation requires its exact original Anchor and birth");
}
static napi_value karw_observe_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int result = karw_ready(held, env) && !held->cas ? rw_retired_observation_next(held->runtime_witnesses) : -1;
    return karw_count(env, held, result, "runtime witness cannot prove its complete original readonly retirement");
}
static napi_value karw_observation(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    napi_value result = karw_ready(held, env) ? rw_observation_value(env, held->runtime_witnesses) : NULL;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return result ? result : ka_error(env, held, "runtime witness observation has not actually completed and closed");
}
static napi_value karw_copy_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int result = karw_ready(held, env) && !held->cas ? rw_capture_entry_next(held->runtime_witnesses) : -1;
    return karw_count(env, held, result, "runtime witness copy changed or failed to close its original reader");
}
static napi_value karw_seal(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = karw_ready(held, env) && !held->cas && rw_begin_seal(held->runtime_witnesses) == 0;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "runtime witness pack cannot seal before the complete original capture");
}
static napi_value karw_verify_next(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int result = karw_ready(held, env) ? rw_verify_next(held->runtime_witnesses) : -1;
    return karw_count(env, held, result, "runtime witness pack bytes, namespace or original readers did not verify");
}
static napi_value karw_recheck(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    int valid = karw_ready(held, env) && rw_restart_complete(held->runtime_witnesses) == 0;
    if (!valid) held->failed = 1;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? ka_undefined(env) : ka_error(env, held, "runtime witness recheck requires the same original fully sealed pack");
}
static napi_value karw_identity(napi_env env, napi_callback_info info) {
    kernel_archive *held = ka_receiver(env, info); if (!held || ka_main_lock(env, held) != 0) return NULL;
    rw_archive *witnesses = held->runtime_witnesses; napi_value result, pack;
    int valid = karw_ready(held, env) && (!witnesses || witnesses->phase == RW_COMPLETE) &&
        napi_create_object(env, &result) == napi_ok;
    if (valid && !witnesses) valid = ka_string_member(env, result, "kind", "absent");
    else if (valid) {
        valid = napi_create_object(env, &pack) == napi_ok && ka_string_member(env, result, "kind", "captured") &&
            ka_string_member(env, result, "layout", "cliq-local-inference-witness-pack-v1") &&
            identity_member(env, result, "sourceDirectory", &witnesses->source) &&
            ka_count_member(env, result, "entryCount", witnesses->count) &&
            ka_count_member(env, result, "totalWitnessBytes", witnesses->total) &&
            identity_member(env, pack, "file", &witnesses->pack) && ka_count_member(env, pack, "byteCount", witnesses->pack_size) &&
            ka_string_member(env, pack, "sha256", witnesses->pack_digest) && napi_object_freeze(env, pack) == napi_ok &&
            napi_set_named_property(env, result, "pack", pack) == napi_ok;
    }
    if (valid) valid = napi_object_freeze(env, result) == napi_ok;
    pthread_mutex_unlock(&kernel_archive_mutex);
    return valid ? result : ka_error(env, held, "runtime namespace identity lacks a complete verified original pack");
}
