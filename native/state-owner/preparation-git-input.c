/* One original same-lock generation + WorkerReservation friend. It carries
 * identities only. The CAS-only producer never receives a host tree mount. */
#include "../linux/preparation-input-bridge.h"
#include "../linux/worker-sha256.h"

struct preparation_git_input {
    struct cliq_preparation_input bridge;
    generation_tree *tree;
    worker_reservation *reservation;
    napi_ref tree_ref, reservation_ref;
    int retirement_failed;
    preparation_git_input *tree_next, *reservation_next;
};
static int preparation_input_close(preparation_git_input *input) {
    if (atomic_load(&input->bridge.execution_claimed) && !atomic_load(&input->bridge.execution_joined)) return EBUSY;
    atomic_store(&input->bridge.closed, true);
    retire_process_fd(&input->bridge.generation_fd, &input->retirement_failed);
    retire_process_fd(&input->bridge.reservation_fd, &input->retirement_failed);
    if (input->retirement_failed) {
        if (input->tree) input->tree->retirement_failed = input->tree->lock->generation_retirement_error = 1;
        input->reservation->lock->worker_reservation_error = EIO;
    }
    return input->retirement_failed ? EIO : 0;
}
static int close_tree_preparation_inputs(generation_tree *tree) {
    int failed = 0;
    for (preparation_git_input *input = tree->preparation_inputs; input; input = input->tree_next)
        if (preparation_input_close(input)) failed = EBUSY;
    return failed;
}
static int close_reservation_preparation_inputs(worker_reservation *reservation) {
    int failed = 0;
    for (preparation_git_input *input = reservation->preparation_inputs; input; input = input->reservation_next)
        if (preparation_input_close(input)) failed = EBUSY;
    return failed;
}
static int tree_preparation_inputs_retired(generation_tree *tree) {
    for (preparation_git_input *input = tree->preparation_inputs; input; input = input->tree_next)
        if (!atomic_load(&input->bridge.closed) || input->retirement_failed || input->bridge.generation_fd >= 0 || input->bridge.reservation_fd >= 0 ||
            (atomic_load(&input->bridge.execution_claimed) && !atomic_load(&input->bridge.execution_joined))) return 0;
    return 1;
}
static int preparation_bridge_retire(struct cliq_preparation_input *bridge) {
    return preparation_input_close((preparation_git_input *)bridge);
}
static bool preparation_input_current(struct cliq_preparation_input *bridge) {
    preparation_git_input *input = (preparation_git_input *)bridge; struct stat generation, reservation;
    if (bridge->abi_version != CLIQ_PREPARATION_INPUT_ABI || atomic_load(&bridge->closed) || input->retirement_failed ||
        !worker_reservation_held(input->reservation) || bridge->reservation_fd < 0 ||
        fstat(bridge->reservation_fd, &reservation) != 0 || !private_lock_file(&reservation) ||
        !same_inode(&reservation, &bridge->reservation_identity) || !same_inode(&reservation, &input->reservation->identity)) return false;
    if (bridge->cleanup_only) return !input->tree && bridge->generation_fd == -1;
    return input->tree && input->tree->lock == input->reservation->lock && tree_held(input->tree) &&
        bridge->generation_fd >= 0 &&
        fstat(bridge->generation_fd, &generation) == 0 && private_directory(&generation) && same_inode(&generation, &bridge->generation_identity) &&
        same_inode(&generation, &input->tree->identity) && fstat(bridge->reservation_fd, &reservation) == 0 && private_lock_file(&reservation) &&
        same_inode(&reservation, &bridge->reservation_identity) && same_inode(&reservation, &input->reservation->identity) &&
        strcmp(bridge->run_id, input->tree->run) == 0 && strcmp(bridge->generation_id, input->tree->generation) == 0;
}
static preparation_git_input *preparation_input_unwrap(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false; preparation_git_input *input = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        ((napi_check_object_type_tag(env, self, &CLIQ_PREPARATION_INPUT_TAG, &tagged) != napi_ok || !tagged) &&
         (napi_check_object_type_tag(env, self, &CLIQ_RETAINED_PREPARATION_INPUT_TAG, &tagged) != napi_ok || !tagged)) ||
        napi_unwrap(env, self, (void **)&input) != napi_ok || !input) {
        native_error(env, "invalid opaque preparing Git input"); return NULL;
    }
    return input;
}
static napi_value preparation_input_assert(napi_env env, napi_callback_info info) {
    preparation_git_input *input = preparation_input_unwrap(env, info); napi_value value;
    if (!input) return NULL;
    if (!preparation_input_current(&input->bridge)) return native_error(env, "original preparing Git input changed or closed");
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static napi_value preparation_input_close_js(napi_env env, napi_callback_info info) {
    preparation_git_input *input = preparation_input_unwrap(env, info); napi_value value;
    if (!input) return NULL;
    if (preparation_input_close(input)) return reservation_retirement_failure(env);
    return napi_get_undefined(env, &value) == napi_ok ? value : NULL;
}
static void preparation_input_finalize(napi_env env, void *data, void *hint) {
    (void)hint; preparation_git_input *input = data;
    if (preparation_input_close(input)) return;
    generation_tree *tree = input->tree; worker_reservation *reservation = input->reservation;
    preparation_git_input **link;
    if (tree) { link = &tree->preparation_inputs;
        while (*link && *link != input) link = &(*link)->tree_next;
        if (*link) *link = input->tree_next; }
    link = &reservation->preparation_inputs;
    while (*link && *link != input) link = &(*link)->reservation_next;
    if (*link) *link = input->reservation_next;
    napi_ref tree_ref = input->tree_ref, reservation_ref = input->reservation_ref;
    free(input); if (tree) free_tree_if_done(env, tree); free_worker_reservation(env, reservation);
    if (tree_ref) napi_delete_reference(env, tree_ref);
    if (reservation_ref) napi_delete_reference(env, reservation_ref);
}
static bool preparation_input_text(napi_env env, napi_value value, char *target, size_t capacity, size_t width, bool hex) {
    size_t length;
    if (napi_get_value_string_utf8(env, value, target, capacity, &length) != napi_ok || length != width || strlen(target) != length) return false;
    for (size_t i = 0; i < width; i++) if (hex ? !((target[i] >= '0' && target[i] <= '9') || (target[i] >= 'a' && target[i] <= 'f')) :
        !((target[i] >= 'A' && target[i] <= 'Z') || (target[i] >= 'a' && target[i] <= 'z') || (target[i] >= '0' && target[i] <= '9') || target[i] == '-' || target[i] == '_')) return false;
    return true;
}
static bool preparation_input_reservation_matches(const preparation_git_input *input) {
    char canonical[256]; int length = snprintf(canonical, sizeof(canonical), "[\"cliq-worker-reservation-v1\",\"%s\",\"%s\"]", input->bridge.launch_id, input->bridge.spawn_nonce);
    if (length <= 0 || (size_t)length >= sizeof(canonical)) return false;
    unsigned char digest[32]; struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)canonical, (size_t)length); sha256_final(&hash, digest);
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; char encoded[44]; size_t at = 0;
    for (size_t i = 0; i < 32; i += 3) {
        uint32_t value = (uint32_t)digest[i] << 16;
        if (i + 1 < 32) value |= (uint32_t)digest[i + 1] << 8;
        if (i + 2 < 32) value |= digest[i + 2];
        encoded[at++] = alphabet[(value >> 18) & 63]; encoded[at++] = alphabet[(value >> 12) & 63];
        if (i + 1 < 32) encoded[at++] = alphabet[(value >> 6) & 63];
        if (i + 2 < 32) encoded[at++] = alphabet[value & 63];
    }
    encoded[at] = '\0'; return at == 43 && strcmp(encoded, input->reservation->name) == 0;
}
static napi_value worker_reservation_preparation_input(napi_env env, napi_callback_info info) {
    worker_reservation *reservation = unwrap_worker_reservation(env, info); size_t argc = 7; napi_value args[7], self, result, identity;
    generation_tree *tree = NULL; bool tagged = false; struct stat file;
    if (!reservation) return NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 7 ||
        napi_check_object_type_tag(env, args[0], &tree_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&tree) != napi_ok || !tree || tree->retained || tree->lock != reservation->lock ||
        !tree_held(tree) || !generation_children_retired(tree) || !worker_reservation_held(reservation) || reservation->preparation_inputs ||
        fstat(reservation->fd, &file) != 0 || file.st_size != 0) return native_error(env, "preparing Git input requires its original same-lock unbound generation and reservation");
    for (generation_borrow *borrow = tree->borrows; borrow; borrow = borrow->next)
        if (borrow->fd >= 0) return native_error(env, "preparing Git input requires joined original generation readers");
    preparation_git_input *input = calloc(1, sizeof(*input));
    if (!input) return native_error(env, "preparing Git input allocation unavailable");
    input->tree = tree; input->reservation = reservation; struct cliq_preparation_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_PREPARATION_INPUT_ABI; bridge->generation_fd = bridge->reservation_fd = -1;
    bridge->assert_current = preparation_input_current; bridge->retire = preparation_bridge_retire;
    atomic_init(&bridge->closed, false); atomic_init(&bridge->execution_claimed, false); atomic_init(&bridge->execution_joined, false);
    strcpy(bridge->run_id, tree->run); strcpy(bridge->generation_id, tree->generation);
    bridge->supervisor_pid = (uint64_t)getpid();
    const char *error = "preparing Git input differs from the original worker reservation";
    if (!preparation_input_text(env, args[1], bridge->launch_id, sizeof(bridge->launch_id), 43, false) ||
        !preparation_input_text(env, args[2], bridge->spawn_nonce, sizeof(bridge->spawn_nonce), 64, true) ||
        !preparation_input_text(env, args[3], bridge->activation_nonce, sizeof(bridge->activation_nonce), 64, true) ||
        !preparation_input_text(env, args[4], bridge->creation_nonce, sizeof(bridge->creation_nonce), 64, true) ||
        !preparation_input_text(env, args[5], bridge->generation_ref, sizeof(bridge->generation_ref), 64, true) ||
        !preparation_input_text(env, args[6], bridge->input_intent_ref, sizeof(bridge->input_intent_ref), 64, true) || !preparation_input_reservation_matches(input) ||
        observe_process_with_retirement(getpid(), bridge->supervisor_token, &input->retirement_failed) != 1) goto failed;
    bridge->generation_fd = fcntl(tree->fd, F_DUPFD_CLOEXEC, 4); bridge->reservation_fd = fcntl(reservation->fd, F_DUPFD_CLOEXEC, 4);
    if (bridge->generation_fd < 0 || bridge->reservation_fd < 0 || fstat(bridge->generation_fd, &bridge->generation_identity) != 0 ||
        fstat(bridge->reservation_fd, &bridge->reservation_identity) != 0 || !preparation_input_current(bridge)) goto failed;
    const napi_property_descriptor methods[] = {
        { "assertHeld", NULL, preparation_input_assert, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, preparation_input_close_js, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &identity) != napi_ok ||
        !string_property(env, identity, "runId", bridge->run_id) || !string_property(env, identity, "generationId", bridge->generation_id) ||
        !string_property(env, identity, "launchId", bridge->launch_id) || !string_property(env, identity, "spawnNonceDigest", bridge->spawn_nonce) ||
        !string_property(env, identity, "activationNonceDigest", bridge->activation_nonce) || !string_property(env, identity, "generationCreationNonceDigest", bridge->creation_nonce) ||
        !string_property(env, identity, "generationRef", bridge->generation_ref) || !string_property(env, identity, "inputIntentRef", bridge->input_intent_ref) ||
        !number_property(env, identity, "originalSupervisorPid", (double)bridge->supervisor_pid) ||
        !string_property(env, identity, "originalSupervisorStartToken", bridge->supervisor_token) ||
        !identity_member(env, identity, "generation", &bridge->generation_identity) || !identity_member(env, identity, "reservation", &bridge->reservation_identity) ||
        napi_object_freeze(env, identity) != napi_ok || napi_set_named_property(env, result, "identity", identity) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &CLIQ_PREPARATION_INPUT_TAG) != napi_ok ||
        napi_create_reference(env, args[0], 1, &input->tree_ref) != napi_ok || napi_create_reference(env, self, 1, &input->reservation_ref) != napi_ok ||
        napi_wrap(env, result, input, preparation_input_finalize, NULL, NULL) != napi_ok) goto failed;
    input->tree_next = tree->preparation_inputs; tree->preparation_inputs = input;
    input->reservation_next = reservation->preparation_inputs; reservation->preparation_inputs = input;
    napi_object_freeze(env, result); return result;
failed:
    (void)preparation_input_close(input);
    if (input->tree_ref) napi_delete_reference(env, input->tree_ref);
    if (input->reservation_ref) napi_delete_reference(env, input->reservation_ref);
    free(input);
    return reservation->lock->worker_reservation_error ? reservation_retirement_failure(env) : native_error(env, error);
}
static bool preparation_cleanup_decimal(napi_env env, napi_value value, uint64_t *result) {
    char text[32]; size_t length; char *end = NULL;
    if (napi_get_value_string_utf8(env, value, text, sizeof(text), &length) != napi_ok || length < 1 || length > 20 ||
        strlen(text) != length || text[0] == '0') return false;
    for (size_t i = 0; i < length; i++) if (text[i] < '0' || text[i] > '9') return false;
    errno = 0; unsigned long long number = strtoull(text, &end, 10);
    if (errno || !end || *end || !number) return false;
    *result = (uint64_t)number; return true;
}
/* Successor-only resource input. It contains no tree, source bytes, writer,
 * execution channel or permission to append to the original birth. */
static napi_value worker_reservation_retained_preparation_input(napi_env env, napi_callback_info info) {
    worker_reservation *reservation = unwrap_worker_reservation(env, info); size_t argc = 12; napi_value args[12], self, result, identity;
    if (!reservation || napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 12 ||
        !worker_reservation_held(reservation) || reservation->preparation_inputs) return native_error(env, "retained preparing cleanup requires the original held reservation");
    preparation_git_input *input = calloc(1, sizeof(*input)); if (!input) return native_error(env, "retained preparing input allocation unavailable");
    input->reservation = reservation; struct cliq_preparation_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_PREPARATION_INPUT_ABI; bridge->cleanup_only = true; bridge->generation_fd = bridge->reservation_fd = -1;
    bridge->assert_current = preparation_input_current; bridge->retire = preparation_bridge_retire;
    atomic_init(&bridge->closed, false); atomic_init(&bridge->execution_claimed, false); atomic_init(&bridge->execution_joined, false);
    size_t run_bytes, token_bytes; double supervisor; uint64_t device, inode;
    bool valid = napi_get_value_string_utf8(env, args[0], bridge->run_id, sizeof(bridge->run_id), &run_bytes) == napi_ok && run_bytes >= 1 &&
        run_bytes <= 128 && strlen(bridge->run_id) == run_bytes;
    for (size_t i = 0; valid && i < run_bytes; i++) { char value = bridge->run_id[i];
        valid = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-' || value == '_'; }
    valid = valid && preparation_input_text(env, args[1], bridge->generation_id, sizeof(bridge->generation_id), 43, false) &&
        preparation_input_text(env, args[2], bridge->launch_id, sizeof(bridge->launch_id), 43, false) &&
        preparation_input_text(env, args[3], bridge->spawn_nonce, sizeof(bridge->spawn_nonce), 64, true) &&
        preparation_input_text(env, args[4], bridge->activation_nonce, sizeof(bridge->activation_nonce), 64, true) &&
        preparation_input_text(env, args[5], bridge->creation_nonce, sizeof(bridge->creation_nonce), 64, true) &&
        preparation_input_text(env, args[6], bridge->generation_ref, sizeof(bridge->generation_ref), 64, true) &&
        preparation_input_text(env, args[7], bridge->input_intent_ref, sizeof(bridge->input_intent_ref), 64, true) &&
        preparation_cleanup_decimal(env, args[8], &device) && preparation_cleanup_decimal(env, args[9], &inode) &&
        napi_get_value_double(env, args[10], &supervisor) == napi_ok && supervisor >= 1 && supervisor <= INT32_MAX && (double)(uint64_t)supervisor == supervisor &&
        napi_get_value_string_utf8(env, args[11], bridge->supervisor_token, sizeof(bridge->supervisor_token), &token_bytes) == napi_ok &&
        token_bytes >= 1 && token_bytes < sizeof(bridge->supervisor_token) && strlen(bridge->supervisor_token) == token_bytes &&
        preparation_input_reservation_matches(input);
    if (!valid) goto retained_failed;
    bridge->supervisor_pid = (uint64_t)supervisor; bridge->generation_identity.st_dev = (dev_t)device; bridge->generation_identity.st_ino = (ino_t)inode;
    bridge->generation_identity.st_uid = geteuid();
    if ((uint64_t)bridge->generation_identity.st_dev != device || (uint64_t)bridge->generation_identity.st_ino != inode) goto retained_failed;
    char descriptor[64]; int length = snprintf(descriptor, sizeof(descriptor), "/dev/fd/%d", reservation->fd);
#ifdef __linux__
    length = snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", reservation->fd);
#endif
    if (length < 0 || (size_t)length >= sizeof(descriptor)) goto retained_failed;
    bridge->reservation_fd = open(descriptor, O_RDONLY | O_CLOEXEC);
    if (bridge->reservation_fd < 0 || fstat(bridge->reservation_fd, &bridge->reservation_identity) != 0 || !preparation_input_current(bridge)) goto retained_failed;
    const napi_property_descriptor methods[] = {
        { "assertHeld", NULL, preparation_input_assert, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, preparation_input_close_js, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &identity) != napi_ok ||
        !string_property(env, identity, "runId", bridge->run_id) || !string_property(env, identity, "generationId", bridge->generation_id) ||
        !string_property(env, identity, "launchId", bridge->launch_id) || !string_property(env, identity, "spawnNonceDigest", bridge->spawn_nonce) ||
        !string_property(env, identity, "activationNonceDigest", bridge->activation_nonce) || !string_property(env, identity, "generationCreationNonceDigest", bridge->creation_nonce) ||
        !string_property(env, identity, "generationRef", bridge->generation_ref) || !string_property(env, identity, "inputIntentRef", bridge->input_intent_ref) ||
        !number_property(env, identity, "originalSupervisorPid", (double)bridge->supervisor_pid) || !string_property(env, identity, "originalSupervisorStartToken", bridge->supervisor_token) ||
        !identity_member(env, identity, "generation", &bridge->generation_identity) || !identity_member(env, identity, "reservation", &bridge->reservation_identity) ||
        napi_object_freeze(env, identity) != napi_ok || napi_set_named_property(env, result, "identity", identity) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, &CLIQ_RETAINED_PREPARATION_INPUT_TAG) != napi_ok ||
        napi_create_reference(env, self, 1, &input->reservation_ref) != napi_ok || napi_wrap(env, result, input, preparation_input_finalize, NULL, NULL) != napi_ok) goto retained_failed;
    input->reservation_next = reservation->preparation_inputs; reservation->preparation_inputs = input;
    napi_object_freeze(env, result); return result;
retained_failed:
    (void)preparation_input_close(input);
    if (input->reservation_ref) napi_delete_reference(env, input->reservation_ref);
    free(input); return reservation->lock->worker_reservation_error ? reservation_retirement_failure(env) : native_error(env, "retained preparing input differs from its held reservation");
}
