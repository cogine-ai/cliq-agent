/* Original held descriptors and one durable bookmark belong to one genuine
 * source staging. No payload read, numerical FD export or launch permission. */
#include "../linux/source-input-bridge.h"
#include "../linux/worker-sha256.h"
#include "../linux/source-git-protocol.h"
#ifdef __linux__
#include "../linux/source-git-history.h"
#include <sys/mman.h>
#endif

struct source_git_input {
    struct cliq_source_input bridge;
    source_root *root;
    source_staging *staging;
    napi_ref root_ref, staging_ref;
    bool retained, registered_absent;
    source_git_input *next;
};
static int source_input_close(source_git_input *input) {
    if (atomic_load(&input->bridge.execution_claimed) && !atomic_load(&input->bridge.execution_joined)) return EBUSY;
    atomic_store(&input->bridge.closed, true);
    int *slots[] = { &input->bridge.root_fd, &input->bridge.git_fd, &input->bridge.birth_fd };
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
        int fd = *slots[i]; *slots[i] = -1;
        if (fd >= 0 && close(fd) < 0) input->staging->lock->source_retirement_error = errno;
    }
    return input->staging->lock->source_retirement_error;
}
static int close_source_git_inputs(source_staging *staging) {
    int failed = 0;
    for (source_git_input *input = staging->git_inputs; input; input = input->next)
        if (source_input_close(input)) failed = 1;
    return failed;
}
static int source_bridge_retire(struct cliq_source_input *bridge) {
    return source_input_close((source_git_input *)bridge);
}
static int source_input_origin_current(source_git_input *input) {
    const struct cliq_source_birth *header = &input->bridge.binding;
    return cliq_source_directory_matches(&header->state_root, &input->staging->lock->root) &&
        cliq_source_directory_matches(&header->runtime, &input->staging->lock->runtime) &&
        cliq_source_directory_matches(&header->source_parent, &input->staging->parent);
}
#ifdef __linux__
static int source_input_original_supervisor_dead(source_git_input *input) {
    const struct cliq_source_birth *header = &input->bridge.binding;
    if (header->supervisor_pid <= 0 || header->supervisor_pid > INT32_MAX || header->supervisor_pid == getpid()) return 0;
    char token[128];
    int status = observe_process_with_retirement((pid_t)header->supervisor_pid, token,
        &input->staging->lock->process_observation_retirement_error);
    return !input->staging->lock->process_observation_retirement_error &&
        (status == 0 || (status == 1 && strcmp(token, header->supervisor_start_token)));
}
#endif
static bool source_input_current(struct cliq_source_input *bridge) {
    source_git_input *input = (source_git_input *)bridge;
    struct stat root, git, birth, named;
    struct cliq_source_birth recorded;
    size_t offset = 0;
    if (bridge->birth_fd < 0) return false;
    while (offset < sizeof(recorded)) {
        ssize_t bytes = pread(bridge->birth_fd, (unsigned char *)&recorded + offset, sizeof(recorded) - offset, (off_t)offset);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        offset += (size_t)bytes;
    }
    return memcmp(&recorded, &bridge->binding, sizeof(recorded)) == 0 &&
        bridge->abi_version == CLIQ_SOURCE_INPUT_ABI && !atomic_load(&bridge->closed) &&
        staging_held(input->staging) && bridge->birth_fd >= 0 &&
        (input->retained ? bridge->root_fd == -1 && bridge->git_fd == -1 && input->root == NULL :
          source_held(input->root) && bridge->root_fd >= 0 && bridge->git_fd >= 0 &&
          fstat(bridge->root_fd, &root) == 0 && same_inode(&root, &bridge->root_identity) && S_ISDIR(root.st_mode) &&
          fstat(bridge->git_fd, &git) == 0 && same_inode(&git, &bridge->git_identity) && S_ISDIR(git.st_mode) &&
          fstatat(bridge->root_fd, ".git", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&git, &named)) &&
        fstat(bridge->birth_fd, &birth) == 0 && S_ISREG(birth.st_mode) && birth.st_uid == geteuid() && same_inode(&birth, &bridge->birth_identity) &&
        (input->registered_absent ?
#ifdef __linux__
          input->staging->absent && birth.st_nlink == 0 && (birth.st_mode & 07777) == 0400 &&
          fcntl(bridge->birth_fd, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
          source_input_origin_current(input) && source_input_original_supervisor_dead(input)
#else
          0
#endif
          : birth.st_nlink == 1 && (birth.st_mode & 07777) == 0600 &&
            bridge->binding.birth_device == (uint64_t)birth.st_dev && bridge->binding.birth_inode == (uint64_t)birth.st_ino &&
            fstatat(input->staging->fd, "native-source-birth", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&birth, &named));
}
static source_git_input *source_input_unwrap(napi_env env, napi_callback_info info) {
    napi_value self; bool tagged = false, retained = false, absent = false; source_git_input *input = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_SOURCE_INPUT_TAG, &tagged) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_RETAINED_SOURCE_INPUT_TAG, &retained) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_ABSENT_SOURCE_INPUT_TAG, &absent) != napi_ok || (!tagged && !retained && !absent) ||
        napi_unwrap(env, self, (void **)&input) != napi_ok || !input) {
        native_error(env, "invalid opaque source Git input"); return NULL;
    }
    return input;
}
static napi_value source_input_assert(napi_env env, napi_callback_info info) {
    source_git_input *input = source_input_unwrap(env, info); napi_value result;
    if (!input) return NULL;
    if (!source_input_current(&input->bridge)) return native_error(env, "source Git input identity changed or closed");
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value source_input_close_js(napi_env env, napi_callback_info info) {
    source_git_input *input = source_input_unwrap(env, info); napi_value result;
    if (!input) return NULL;
    if (source_input_close(input)) return staging_retirement_failure(env);
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void source_input_finalize(napi_env env, void *data, void *hint) {
    (void)hint; source_git_input *input = data;
    /* A native execution reference normally prevents this branch. Never let
     * GC turn missing execution join into a successful owner release. */
    if (source_input_close(input)) return;
    source_git_input **link = &input->staging->git_inputs;
    while (*link && *link != input) link = &(*link)->next;
    if (*link) *link = input->next;
    napi_ref root = input->root_ref, staging = input->staging_ref;
    free(input);
    if (root) napi_delete_reference(env, root);
    if (staging) napi_delete_reference(env, staging);
}
static int source_input_text(napi_env env, napi_value value, char *target, size_t capacity, size_t required, int hex) {
    size_t length;
    if (napi_get_value_string_utf8(env, value, target, capacity, &length) != napi_ok || length != required || strlen(target) != length) return 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)target[i];
        if (hex ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) :
            !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}
static int source_input_matches_staging(source_git_input *input) {
    char canonical[128];
    int count = snprintf(canonical, sizeof(canonical), "[\"%s\",\"%s\"]", input->bridge.binding.inspection_id, input->bridge.binding.staging_nonce);
    if (count <= 0 || (size_t)count >= sizeof(canonical)) return 0;
    unsigned char digest[32]; struct sha256_context hash;
    sha256_init(&hash); sha256_update(&hash, (const unsigned char *)canonical, (size_t)count); sha256_final(&hash, digest);
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char encoded[44]; size_t at = 0;
    for (size_t i = 0; i < 32; i += 3) {
        uint32_t value = (uint32_t)digest[i] << 16;
        if (i + 1 < 32) value |= (uint32_t)digest[i + 1] << 8;
        if (i + 2 < 32) value |= digest[i + 2];
        encoded[at++] = alphabet[(value >> 18) & 63]; encoded[at++] = alphabet[(value >> 12) & 63];
        if (i + 1 < 32) encoded[at++] = alphabet[(value >> 6) & 63];
        if (i + 2 < 32) encoded[at++] = alphabet[value & 63];
    }
    encoded[at] = '\0'; return at == 43 && strcmp(encoded, input->staging->name) == 0;
}
static napi_value source_input_publish(napi_env env, source_git_input *input, napi_value staging, napi_value root) {
    struct cliq_source_input *bridge = &input->bridge; napi_value result, identity;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, source_input_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, source_input_close_js, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &identity) != napi_ok ||
        !string_property(env, identity, "inspectionId", bridge->binding.inspection_id) ||
        !string_property(env, identity, "stagingNonceDigest", bridge->binding.staging_nonce) ||
        !string_property(env, identity, "targetRef", bridge->binding.target_ref) ||
        !string_property(env, identity, "inputIntentRef", bridge->binding.input_intent_ref) ||
        !identity_member(env, identity, input->registered_absent ? "snapshotIdentity" : "birthIdentity", &bridge->birth_identity) ||
        napi_object_freeze(env, identity) != napi_ok || napi_set_named_property(env, result, "identity", identity) != napi_ok ||
        napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
        napi_type_tag_object(env, result, input->registered_absent ? &CLIQ_ABSENT_SOURCE_INPUT_TAG :
            input->retained ? &CLIQ_RETAINED_SOURCE_INPUT_TAG : &CLIQ_SOURCE_INPUT_TAG) != napi_ok ||
        (root && napi_create_reference(env, root, 1, &input->root_ref) != napi_ok) ||
        napi_create_reference(env, staging, 1, &input->staging_ref) != napi_ok ||
        napi_wrap(env, result, input, source_input_finalize, NULL, NULL) != napi_ok) return NULL;
    input->next = input->staging->git_inputs; input->staging->git_inputs = input;
    napi_object_freeze(env, result); return result;
}
static napi_value source_staging_borrow_git_input(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); size_t argc = 5;
    napi_value args[5], self; bool tagged = false; source_root *root = NULL;
    if (!staging) return NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 5 ||
        napi_check_object_type_tag(env, args[0], &source_root_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, args[0], (void **)&root) != napi_ok || !root || !source_held(root) || root->git_fd < 0 ||
        !staging_held(staging) || staging->absent || staging->git_inputs) return native_error(env, "source Git input requires its original unborrowed descriptors");
    source_git_input *input = calloc(1, sizeof(*input));
    if (!input) return native_error(env, "source Git input allocation failed");
    input->root = root; input->staging = staging;
    struct cliq_source_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_SOURCE_INPUT_ABI; bridge->root_fd = bridge->git_fd = bridge->birth_fd = -1;
    bridge->assert_current = source_input_current;
    bridge->retire = source_bridge_retire;
    atomic_init(&bridge->closed, false); atomic_init(&bridge->execution_claimed, false); atomic_init(&bridge->execution_joined, false);
    const char *error = "source Git input binding differs from its original staging";
    if (!source_input_text(env, args[1], bridge->binding.inspection_id, sizeof(bridge->binding.inspection_id), 43, 0) ||
        !source_input_text(env, args[2], bridge->binding.staging_nonce, sizeof(bridge->binding.staging_nonce), 64, 1) ||
        !source_input_text(env, args[3], bridge->binding.target_ref, sizeof(bridge->binding.target_ref), 64, 1) ||
        !source_input_text(env, args[4], bridge->binding.input_intent_ref, sizeof(bridge->binding.input_intent_ref), 64, 1) ||
        !source_input_matches_staging(input)) goto failed;
    bridge->root_fd = fcntl(root->fds[root->count - 1], F_DUPFD_CLOEXEC, 4);
    bridge->git_fd = fcntl(root->git_fd, F_DUPFD_CLOEXEC, 4);
    error = "source Git input descriptors could not be retained";
    if (bridge->root_fd < 0 || bridge->git_fd < 0 || fstat(bridge->root_fd, &bridge->root_identity) < 0 || fstat(bridge->git_fd, &bridge->git_identity) < 0) goto failed;
    bridge->birth_fd = openat(staging->fd, "native-source-birth", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    error = "source native birth must be created once and durably retained";
    if (bridge->birth_fd < 0 || fstat(bridge->birth_fd, &bridge->birth_identity) < 0 || !S_ISREG(bridge->birth_identity.st_mode) ||
        bridge->birth_identity.st_nlink != 1 || bridge->birth_identity.st_uid != geteuid()) goto failed;
    bridge->binding.magic = CLIQ_SOURCE_BIRTH_MAGIC; bridge->binding.version = CLIQ_SOURCE_BIRTH_VERSION;
    bridge->binding.staging_device = staging->identity.st_dev; bridge->binding.staging_inode = staging->identity.st_ino;
    bridge->binding.staging_gid = staging->identity.st_gid;
    bridge->binding.workspace_device = bridge->root_identity.st_dev; bridge->binding.workspace_inode = bridge->root_identity.st_ino;
    bridge->binding.git_device = bridge->git_identity.st_dev; bridge->binding.git_inode = bridge->git_identity.st_ino;
    bridge->binding.owner_uid = geteuid();
    bridge->binding.birth_device = bridge->birth_identity.st_dev; bridge->binding.birth_inode = bridge->birth_identity.st_ino;
    struct cliq_source_directory_identity *origins[] = { &bridge->binding.state_root, &bridge->binding.runtime, &bridge->binding.source_parent };
    const struct stat *directories[] = { &staging->lock->root, &staging->lock->runtime, &staging->parent };
    for (size_t i = 0; i < 3; i++) {
        origins[i]->device = directories[i]->st_dev; origins[i]->inode = directories[i]->st_ino;
        origins[i]->uid = directories[i]->st_uid; origins[i]->gid = directories[i]->st_gid; origins[i]->mode = directories[i]->st_mode;
    }
    bridge->binding.supervisor_pid = getpid();
    if (observe_process_with_retirement(getpid(), bridge->binding.supervisor_start_token,
        &staging->lock->process_observation_retirement_error) != 1 || staging->lock->process_observation_retirement_error) goto failed;
#ifdef __linux__
    if (!cliq_source_birth_origin_valid(&bridge->binding)) goto failed;
#endif
    struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)&bridge->binding, offsetof(struct cliq_source_birth, digest));
    sha256_final(&hash, bridge->binding.digest);
    size_t used = 0;
    while (used < sizeof(bridge->binding)) {
        ssize_t written = write(bridge->birth_fd, (const unsigned char *)&bridge->binding + used, sizeof(bridge->binding) - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) goto failed;
        used += (size_t)written;
    }
    if (!sync_directory(bridge->birth_fd) || !sync_directory(staging->fd) || !source_input_current(bridge)) goto failed;
    napi_value result = source_input_publish(env, input, self, args[0]);
    if (result) return result;
failed:
    (void)source_input_close(input);
    if (input->root_ref) napi_delete_reference(env, input->root_ref);
    if (input->staging_ref) napi_delete_reference(env, input->staging_ref);
    free(input);
    return staging->lock->source_retirement_error ? staging_retirement_failure(env) : native_error(env, error);
}

/* Cleanup-only reopen. No WorkspaceRoot, source directory or execution image
 * is accepted, opened or inferred from the recorded descriptor identities. */
static napi_value source_staging_open_git_input(napi_env env, napi_callback_info info) {
    source_staging *staging = unwrap_source_staging(env, info); size_t argc = 4;
    napi_value args[4], self;
    if (!staging) return NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 4 ||
        !staging_held(staging) || staging->absent || staging->git_inputs) return native_error(env, "retained source input requires original staging");
    source_git_input *input = calloc(1, sizeof(*input));
    if (!input) return native_error(env, "retained source input allocation failed");
    input->staging = staging; input->retained = true;
    struct cliq_source_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_SOURCE_INPUT_ABI; bridge->root_fd = bridge->git_fd = bridge->birth_fd = -1;
    bridge->assert_current = source_input_current; bridge->retire = source_bridge_retire;
    atomic_init(&bridge->closed, false); atomic_init(&bridge->execution_claimed, false); atomic_init(&bridge->execution_joined, false);
    struct cliq_source_birth expected = {0};
    const char *error = "retained source input differs from its original immutable birth";
    if (!source_input_text(env, args[0], expected.inspection_id, sizeof(expected.inspection_id), 43, 0) ||
        !source_input_text(env, args[1], expected.staging_nonce, sizeof(expected.staging_nonce), 64, 1) ||
        !source_input_text(env, args[2], expected.target_ref, sizeof(expected.target_ref), 64, 1) ||
        !source_input_text(env, args[3], expected.input_intent_ref, sizeof(expected.input_intent_ref), 64, 1)) goto failed;
    bridge->binding = expected;
    if (!source_input_matches_staging(input)) goto failed;
    bridge->birth_fd = openat(staging->fd, "native-source-birth", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (bridge->birth_fd < 0 || fstat(bridge->birth_fd, &bridge->birth_identity) < 0 ||
        bridge->birth_identity.st_size < (off_t)sizeof(bridge->binding) ||
        bridge->birth_identity.st_size > (off_t)(sizeof(bridge->binding) + sizeof(struct cliq_source_controller_birth) + 12 * sizeof(struct cliq_source_birth_record)) ||
        pread(bridge->birth_fd, &bridge->binding, sizeof(bridge->binding), 0) != (ssize_t)sizeof(bridge->binding)) goto failed;
    struct cliq_source_birth *header = &bridge->binding;
    unsigned char digest[32]; struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)header, offsetof(struct cliq_source_birth, digest)); sha256_final(&hash, digest);
    if (header->magic != CLIQ_SOURCE_BIRTH_MAGIC || header->version != CLIQ_SOURCE_BIRTH_VERSION || header->owner_uid != (uint64_t)geteuid() ||
        header->staging_device != (uint64_t)staging->identity.st_dev || header->staging_inode != (uint64_t)staging->identity.st_ino ||
        memcmp(expected.inspection_id, header->inspection_id, sizeof(expected.inspection_id)) != 0 ||
        memcmp(expected.staging_nonce, header->staging_nonce, sizeof(expected.staging_nonce)) != 0 ||
        memcmp(expected.target_ref, header->target_ref, sizeof(expected.target_ref)) != 0 ||
        memcmp(expected.input_intent_ref, header->input_intent_ref, sizeof(expected.input_intent_ref)) != 0 ||
        memcmp(digest, header->digest, sizeof(digest)) != 0 || !source_input_origin_current(input) || !source_input_current(bridge)) goto failed;
    napi_value result = source_input_publish(env, input, self, NULL);
    if (result) return result;
failed:
    (void)source_input_close(input);
    if (input->staging_ref) napi_delete_reference(env, input->staging_ref);
    free(input);
    return staging->lock->source_retirement_error ? staging_retirement_failure(env) : native_error(env, error);
}

/* Already-registered missing root only. No host source path is opened, no
 * birth is recreated, and this distinct tag can never reserve execution. */
static napi_value source_staging_open_absent_git_input(napi_env env, napi_callback_info info) {
#ifndef __linux__
    (void)info; return native_error(env, "registered absent source cleanup requires Linux");
#else
    source_staging *staging = unwrap_source_staging(env, info); size_t argc = 5, length = 0;
    napi_value args[5], self; void *bytes = NULL; bool buffer = false;
    if (!staging) return NULL;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 5 ||
        !staging_held(staging) || !staging->absent || staging->git_inputs ||
        napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, args[0], &bytes, &length) != napi_ok || length < sizeof(struct cliq_source_birth) ||
        length > CLIQ_SOURCE_HISTORY_MAX_BYTES) return native_error(env, "registered absent source input requires complete original bytes");
    source_git_input *input = calloc(1, sizeof(*input));
    if (!input) return native_error(env, "registered absent source input allocation failed");
    input->staging = staging; input->retained = input->registered_absent = true;
    struct cliq_source_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_SOURCE_INPUT_ABI; bridge->root_fd = bridge->git_fd = bridge->birth_fd = -1;
    bridge->assert_current = source_input_current; bridge->retire = source_bridge_retire;
    atomic_init(&bridge->closed, false); atomic_init(&bridge->execution_claimed, false); atomic_init(&bridge->execution_joined, false);
    struct cliq_source_birth expected; memset(&expected, 0, sizeof(expected));
    struct cliq_source_history history;
    const char *error = "registered absent source lifecycle differs from the original reservation";
    if (!source_input_text(env, args[1], expected.inspection_id, sizeof(expected.inspection_id), 43, 0) ||
        !source_input_text(env, args[2], expected.staging_nonce, sizeof(expected.staging_nonce), 64, 1) ||
        !source_input_text(env, args[3], expected.target_ref, sizeof(expected.target_ref), 64, 1) ||
        !source_input_text(env, args[4], expected.input_intent_ref, sizeof(expected.input_intent_ref), 64, 1)) goto failed;
    memcpy(&bridge->binding, bytes, sizeof(bridge->binding));
    const struct cliq_source_birth *header = &bridge->binding;
    if (memcmp(header->inspection_id, expected.inspection_id, sizeof(expected.inspection_id)) ||
        memcmp(header->staging_nonce, expected.staging_nonce, sizeof(expected.staging_nonce)) ||
        memcmp(header->target_ref, expected.target_ref, sizeof(expected.target_ref)) ||
        memcmp(header->input_intent_ref, expected.input_intent_ref, sizeof(expected.input_intent_ref)) ||
        header->staging_device != (uint64_t)staging->identity.st_dev || header->staging_inode != (uint64_t)staging->identity.st_ino ||
        !source_input_matches_staging(input) || !source_input_origin_current(input) || !source_input_original_supervisor_dead(input) ||
        !cliq_source_history_decode(bytes, length, header, &history) || !cliq_source_recovery_prefix_complete(&history)) goto failed;
    bridge->birth_fd = memfd_create("cliq-source-registered-lifecycle", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (bridge->birth_fd < 0) goto failed;
    size_t used = 0;
    while (used < length) {
        ssize_t written = write(bridge->birth_fd, (const unsigned char *)bytes + used, length - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) goto failed;
        used += (size_t)written;
    }
    if (fchmod(bridge->birth_fd, 0400) || fcntl(bridge->birth_fd, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) || fstat(bridge->birth_fd, &bridge->birth_identity) ||
        !source_input_current(bridge)) goto failed;
    napi_value result = source_input_publish(env, input, self, NULL);
    if (result) return result;
failed:
    (void)source_input_close(input);
    if (input->staging_ref) napi_delete_reference(env, input->staging_ref);
    free(input);
    return staging->lock->source_retirement_error ? staging_retirement_failure(env) : native_error(env, error);
#endif
}
