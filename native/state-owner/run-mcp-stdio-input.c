/* Original Run stdio launch's physical bookmark. This is resource custody,
 * not a worker/source/Admin execution capability or a SQLite permission. */
#include "../linux/mcp-stdio-protocol.h"
#include <math.h>
#ifdef __linux__
#include <sys/syscall.h>
struct run_mcp_stdio_input {
    struct cliq_mcp_stdio_run_input bridge;
    state_lock *lock;
    napi_ref lock_ref;
    int parent_fd;
    struct stat parent;
    bool retained;
    struct run_mcp_stdio_input *next;
};
static bool run_stdio_current_process(const struct cliq_mcp_stdio_run_input *bridge) {
    return bridge->creator_pid == getpid()
#ifdef __linux__
        && syscall(SYS_gettid) == getpid()
#endif
        ;
}
static bool run_stdio_input_current(struct cliq_mcp_stdio_run_input *bridge) {
    struct run_mcp_stdio_input *input = (struct run_mcp_stdio_input *)bridge;
    struct stat parent, file, named;
    struct cliq_mcp_stdio_run_birth recorded;
    return run_stdio_current_process(bridge) && bridge->abi_version == CLIQ_MCP_STDIO_RUN_INPUT_ABI && !atomic_load(&bridge->closed) &&
        !input->lock->run_mcp_stdio_retirement_error && lock_is_held(input->lock) && input->parent_fd >= 0 && bridge->birth_fd >= 0 &&
        !fstat(input->parent_fd, &parent) && private_directory(&parent) && same_inode(&parent, &input->parent) &&
        !fstatat(input->lock->runtime_fd, "run-mcp-stdio", &named, AT_SYMLINK_NOFOLLOW) && private_directory(&named) && same_inode(&parent, &named) &&
        !fstat(bridge->birth_fd, &file) && private_lock_file(&file) && same_inode(&file, &bridge->birth_identity) &&
        !fstatat(input->parent_fd, bridge->binding.identity.nonce, &named, AT_SYMLINK_NOFOLLOW) && private_lock_file(&named) && same_inode(&file, &named) &&
        cliq_mcp_admin_read_exact(bridge->birth_fd, &recorded, sizeof(recorded), 0) && !memcmp(&recorded, &bridge->binding, sizeof(recorded)) &&
        admin_mcp_directory_same(&recorded.state_root, &input->lock->root) && admin_mcp_directory_same(&recorded.runtime, &input->lock->runtime) &&
        admin_mcp_directory_same(&recorded.private_parent, &parent) && admin_mcp_directory_same(&recorded.birth, &file);
}
static int run_stdio_input_retire(struct cliq_mcp_stdio_run_input *bridge) {
    struct run_mcp_stdio_input *input = (struct run_mcp_stdio_input *)bridge;
    if (!run_stdio_current_process(bridge) || (atomic_load(&bridge->execution_claimed) && !atomic_load(&bridge->execution_joined)))
        return EBUSY;
    atomic_store(&bridge->closed, true);
    int *slots[] = {&bridge->birth_fd, &input->parent_fd};
    for (size_t i = 0; i < 2; i++) {
        int fd = *slots[i];
        *slots[i] = -1;
        if (fd >= 0 && close(fd))
            input->lock->run_mcp_stdio_retirement_error = errno;
    }
    return input->lock->run_mcp_stdio_retirement_error;
}
static int close_lock_run_mcp_stdio_inputs(state_lock *lock) {
    int failed = 0;
    for (struct run_mcp_stdio_input *input = lock->run_mcp_stdio_inputs; input; input = input->next)
        if (run_stdio_input_retire(&input->bridge))
            failed = 1;
    return failed || lock->run_mcp_stdio_retirement_error;
}
static napi_value run_stdio_retirement_error(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "Run MCP stdio custody did not retire; the original StateOwner remains held");
    return NULL;
}
static struct run_mcp_stdio_input *run_stdio_unwrap(napi_env env, napi_callback_info info) {
    napi_value self;
    bool execution = false, retained = false;
    struct run_mcp_stdio_input *input = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_RUN_INPUT_TAG, &execution) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_RUN_RETAINED_INPUT_TAG, &retained) != napi_ok ||
        (!execution && !retained) || napi_unwrap(env, self, (void **)&input) != napi_ok || !input ||
        input->bridge.environment != env || !run_stdio_current_process(&input->bridge)) {
        native_error(env, "Invalid original Run MCP stdio input");
        return NULL;
    }
    return input;
}
static napi_value run_stdio_assert(napi_env env, napi_callback_info info) {
    struct run_mcp_stdio_input *input = run_stdio_unwrap(env, info);
    napi_value result;
    if (!input)
        return NULL;
    if (!run_stdio_input_current(&input->bridge))
        return native_error(env, "Run MCP stdio input changed or closed");
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value run_stdio_close(napi_env env, napi_callback_info info) {
    struct run_mcp_stdio_input *input = run_stdio_unwrap(env, info);
    napi_value result;
    if (!input)
        return NULL;
    if (run_stdio_input_retire(&input->bridge))
        return run_stdio_retirement_error(env);
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void run_stdio_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    struct run_mcp_stdio_input *input = data;
    if (run_stdio_input_retire(&input->bridge))
        return;
    state_lock *lock = input->lock;
    napi_ref ref = input->lock_ref;
    struct run_mcp_stdio_input **link = &lock->run_mcp_stdio_inputs;
    while (*link && *link != input)
        link = &(*link)->next;
    if (*link)
        *link = input->next;
    free(input);
    free_lock_if_done(lock);
    if (ref)
        napi_delete_reference(env, ref);
}
static bool run_stdio_text(napi_env env, napi_value value, char *out, size_t capacity, bool digest) {
    size_t size = 0;
    if (napi_get_value_string_utf8(env, value, NULL, 0, &size) != napi_ok || !size || size >= capacity ||
        napi_get_value_string_utf8(env, value, out, capacity, &size) != napi_ok || strlen(out) != size)
        return false;
    return !digest || cliq_mcp_admin_digest(out);
}
static bool run_stdio_number(napi_env env, napi_value value, uint64_t minimum, uint64_t *out) {
    double number = 0;
    if (napi_get_value_double(env, value, &number) != napi_ok || !isfinite(number) || number < (double)minimum || number > 9007199254740991.0 || number != (double)(uint64_t)number)
        return false;
    *out = (uint64_t)number;
    return true;
}
/* Fixed primitive-only private ABI. No native property traversal, caller getter,
 * proxy trap, pathname, fd, callback or structural capability is accepted. */
static bool run_stdio_arguments(napi_env env, napi_value args[31], struct cliq_mcp_stdio_run_birth *birth) {
    struct cliq_mcp_stdio_run_identity *binding = &birth->identity;
    size_t index = 0;
#define RUN_STDIO_TEXT(field, digest) do { if (!run_stdio_text(env, args[index++], binding->field, sizeof(binding->field), digest)) return false; } while (0)
    RUN_STDIO_TEXT(run, false);
    RUN_STDIO_TEXT(principal, false);
    RUN_STDIO_TEXT(launch_op, false);
    RUN_STDIO_TEXT(batch_item, false);
    RUN_STDIO_TEXT(call, false);
    RUN_STDIO_TEXT(worker_launch, false);
    RUN_STDIO_TEXT(supervisor, false);
    RUN_STDIO_TEXT(nonce, true);
    RUN_STDIO_TEXT(registry_ref, true);
    RUN_STDIO_TEXT(manifest_digest, true);
    RUN_STDIO_TEXT(tool_request_ref, true);
    RUN_STDIO_TEXT(tool_request_digest, true);
    RUN_STDIO_TEXT(launch_request_ref, true);
    RUN_STDIO_TEXT(launch_request_digest, true);
    RUN_STDIO_TEXT(target_ref, true);
    RUN_STDIO_TEXT(target_digest, true);
    RUN_STDIO_TEXT(grant_ref, true);
    RUN_STDIO_TEXT(grant_digest, true);
    RUN_STDIO_TEXT(plan_ref, true);
    RUN_STDIO_TEXT(plan_digest, true);
    RUN_STDIO_TEXT(spec_ref, true);
    RUN_STDIO_TEXT(spec_digest, true);
#undef RUN_STDIO_TEXT
#define RUN_STDIO_NUMBER(field, minimum) do { if (!run_stdio_number(env, args[index++], minimum, &binding->field)) return false; } while (0)
    RUN_STDIO_NUMBER(launch_attempt, 0);
    RUN_STDIO_NUMBER(lifecycle_seq, 0);
    RUN_STDIO_NUMBER(call_index, 0);
    RUN_STDIO_NUMBER(lease_epoch, 1);
    RUN_STDIO_NUMBER(owner_epoch, 1);
    RUN_STDIO_NUMBER(call_deadline_ms, 1);
    RUN_STDIO_NUMBER(launch_deadline_ms, 1);
#undef RUN_STDIO_NUMBER
    uint64_t pid;
    if (!run_stdio_number(env, args[index++], 1, &pid) || pid > INT32_MAX ||
        !run_stdio_text(env, args[index++], birth->supervisor_start_token, sizeof(birth->supervisor_start_token), false))
        return false;
    birth->supervisor_pid = (int64_t)pid;
    return index == 31 && binding->launch_deadline_ms <= binding->call_deadline_ms;
}
static napi_value run_stdio_open(napi_env env, napi_callback_info info, bool create) {
#ifndef __linux__
    (void)info;
    (void)create;
    return native_error(env, "Run MCP stdio physical input requires its Linux backend");
#else
    state_lock *lock = unwrap_lock(env, info);
    size_t argc = 32;
    napi_value args[32], self, result, identity;
    if (!lock || !lock_is_held(lock) || lock->run_mcp_stdio_retirement_error || syscall(SYS_gettid) != getpid() ||
        napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != 31)
        return native_error(env, "Run MCP stdio input requires its original held main-thread StateOwner");
    struct run_mcp_stdio_input *input = calloc(1, sizeof(*input));
    if (!input)
        return native_error(env, "Run MCP stdio input allocation failed");
    input->lock = lock;
    input->parent_fd = -1;
    input->retained = !create;
    struct cliq_mcp_stdio_run_input *bridge = &input->bridge;
    bridge->birth_fd = -1;
    bridge->abi_version = CLIQ_MCP_STDIO_RUN_INPUT_ABI;
    bridge->creator_pid = getpid();
    bridge->environment = env;
    bridge->assert_current = run_stdio_input_current;
    bridge->retire = run_stdio_input_retire;
    atomic_init(&bridge->closed, false);
    atomic_init(&bridge->execution_claimed, false);
    atomic_init(&bridge->execution_joined, false);
    if (!run_stdio_arguments(env, args, &bridge->binding))
        goto failed;
    struct cliq_mcp_stdio_run_birth expected = bridge->binding;
    if (create) {
        char token[128];
        if (expected.supervisor_pid != getpid() || observe_process_with_retirement(getpid(), token, &lock->process_observation_retirement_error) != 1 ||
            lock->process_observation_retirement_error || strcmp(token, expected.supervisor_start_token))
            goto failed;
    }
    int made = 0;
    if (create) {
        if (!mkdirat(lock->runtime_fd, "run-mcp-stdio", 0700))
            made = 1;
        else if (errno != EEXIST)
            goto failed;
    }
    input->parent_fd = openat(lock->runtime_fd, "run-mcp-stdio", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat named;
    if (input->parent_fd < 0 || fstat(input->parent_fd, &input->parent) || !private_directory(&input->parent) || input->parent.st_dev != lock->root.st_dev ||
        fstatat(lock->runtime_fd, "run-mcp-stdio", &named, AT_SYMLINK_NOFOLLOW) || !same_inode(&named, &input->parent) ||
        (made && !sync_directory(lock->runtime_fd)))
        goto failed;
    bridge->birth_fd = openat(input->parent_fd, bridge->binding.identity.nonce, O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0), 0600);
    if (bridge->birth_fd < 0 || fstat(bridge->birth_fd, &bridge->birth_identity) || !private_lock_file(&bridge->birth_identity) || bridge->birth_identity.st_dev != lock->root.st_dev)
        goto failed;
    if (create) {
        if (bridge->birth_identity.st_size)
            goto failed;
        bridge->binding.magic = CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC;
        bridge->binding.version = 1;
        admin_mcp_directory(&bridge->binding.state_root, &lock->root);
        admin_mcp_directory(&bridge->binding.runtime, &lock->runtime);
        admin_mcp_directory(&bridge->binding.private_parent, &input->parent);
        admin_mcp_directory(&bridge->binding.birth, &bridge->birth_identity);
        cliq_mcp_admin_hash(&bridge->binding, offsetof(struct cliq_mcp_stdio_run_birth, digest), bridge->binding.digest);
        size_t offset = 0;
        while (offset < sizeof(bridge->binding)) {
            ssize_t count = pwrite(bridge->birth_fd, (unsigned char *)&bridge->binding + offset, sizeof(bridge->binding) - offset, (off_t)offset);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
                goto failed;
            offset += (size_t)count;
        }
        if (fsync(bridge->birth_fd) || !sync_directory(input->parent_fd))
            goto failed;
    } else {
        struct cliq_mcp_stdio_history history;
        if (!cliq_mcp_stdio_read_history(bridge->birth_fd, &history, NULL, NULL) || history.purpose != CLIQ_MCP_STDIO_RUN)
            goto failed;
        bridge->binding = history.header.run;
        if (bridge->binding.magic != CLIQ_MCP_STDIO_RUN_BIRTH_MAGIC || bridge->binding.version != 1 ||
            memcmp(&bridge->binding.identity, &expected.identity, sizeof(expected.identity)) ||
            bridge->binding.supervisor_pid != expected.supervisor_pid || memcmp(bridge->binding.supervisor_start_token, expected.supervisor_start_token, sizeof(expected.supervisor_start_token)) ||
            bridge->binding.supervisor_pid == getpid())
            goto failed;
        char token[128];
        int observed = observe_process_with_retirement((pid_t)bridge->binding.supervisor_pid, token, &lock->process_observation_retirement_error);
        if (lock->process_observation_retirement_error || (observed != 0 && !(observed == 1 && strcmp(token, bridge->binding.supervisor_start_token))))
            goto failed;
        /* This tag establishes the original complete chain and held file.
         * The disjoint cleanup constructor must repeat its currentness and
         * actual old-controller death checks before any physical action. */
    }
    if (!run_stdio_input_current(bridge) || napi_create_object(env, &result) != napi_ok || napi_create_object(env, &identity) != napi_ok ||
        !string_property(env, identity, "runId", bridge->binding.identity.run) || !string_property(env, identity, "launchOpId", bridge->binding.identity.launch_op) ||
        !string_property(env, identity, "nonce", bridge->binding.identity.nonce) || !identity_member(env, identity, "birthIdentity", &bridge->birth_identity) ||
        !identity_member(env, identity, "privateParentIdentity", &input->parent))
        goto failed;
    napi_object_freeze(env, identity);
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, run_stdio_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, run_stdio_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_set_named_property(env, result, "identity", identity) != napi_ok || napi_define_properties(env, result, 2, methods) != napi_ok ||
        napi_type_tag_object(env, result, create ? &CLIQ_MCP_STDIO_RUN_INPUT_TAG : &CLIQ_MCP_STDIO_RUN_RETAINED_INPUT_TAG) != napi_ok ||
        napi_create_reference(env, self, 1, &input->lock_ref) != napi_ok || napi_wrap(env, result, input, run_stdio_finalize, NULL, NULL) != napi_ok)
        goto failed;
    input->next = lock->run_mcp_stdio_inputs;
    lock->run_mcp_stdio_inputs = input;
    napi_object_freeze(env, result);
    return result;
failed:
    run_stdio_input_retire(bridge);
    if (input->lock_ref)
        napi_delete_reference(env, input->lock_ref);
    free(input);
    if (lock->run_mcp_stdio_retirement_error)
        return run_stdio_retirement_error(env);
    return native_error(env, "Original Run MCP stdio birth is missing, partial, replaced or unavailable; recovery is required");
#endif
}
static napi_value create_run_mcp_stdio_input(napi_env env, napi_callback_info info) {
    return run_stdio_open(env, info, true);
}
static napi_value open_retained_run_mcp_stdio_input(napi_env env, napi_callback_info info) {
    return run_stdio_open(env, info, false);
}
#else
static int close_lock_run_mcp_stdio_inputs(state_lock *lock) {
    return lock->run_mcp_stdio_retirement_error;
}
static napi_value create_run_mcp_stdio_input(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "Run MCP stdio physical input requires its Linux backend");
}
static napi_value open_retained_run_mcp_stdio_input(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "Run MCP stdio physical input requires its Linux backend");
}
#endif
