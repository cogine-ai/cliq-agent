/*
 * Original Admin prepared intent's private birth bookmark, rooted in this held StateOwner. This is physical custody,
 * never a SQL permission grant.
 */
#include "../linux/mcp-http-admin-protocol.h"
#include "../linux/mcp-stdio-protocol.h"
#include <math.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
struct admin_mcp_input {
    struct cliq_mcp_admin_input bridge;
    state_lock     *lock;
    napi_ref        lock_ref;
    int             parent_fd;
    struct stat     parent;
    bool            retained;
    bool            stdio;
    struct admin_mcp_input *next;
};
static void
admin_mcp_directory(struct cliq_mcp_admin_directory *out, const struct stat *file)
{
    out->device = file->st_dev;
    out->inode = file->st_ino;
    out->uid = file->st_uid;
    out->gid = file->st_gid;
    out->mode = file->st_mode;
}
static bool
admin_mcp_directory_same(const struct cliq_mcp_admin_directory *left, const struct stat *right)
{
    return left->device == (uint64_t) right->st_dev && left->inode == (uint64_t) right->st_ino && left->uid == right->st_uid && left->gid == right->st_gid && left->mode == right->st_mode;
}
static bool
admin_mcp_current_process(struct cliq_mcp_admin_input *bridge)
{
    return bridge->creator_pid == getpid()
#ifdef __linux__
        && syscall(SYS_gettid) == getpid()
#endif
        ;
}
static bool
admin_mcp_input_current(struct cliq_mcp_admin_input *bridge)
{
    admin_mcp_input *input = (admin_mcp_input *) bridge;
    struct stat     parent, file, named;
    struct cliq_mcp_admin_birth recorded;
    return admin_mcp_current_process(bridge) && bridge->abi_version == CLIQ_MCP_ADMIN_INPUT_ABI && !atomic_load(&bridge->closed) && !input->lock->admin_mcp_retirement_error &&
        lock_is_held(input->lock) && input->parent_fd >= 0 && bridge->birth_fd >= 0 && fstat(input->parent_fd, &parent) == 0 && private_directory(&parent) && same_inode(&parent, &input->parent) &&
        fstatat(input->lock->runtime_fd, input->stdio ? "admin-mcp-stdio" : "admin-mcp", &named, AT_SYMLINK_NOFOLLOW) == 0 && private_directory(&named) && same_inode(&named, &parent) &&
        fstat(bridge->birth_fd, &file) == 0 && private_lock_file(&file) && same_inode(&file, &bridge->birth_identity) &&
        fstatat(input->parent_fd, bridge->binding.nonce, &named, AT_SYMLINK_NOFOLLOW) == 0 && private_lock_file(&named) && same_inode(&file, &named) &&
        cliq_mcp_admin_read_exact(bridge->birth_fd, &recorded, sizeof(recorded), 0) && !memcmp(&recorded, &bridge->binding, sizeof(recorded)) &&
        admin_mcp_directory_same(&recorded.state_root, &input->lock->root) && admin_mcp_directory_same(&recorded.runtime, &input->lock->runtime) &&
        admin_mcp_directory_same(&recorded.admin_parent, &parent) && admin_mcp_directory_same(&recorded.birth, &file);
}
static int
admin_mcp_input_close_native(struct cliq_mcp_admin_input *bridge)
{
    admin_mcp_input *input = (admin_mcp_input *) bridge;
    if (!admin_mcp_current_process(bridge) || (atomic_load(&bridge->execution_claimed) && !atomic_load(&bridge->execution_joined)))
        return EBUSY;
    atomic_store(&bridge->closed, true);
    int            *slots[] = {&bridge->birth_fd, &input->parent_fd};
    for (size_t i = 0; i < 2; i++) {
        int             fd = *slots[i];
        *slots[i] = -1;
        if (fd >= 0 && close(fd) < 0)
            input->lock->admin_mcp_retirement_error = errno;
    }
    return input->lock->admin_mcp_retirement_error;
}
static bool
admin_mcp_retired_snapshot(struct cliq_mcp_admin_input *bridge, const unsigned char *expected, size_t expected_size)
{
    admin_mcp_input *input = (admin_mcp_input *)bridge;
    if (!admin_mcp_current_process(bridge) || bridge->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI || input->retained ||
        !expected || !expected_size || expected_size > sizeof(struct cliq_mcp_admin_birth) +
            CLIQ_MCP_STDIO_MAX_PROGRESS * sizeof(struct cliq_mcp_stdio_progress) ||
        !atomic_load(&bridge->closed) || !atomic_load(&bridge->execution_claimed) || !atomic_load(&bridge->execution_joined) ||
        bridge->birth_fd >= 0 || input->parent_fd >= 0 || input->lock->admin_mcp_retirement_error || !lock_is_held(input->lock)) return false;
    int parent = openat(input->lock->runtime_fd, input->stdio ? "admin-mcp-stdio" : "admin-mcp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int birth = -1; struct stat held, named, file; unsigned char *bytes = NULL; size_t size = 0;
    bool valid = parent >= 0 && !fstat(parent, &held) && private_directory(&held) && same_inode(&held, &input->parent) &&
        admin_mcp_directory_same(&bridge->binding.admin_parent, &held) &&
        !fstatat(input->lock->runtime_fd, input->stdio ? "admin-mcp-stdio" : "admin-mcp", &named, AT_SYMLINK_NOFOLLOW) &&
        same_inode(&held, &named);
    if (valid) birth = openat(parent, bridge->binding.nonce, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    valid = valid && birth >= 0 && !fstat(birth, &file) && private_lock_file(&file) && same_inode(&file, &bridge->birth_identity) &&
        admin_mcp_directory_same(&bridge->binding.birth, &file) && !fstatat(parent, bridge->binding.nonce, &named, AT_SYMLINK_NOFOLLOW) &&
        private_lock_file(&named) && same_inode(&file, &named);
    if (valid && input->stdio) {
        struct cliq_mcp_stdio_history history;
        valid = cliq_mcp_stdio_read_history(birth, &history, &bytes, &size) && history.purpose == CLIQ_MCP_STDIO_ADMIN &&
            history.count && history.last.kind == 9 && !memcmp(&history.header.admin, &bridge->binding, sizeof(bridge->binding));
    } else if (valid) {
        struct cliq_mcp_admin_history history;
        valid = cliq_mcp_admin_read_history(birth, &history, &bytes, &size) && history.count && history.last.kind == 9 &&
            !memcmp(&history.header, &bridge->binding, sizeof(bridge->binding));
    }
    valid = valid && size == expected_size && !memcmp(bytes, expected, size) && !fstat(birth, &held) &&
        private_lock_file(&held) && same_inode(&held, &file) && !fstatat(parent, bridge->binding.nonce, &named, AT_SYMLINK_NOFOLLOW) &&
        private_lock_file(&named) && same_inode(&held, &named) && lock_is_held(input->lock);
    free(bytes);
    int descriptors[] = {birth, parent};
    for (size_t i = 0; i < 2; i++) if (descriptors[i] >= 0 && close(descriptors[i])) input->lock->admin_mcp_retirement_error = errno;
    return valid && !input->lock->admin_mcp_retirement_error && lock_is_held(input->lock);
}
static int
close_lock_admin_mcp_inputs(state_lock * lock)
{
    int             failed = 0;
    for (admin_mcp_input * input = lock->admin_mcp_inputs; input; input = input->next)
        if (admin_mcp_input_close_native(&input->bridge))
            failed = 1;
    return failed || lock->admin_mcp_retirement_error;
}
static napi_value admin_mcp_retirement(napi_env env) {
    napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "Admin MCP resources did not retire; original StateOwner remains held");
    return NULL;
}
static admin_mcp_input * admin_mcp_unwrap(napi_env env, napi_callback_info info) {
    napi_value      self;
    bool            live = false, retained = false, stdio_live = false, stdio_retained = false;
    admin_mcp_input *input = NULL;
    if (napi_get_cb_info(env, info, NULL, NULL, &self, NULL) != napi_ok || napi_check_object_type_tag(env, self, &CLIQ_MCP_ADMIN_INPUT_TAG, &live) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_ADMIN_RETAINED_INPUT_TAG, &retained) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_ADMIN_INPUT_TAG, &stdio_live) != napi_ok ||
        napi_check_object_type_tag(env, self, &CLIQ_MCP_STDIO_ADMIN_RETAINED_INPUT_TAG, &stdio_retained) != napi_ok ||
        (!live && !retained && !stdio_live && !stdio_retained) || napi_unwrap(env, self, (void **)&input) != napi_ok ||
        !input || input->stdio != (stdio_live || stdio_retained) || input->bridge.environment != env || !admin_mcp_current_process(&input->bridge)) {
        native_error(env, "Invalid original Admin MCP input");
        return NULL;
    } return input;
}
static napi_value admin_mcp_assert(napi_env env, napi_callback_info info) {
    admin_mcp_input *input = admin_mcp_unwrap(env, info);
    napi_value      result;
    if (!input)
        return NULL;
    if (!admin_mcp_input_current(&input->bridge))
        return native_error(env, "Original Admin MCP input changed or closed");
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value admin_mcp_close(napi_env env, napi_callback_info info) {
    admin_mcp_input *input = admin_mcp_unwrap(env, info);
    napi_value      result;
    if (!input)
        return NULL;
    if (admin_mcp_input_close_native(&input->bridge))
        return admin_mcp_retirement(env);
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void
admin_mcp_finalize(napi_env env, void *data, void *hint)
{
    (void)hint;
    admin_mcp_input *input = data;
    if (admin_mcp_input_close_native(&input->bridge))
        return;
    state_lock     *lock = input->lock;
    napi_ref        ref = input->lock_ref;
    admin_mcp_input **link = &lock->admin_mcp_inputs;
    while (*link && *link != input)
        link = &(*link)->next;
    if (*link)
        *link = input->next;
    free(input);
    free_lock_if_done(lock);
    if (ref)
        napi_delete_reference(env, ref);
}
static bool
admin_mcp_field(napi_env env, napi_value value, const char *name, char *out, size_t capacity, bool digest)
{
    napi_value      item;
    size_t          size;
    if (napi_get_named_property(env, value, name, &item) != napi_ok || napi_get_value_string_utf8(env, item, NULL, 0, &size) != napi_ok || !size || size >= capacity ||
        napi_get_value_string_utf8(env, item, out, capacity, &size) != napi_ok || strlen(out) != size) {
        return false;
    }
    return !digest || cliq_mcp_admin_digest(out);
}
static bool
admin_mcp_binding_data(napi_env env, napi_value value, struct cliq_mcp_admin_birth *binding)
{
    const char     *keys[] = {"adminOperationId", "attempt", "principalId", "nonce", "targetRef", "targetDigest", "probePayloadCoreRef", "probePayloadCoreDigest", "plannedContainmentRef", "plannedContainmentDigest", "sandboxLaunchSpecRef", "sandboxLaunchSpecDigest"};
    napi_value      names, item;
    uint32_t        count;
    double          attempt;
    bool            array;
    if (napi_is_array(env, value, &array) != napi_ok || array || napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok || napi_get_array_length(env, names, &count) != napi_ok || count != 12)
        return false;
    for (size_t i = 0; i < 12; i++) {
        bool            has;
        napi_value      key;
        if (napi_create_string_utf8(env, keys[i], NAPI_AUTO_LENGTH, &key) != napi_ok || napi_has_own_property(env, value, key, &has) != napi_ok || !has)
            return false;
    }
    if (napi_get_named_property(env, value, "attempt", &item) != napi_ok || napi_get_value_double(env, item, &attempt) != napi_ok || attempt < 0 || attempt > 9007199254740991.0 || attempt != (double)(uint64_t) attempt)
        return false;
    binding->attempt = (uint64_t) attempt;
    return admin_mcp_field(env, value, "adminOperationId", binding->operation, sizeof(binding->operation), false) && admin_mcp_field(env, value, "principalId", binding->principal, sizeof(binding->principal), false) &&
        admin_mcp_field(env, value, "nonce", binding->nonce, sizeof(binding->nonce), true) && admin_mcp_field(env, value, "targetRef", binding->target_ref, sizeof(binding->target_ref), true) &&
        admin_mcp_field(env, value, "targetDigest", binding->target_digest, sizeof(binding->target_digest), true) && admin_mcp_field(env, value, "probePayloadCoreRef", binding->core_ref, sizeof(binding->core_ref), true) &&
        admin_mcp_field(env, value, "probePayloadCoreDigest", binding->core_digest, sizeof(binding->core_digest), true) && admin_mcp_field(env, value, "plannedContainmentRef", binding->plan_ref, sizeof(binding->plan_ref), true) &&
        admin_mcp_field(env, value, "plannedContainmentDigest", binding->plan_digest, sizeof(binding->plan_digest), true) && admin_mcp_field(env, value, "sandboxLaunchSpecRef", binding->spec_ref, sizeof(binding->spec_ref), true) &&
        admin_mcp_field(env, value, "sandboxLaunchSpecDigest", binding->spec_digest, sizeof(binding->spec_digest), true);
}
static bool
admin_mcp_same_binding(const struct cliq_mcp_admin_birth *left, const struct cliq_mcp_admin_birth *right)
{
    return left->attempt == right->attempt && !strcmp(left->operation, right->operation) && !strcmp(left->principal, right->principal) && !strcmp(left->nonce, right->nonce) &&
        !strcmp(left->target_ref, right->target_ref) && !strcmp(left->target_digest, right->target_digest) && !strcmp(left->core_ref, right->core_ref) && !strcmp(left->core_digest, right->core_digest) &&
        !strcmp(left->plan_ref, right->plan_ref) && !strcmp(left->plan_digest, right->plan_digest) && !strcmp(left->spec_ref, right->spec_ref) && !strcmp(left->spec_digest, right->spec_digest);
}
static bool admin_stdio_text(napi_env env, napi_value value, char *out, size_t capacity, bool digest) {
    size_t size = 0;
    return napi_get_value_string_utf8(env, value, NULL, 0, &size) == napi_ok && size && size < capacity &&
        napi_get_value_string_utf8(env, value, out, capacity, &size) == napi_ok && strlen(out) == size && (!digest || cliq_mcp_admin_digest(out));
}
static bool admin_stdio_arguments(napi_env env, napi_value args[14], struct cliq_mcp_admin_birth *birth) {
    size_t index = 0;
#define ADMIN_STDIO_TEXT(field, digest) do { if (!admin_stdio_text(env, args[index++], birth->field, sizeof(birth->field), digest)) return false; } while (0)
    ADMIN_STDIO_TEXT(operation, false); ADMIN_STDIO_TEXT(principal, false); ADMIN_STDIO_TEXT(nonce, true);
    ADMIN_STDIO_TEXT(target_ref, true); ADMIN_STDIO_TEXT(target_digest, true); ADMIN_STDIO_TEXT(core_ref, true); ADMIN_STDIO_TEXT(core_digest, true);
    ADMIN_STDIO_TEXT(plan_ref, true); ADMIN_STDIO_TEXT(plan_digest, true); ADMIN_STDIO_TEXT(spec_ref, true); ADMIN_STDIO_TEXT(spec_digest, true);
    double attempt, pid;
    if (napi_get_value_double(env, args[index++], &attempt) != napi_ok || !isfinite(attempt) || attempt < 0 || attempt > 9007199254740991.0 || attempt != (double)(uint64_t)attempt ||
        napi_get_value_double(env, args[index++], &pid) != napi_ok || !isfinite(pid) || pid < 1 || pid > INT32_MAX || pid != (double)(int64_t)pid) return false;
    birth->attempt = (uint64_t)attempt; birth->supervisor_pid = (int64_t)pid;
    ADMIN_STDIO_TEXT(supervisor_start_token, false);
#undef ADMIN_STDIO_TEXT
    return index == 14;
}
static napi_value admin_mcp_open(napi_env env, napi_callback_info info, bool create, bool stdio){
    state_lock     *lock = unwrap_lock(env, info);
    size_t          argc = 15;
    napi_value      args[15], self, result, identity;
    if (!lock)
        return NULL;
    if (!lock_is_held(lock) || lock->admin_mcp_retirement_error || napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc != (stdio ? 14u : 1u))
        return native_error(env, "Admin MCP input requires its original held StateOwner");
    admin_mcp_input *input = calloc(1, sizeof(*input));
    if (!input)
        return native_error(env, "Admin MCP input allocation unavailable");
    input->lock = lock;
    input->parent_fd = -1;
    input->bridge.birth_fd = -1;
    input->retained = !create;
    input->stdio = stdio;
    struct cliq_mcp_admin_input *bridge = &input->bridge;
    bridge->abi_version = CLIQ_MCP_ADMIN_INPUT_ABI;
    bridge->creator_pid = getpid();
    bridge->environment = env;
    bridge->assert_current = admin_mcp_input_current;
    bridge->retire = admin_mcp_input_close_native;
    bridge->assert_retired_snapshot = admin_mcp_retired_snapshot;
    atomic_init(&bridge->closed, false);
    atomic_init(&bridge->execution_claimed, false);
    atomic_init(&bridge->execution_joined, false);
    if (!(stdio ? admin_stdio_arguments(env, args, &bridge->binding) : admin_mcp_binding_data(env, args[0], &bridge->binding)))
        goto failed;
    if (stdio && create) {
        char token[128];
        if (bridge->binding.supervisor_pid != getpid() || observe_process_with_retirement(getpid(), token, &lock->process_observation_retirement_error) != 1 ||
            lock->process_observation_retirement_error || strcmp(token, bridge->binding.supervisor_start_token)) goto failed;
    }
    const char *parent_name = stdio ? "admin-mcp-stdio" : "admin-mcp";
    int             made = 0;
    if (create) {
        if (!mkdirat(lock->runtime_fd, parent_name, 0700))
            made = 1;
        else if (errno != EEXIST)
            goto failed;
    }
    input->parent_fd = openat(lock->runtime_fd, parent_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat     named;
    if (input->parent_fd < 0 || fstat(input->parent_fd, &input->parent) || !private_directory(&input->parent) || input->parent.st_dev != lock->root.st_dev ||
        fstatat(lock->runtime_fd, parent_name, &named, AT_SYMLINK_NOFOLLOW) || !same_inode(&named, &input->parent) || (made && !sync_directory(lock->runtime_fd)))
        goto failed;
    bridge->birth_fd = openat(input->parent_fd, bridge->binding.nonce, O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT | O_EXCL : 0), 0600);
    if (bridge->birth_fd < 0 || fstat(bridge->birth_fd, &bridge->birth_identity) || !private_lock_file(&bridge->birth_identity) || bridge->birth_identity.st_dev != lock->root.st_dev)
        goto failed;
    if (create) {
        bridge->binding.magic = stdio ? CLIQ_MCP_STDIO_ADMIN_BIRTH_MAGIC : CLIQ_MCP_ADMIN_BIRTH_MAGIC;
        bridge->binding.version = 1;
        bridge->binding.supervisor_pid = getpid();
        char            token[128];
        if (bridge->birth_identity.st_size || observe_process_with_retirement(getpid(), token, &lock->process_observation_retirement_error) != 1 || lock->process_observation_retirement_error)
            goto failed;
        memcpy(bridge->binding.supervisor_start_token, token, strlen(token) + 1);
        admin_mcp_directory(&bridge->binding.state_root, &lock->root);
        admin_mcp_directory(&bridge->binding.runtime, &lock->runtime);
        admin_mcp_directory(&bridge->binding.admin_parent, &input->parent);
        admin_mcp_directory(&bridge->binding.birth, &bridge->birth_identity);
        cliq_mcp_admin_hash(&bridge->binding, offsetof(struct cliq_mcp_admin_birth, digest), bridge->binding.digest);
        size_t          offset = 0;
        while (offset < sizeof(bridge->binding)) {
            ssize_t         n = pwrite(bridge->birth_fd, (unsigned char *)&bridge->binding + offset, sizeof(bridge->binding) - offset, (off_t) offset);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                goto failed;
            offset += (size_t) n;
        }
        if (fsync(bridge->birth_fd) || !sync_directory(input->parent_fd))
            goto failed;
    } else {
        struct cliq_mcp_admin_history history;
        struct cliq_mcp_admin_birth expected = bridge->binding;
        if (stdio) {
            struct cliq_mcp_stdio_history original;
            if (!cliq_mcp_stdio_read_history(bridge->birth_fd, &original, NULL, NULL) || original.purpose != CLIQ_MCP_STDIO_ADMIN) goto failed;
            history.header = original.header.admin;
        } else if (!cliq_mcp_admin_read_history(bridge->birth_fd, &history, NULL, NULL)) goto failed;
        if (!admin_mcp_same_binding(&expected, &history.header) || history.header.supervisor_pid <= 0 || history.header.supervisor_pid > INT32_MAX || history.header.supervisor_pid == getpid() ||
            (stdio && (history.header.supervisor_pid != expected.supervisor_pid || strcmp(history.header.supervisor_start_token, expected.supervisor_start_token))))
            goto failed;
        char            token[128];
        int             observed = observe_process_with_retirement((pid_t) history.header.supervisor_pid, token, &lock->process_observation_retirement_error);
        if (lock->process_observation_retirement_error || (observed != 0 && !(observed == 1 && strcmp(token, history.header.supervisor_start_token))))
            goto failed;
        bridge->binding = history.header;
    }
    if (!admin_mcp_input_current(bridge) || napi_create_object(env, &result) != napi_ok || napi_create_object(env, &identity) != napi_ok ||
        !string_property(env, identity, "adminOperationId", bridge->binding.operation) || !string_property(env, identity, "nonce", bridge->binding.nonce) ||
        !string_property(env, identity, "targetRef", bridge->binding.target_ref) || !string_property(env, identity, "probePayloadCoreRef", bridge->binding.core_ref) || !identity_member(env, identity, "birthIdentity", &bridge->birth_identity))
        goto failed;
    napi_value      attempt;
    napi_create_double(env, (double)bridge->binding.attempt, &attempt);
    napi_set_named_property(env, identity, "attempt", attempt);
    napi_object_freeze(env, identity);
    const           napi_property_descriptor methods[] = {{"assertHeld", NULL, admin_mcp_assert, NULL, NULL, NULL, napi_default, NULL}, {"close", NULL, admin_mcp_close, NULL, NULL, NULL, napi_default, NULL}};
    const napi_type_tag *tag = stdio ? (create ? &CLIQ_MCP_STDIO_ADMIN_INPUT_TAG : &CLIQ_MCP_STDIO_ADMIN_RETAINED_INPUT_TAG) :
        (create ? &CLIQ_MCP_ADMIN_INPUT_TAG : &CLIQ_MCP_ADMIN_RETAINED_INPUT_TAG);
    if (napi_set_named_property(env, result, "identity", identity) != napi_ok || napi_define_properties(env, result, 2, methods) != napi_ok || napi_type_tag_object(env, result, tag) != napi_ok ||
        napi_create_reference(env, self, 1, &input->lock_ref) != napi_ok || napi_wrap(env, result, input, admin_mcp_finalize, NULL, NULL) != napi_ok)
        goto failed;
    input->next = lock->admin_mcp_inputs;
    lock->admin_mcp_inputs = input;
    napi_object_freeze(env, result);
    return result;
failed:admin_mcp_input_close_native(bridge);
    if (input->lock_ref)
        napi_delete_reference(env, input->lock_ref);
    free(input);
    if (lock->admin_mcp_retirement_error)
        return admin_mcp_retirement(env);
    return native_error(env, "Original Admin MCP birth is missing, partial, changed or unavailable; recovery is required");
}
static napi_value create_admin_mcp_input(napi_env env, napi_callback_info info) {
    return admin_mcp_open(env, info, true, false);
}
static napi_value open_retained_admin_mcp_input(napi_env env, napi_callback_info info) {
    return admin_mcp_open(env, info, false, false);
}
static napi_value create_admin_mcp_stdio_input(napi_env env, napi_callback_info info) {
    return admin_mcp_open(env, info, true, true);
}
static napi_value open_retained_admin_mcp_stdio_input(napi_env env, napi_callback_info info) {
    return admin_mcp_open(env, info, false, true);
}
static napi_value open_absent_admin_mcp_input(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "Missing Admin MCP birth cannot prove no-spawn; original recovery is required");
}
static void
admin_mcp_data_number(napi_env env, napi_value object, const char *key, uint64_t number)
{
    napi_value      value;
    napi_create_double(env, (double)number, &value);
    napi_set_named_property(env, object, key, value);
}
static void
admin_mcp_data_bool(napi_env env, napi_value object, const char *key, bool boolean)
{
    napi_value      value;
    napi_get_boolean(env, boolean, &value);
    napi_set_named_property(env, object, key, value);
}
static napi_value admin_mcp_binding_value(napi_env env, const struct cliq_mcp_admin_birth *header){
    napi_value      value;
    napi_create_object(env, &value);
    string_property(env, value, "adminOperationId", header->operation);
    admin_mcp_data_number(env, value, "attempt", header->attempt);
    string_property(env, value, "principalId", header->principal);
    string_property(env, value, "nonce", header->nonce);
    string_property(env, value, "targetRef", header->target_ref);
    string_property(env, value, "targetDigest", header->target_digest);
    string_property(env, value, "probePayloadCoreRef", header->core_ref);
    string_property(env, value, "probePayloadCoreDigest", header->core_digest);
    string_property(env, value, "plannedContainmentRef", header->plan_ref);
    string_property(env, value, "plannedContainmentDigest", header->plan_digest);
    string_property(env, value, "sandboxLaunchSpecRef", header->spec_ref);
    string_property(env, value, "sandboxLaunchSpecDigest", header->spec_digest);
    napi_object_freeze(env, value);
    return value;
}
static napi_value admin_mcp_packet_value(napi_env env, const struct cliq_worker_packet *packet){
    napi_value      value;
    napi_create_object(env, &value);
    admin_mcp_data_number(env, value, "pid", packet->pid);
    admin_mcp_data_number(env, value, "namespaceInitPid", packet->namespace_init_pid);
    string_property(env, value, "processStartToken", packet->start_token);
    string_property(env, value, "namespaceInitStartToken", packet->init_start_token);
    char            text[32];
    snprintf(text, sizeof(text), "%llu", (unsigned long long)packet->cgroup_inode);
    string_property(env, value, "cgroupId", text);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)packet->pid_namespace_inode);
    string_property(env, value, "pidNamespaceId", text);
    admin_mcp_data_number(env, value, "cgroupPopulated", packet->populated);
    admin_mcp_data_number(env, value, "remainingTrackedDescendants", packet->remaining_descendants);
    admin_mcp_data_number(env, value, "namespaceInitDeadAndReaped", packet->init_reaped);
    admin_mcp_data_number(env, value, "observedAtMs", packet->observed_at_ms);
    napi_object_freeze(env, value);
    return value;
}
static napi_value admin_mcp_identity_value(napi_env env, const struct cliq_mcp_admin_directory *identity){
    napi_value      value;
    napi_create_object(env, &value);
    char            text[32];
    snprintf(text, sizeof(text), "%llu", (unsigned long long)identity->device);
    string_property(env, value, "deviceId", text);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)identity->inode);
    string_property(env, value, "fileId", text);
    admin_mcp_data_number(env, value, "ownerUid", identity->uid);
    napi_object_freeze(env, value);
    return value;
}
static napi_value decode_admin_mcp_lifecycle(napi_env env, napi_callback_info info) {
    size_t          argc = 2, size;
    napi_value      args[2];
    bool            buffer;
    void           *bytes;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 || napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok ||
        size > sizeof(struct cliq_mcp_admin_birth) + 32 * sizeof(struct cliq_mcp_admin_progress))
        return native_error(env, "Invalid bounded Admin MCP lifecycle data");
    struct cliq_mcp_admin_history history;
    if (!cliq_mcp_admin_history_bytes(bytes, size, &history))
        return native_error(env, "Invalid complete original Admin MCP lifecycle hashchain");
    napi_value      result, binding, controller, reservation, containment, joined;
    napi_create_object(env, &result);
    binding = admin_mcp_binding_value(env, &history.header);
    napi_set_named_property(env, result, "binding", binding);
    admin_mcp_data_number(env, result, "schemaVersion", 1);
    string_property(env, result, "format", "cliq-mcp-admin-native-lifecycle-v1");
    napi_create_object(env, &controller);
    napi_value      original_supervisor;
    napi_create_object(env, &original_supervisor);
    admin_mcp_data_number(env, original_supervisor, "pid", history.header.supervisor_pid);
    string_property(env, original_supervisor, "processStartToken", history.header.supervisor_start_token);
    napi_object_freeze(env, original_supervisor);
    napi_set_named_property(env, result, "originalSupervisor", original_supervisor);
    napi_set_named_property(env, result, "stateRootIdentity", admin_mcp_identity_value(env, &history.header.state_root));
    napi_set_named_property(env, result, "runtimeIdentity", admin_mcp_identity_value(env, &history.header.runtime));
    napi_value      birth_identity, parent_identity;
    napi_create_object(env, &birth_identity);
    napi_create_object(env, &parent_identity);
    char            identity_text[32];
    snprintf(identity_text, sizeof(identity_text), "%llu", (unsigned long long)history.header.birth.device);
    string_property(env, birth_identity, "deviceId", identity_text);
    snprintf(identity_text, sizeof(identity_text), "%llu", (unsigned long long)history.header.birth.inode);
    string_property(env, birth_identity, "fileId", identity_text);
    admin_mcp_data_number(env, birth_identity, "ownerUid", history.header.birth.uid);
    napi_object_freeze(env, birth_identity);
    napi_set_named_property(env, result, "birthIdentity", birth_identity);
    snprintf(identity_text, sizeof(identity_text), "%llu", (unsigned long long)history.header.admin_parent.device);
    string_property(env, parent_identity, "deviceId", identity_text);
    snprintf(identity_text, sizeof(identity_text), "%llu", (unsigned long long)history.header.admin_parent.inode);
    string_property(env, parent_identity, "fileId", identity_text);
    admin_mcp_data_number(env, parent_identity, "ownerUid", history.header.admin_parent.uid);
    napi_object_freeze(env, parent_identity);
    napi_set_named_property(env, result, "privateParentIdentity", parent_identity);
    admin_mcp_data_number(env, controller, "pid", history.count ? (uint64_t) history.first.controller_pid : 0);
    string_property(env, controller, "processStartToken", history.count ? history.first.controller_start_token : "");
    napi_object_freeze(env, controller);
    napi_set_named_property(env, result, "controller", controller);
    napi_create_object(env, &reservation);
    const struct cliq_worker_packet *last = &history.last.packet;
    string_property(env, reservation, "cgroupName", history.count ? last->cgroup_name : "");
    char            text[32];
    snprintf(text, sizeof(text), "%llu", (unsigned long long)last->cgroup_device);
    string_property(env, reservation, "cgroupDevice", text);
    snprintf(text, sizeof(text), "%llu", (unsigned long long)last->cgroup_inode);
    string_property(env, reservation, "cgroupInode", text);
    napi_object_freeze(env, reservation);
    napi_set_named_property(env, result, "reservation", reservation);
    if (history.ready.kind == 5)
        containment = admin_mcp_packet_value(env, &history.ready.packet);
    else
        napi_get_null(env, &containment);
    napi_set_named_property(env, result, "containment", containment);
    napi_value      retirement;
    if (history.count && history.last.kind >= 8)
        retirement = admin_mcp_packet_value(env, last);
    else
        napi_get_null(env, &retirement);
    napi_set_named_property(env, result, "retirement", retirement);
    napi_create_object(env, &joined);
    bool            death = history.count && history.last.kind >= 8 && !last->populated && !last->remaining_descendants && (!history.ready.kind || last->init_reaped == 1);
    admin_mcp_data_bool(env, joined, "deathJoined", death);
    admin_mcp_data_bool(env, joined, "outputCustodyRetired", death && history.last.kind == 9);
    admin_mcp_data_bool(env, joined, "protocolCompleted", history.count && last->admin_protocol_complete == 1);
    napi_object_freeze(env, joined);
    napi_set_named_property(env, result, "joined", joined);
    admin_mcp_data_number(env, result, "progressKind", history.count ? history.last.kind : 0);
    const unsigned char *hash = history.count ? history.last.digest : history.header.digest;
    char            digest[65];
    for (size_t i = 0; i < 32; i++)
        snprintf(digest + i * 2, 3, "%02x", hash[i]);
    string_property(env, result, "progressDigest", digest);
    napi_object_freeze(env, result);
    return result;
}
