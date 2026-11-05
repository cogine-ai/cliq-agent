#ifndef CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_NATIVE_H
#define CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_NATIVE_H
#include "mcp-admin-original-retirement.h"
static const napi_type_tag MCP_ADMIN_ORIGINAL_HTTP_TAG = {UINT64_C(0x5f6d4a9d4fd14912), UINT64_C(0xabc48633b198a9ad)};
static const napi_type_tag MCP_ADMIN_ORIGINAL_STDIO_TAG = {UINT64_C(0x34ff7d287bb04d35), UINT64_C(0xb2c7a6bcb782e990)};
struct mcp_admin_original_receipt {
    void *scope;
    struct controller *controller;
    napi_env env;
    napi_ref original;
    struct cliq_mcp_admin_original_retirement data;
};
static bool mcp_admin_original_directory(const struct cliq_mcp_admin_directory *expected, const struct stat *actual) {
    return expected->device == (uint64_t)actual->st_dev && expected->inode == (uint64_t)actual->st_ino &&
        expected->uid == actual->st_uid && expected->gid == actual->st_gid && expected->mode == actual->st_mode;
}
static const napi_type_tag *mcp_admin_original_tag(unsigned transport) {
    return transport == CLIQ_MCP_ADMIN_ORIGINAL_HTTP ? &MCP_ADMIN_ORIGINAL_HTTP_TAG : &MCP_ADMIN_ORIGINAL_STDIO_TAG;
}
static void mcp_admin_original_finalize(napi_env env, void *data, void *hint) {
    (void)hint; struct mcp_admin_original_receipt *receipt = data;
    if (receipt->original) napi_delete_reference(env, receipt->original);
    free(receipt);
}
static napi_value mcp_admin_original_copy(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value self, args[1], result; struct mcp_admin_original_receipt *receipt = NULL;
    bool http = false, stdio = false;
    if (napi_get_cb_info(env, info, &argc, args, &self, NULL) != napi_ok || argc ||
        napi_check_object_type_tag(env, self, &MCP_ADMIN_ORIGINAL_HTTP_TAG, &http) != napi_ok ||
        napi_check_object_type_tag(env, self, &MCP_ADMIN_ORIGINAL_STDIO_TAG, &stdio) != napi_ok || (!http && !stdio) ||
        napi_unwrap(env, self, (void **)&receipt) != napi_ok || !receipt || receipt->env != env ||
        receipt->controller->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
        receipt->data.transport != (http ? CLIQ_MCP_ADMIN_ORIGINAL_HTTP : CLIQ_MCP_ADMIN_ORIGINAL_STDIO))
        return failure(env, "Invalid original MCP Admin current observation");
    return napi_create_buffer_copy(env, sizeof(receipt->data), &receipt->data, NULL, &result) == napi_ok ? result : NULL;
}
static bool mcp_admin_original_observe(struct controller *c, struct cliq_mcp_admin_input *input,
    const unsigned char *bytes, size_t size, const struct cliq_mcp_admin_binding *binding, unsigned transport,
    struct cliq_mcp_admin_original_retirement *out) {
    struct cliq_mcp_admin_original_source source;
    if (c->creator_pid != getpid() || syscall(SYS_gettid) != getpid() || !c->closed || !c->cleanup_done || !c->reaped ||
        !c->controller_leaf_retired || c->retirement_failed || atomic_load(&native_retirement_failed) ||
        !input || input->abi_version != CLIQ_MCP_ADMIN_INPUT_ABI || input->creator_pid != getpid() || input->environment != c->env ||
        !input->assert_retired_snapshot || !binding->owner_epoch || binding->owner_epoch > UINT64_C(9007199254740991) ||
        !cliq_mcp_stdio_text(binding->supervisor, sizeof(binding->supervisor)) ||
        !cliq_mcp_admin_original_source(bytes, size, transport, &source) ||
        source.binding.supervisor_pid != getpid() || memcmp(&source.binding, &input->binding, sizeof(input->binding)) ||
        source.controller_pid != c->pid || strcmp(source.controller_token, c->token) || strcmp(source.controller_leaf, c->leaf_name) ||
        !mcp_admin_original_directory(&source.root, &c->root_identity) || !mcp_admin_original_directory(&source.parent, &c->parent_identity) ||
        !mcp_admin_original_directory(&source.leaf, &c->leaf_identity) || !input->assert_retired_snapshot(input, bytes, size)) return false;
    struct process_sample observer;
    bool valid = sample_process(c, getpid(), &observer, false) && !observer.absent &&
        !strcmp(observer.token, source.binding.supervisor_start_token);
    int root = valid ? open(c->root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1, parent = -1;
    struct stat held, named;
    valid = valid && root >= 0 && private_cgroup(root, &held) && same_directory(&c->root_identity, &held) &&
        !lstat(c->root_path, &named) && same_directory(&c->root_identity, &named);
    if (valid) parent = openat(root, "controllers", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    valid = valid && parent >= 0 && private_cgroup(parent, &held) && same_directory(&c->parent_identity, &held) &&
        !fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) && same_directory(&c->parent_identity, &named) &&
        fstatat(parent, c->leaf_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(root, source.last.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    int64_t pids[] = {source.controller_pid, source.last.monitor_pid, source.last.namespace_init_pid, source.last.pid};
    const char *tokens[] = {source.controller_token, source.last.monitor_start_token, source.last.init_native_start_token, source.last.start_token};
    for (size_t i = 0; valid && i < sizeof(pids) / sizeof(pids[0]); i++) {
        if (!pids[i] && !*tokens[i]) continue;
        struct process_sample process;
        valid = pids[i] > 0 && pids[i] <= INT32_MAX && *tokens[i] && sample_process(c, (pid_t)pids[i], &process, false) &&
            (process.absent || strcmp(process.token, tokens[i]));
    }
    valid = valid && !fstat(root, &held) && same_directory(&c->root_identity, &held) &&
        !lstat(c->root_path, &named) && same_directory(&c->root_identity, &named) &&
        !fstat(parent, &held) && same_directory(&c->parent_identity, &held) &&
        !fstatat(root, "controllers", &named, AT_SYMLINK_NOFOLLOW) && same_directory(&c->parent_identity, &named) &&
        fstatat(parent, c->leaf_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(root, source.last.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    bool parent_closed = retire_descriptor(&parent), root_closed = retire_descriptor(&root);
    if (!parent_closed || !root_closed) { c->retirement_failed = true; valid = false; }
    valid = valid && input->assert_retired_snapshot(input, bytes, size);
    struct timespec now;
    if (!valid || clock_gettime(CLOCK_REALTIME, &now) || now.tv_sec < 0 || (uint64_t)now.tv_sec > UINT64_C(9007199254740)) return false;
    uint64_t observed = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    if (!observed || observed > UINT64_C(9007199254740991) || observed < source.last.observed_at_ms) return false;
    memset(out, 0, sizeof(*out)); out->magic = CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_MAGIC; out->version = 1; out->transport = transport;
    out->original_bytes = size; out->observer_epoch = binding->owner_epoch; out->observed_at_ms = observed; out->observer_pid = getpid();
    memcpy(out->observer_supervisor, binding->supervisor, strnlen(binding->supervisor, sizeof(out->observer_supervisor)));
    memcpy(out->observer_token, observer.token, strlen(observer.token)); out->controller_root = source.root;
    cliq_mcp_admin_hash(bytes, size, out->original_digest);
    cliq_mcp_admin_hash(out, offsetof(struct cliq_mcp_admin_original_retirement, digest), out->digest);
    struct cliq_mcp_admin_original_retirement checked;
    return cliq_mcp_admin_original_retirement_bytes((unsigned char *)out, sizeof(*out), bytes, size, &checked, &source);
}
static napi_value mcp_admin_original_value(napi_env env, napi_value self, void *scope, struct controller *c,
    struct cliq_mcp_admin_input *input, const unsigned char *bytes, size_t size,
    const struct cliq_mcp_admin_binding *binding, unsigned transport) {
    struct mcp_admin_original_receipt *receipt = calloc(1, sizeof(*receipt)); napi_value result;
    if (!receipt) return failure(env, "MCP Admin current observation allocation unavailable");
    receipt->scope = scope; receipt->controller = c; receipt->env = env;
    const napi_property_descriptor methods[] = {{"copyData", NULL, mcp_admin_original_copy, NULL, NULL, NULL, napi_default, NULL}};
    if (!mcp_admin_original_observe(c, input, bytes, size, binding, transport, &receipt->data) || napi_create_object(env, &result) != napi_ok ||
        napi_define_properties(env, result, 1, methods) != napi_ok || napi_type_tag_object(env, result, mcp_admin_original_tag(transport)) != napi_ok ||
        napi_create_reference(env, self, 1, &receipt->original) != napi_ok ||
        napi_wrap(env, result, receipt, mcp_admin_original_finalize, NULL, NULL) != napi_ok) {
        if (receipt->original) napi_delete_reference(env, receipt->original);
        free(receipt); return failure(env, "MCP Admin original retirement cannot be freshly observed");
    }
    napi_object_freeze(env, result); return result;
}
static napi_value mcp_admin_original_assert(napi_env env, void *scope, struct controller *c, napi_value value, unsigned transport) {
    struct mcp_admin_original_receipt *receipt = NULL;
    if (!tagged(env, value, mcp_admin_original_tag(transport), (void **)&receipt) || !receipt || receipt->scope != scope ||
        receipt->controller != c || receipt->env != env || c->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
        c->retirement_failed || atomic_load(&native_retirement_failed) || !c->closed || !c->cleanup_done || !c->reaped)
        return failure(env, "MCP Admin current observation is not this exact retired original scope");
    return undefined(env);
}
#endif
