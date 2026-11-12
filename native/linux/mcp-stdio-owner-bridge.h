#ifndef CLIQ_MCP_STDIO_OWNER_BRIDGE_H
#define CLIQ_MCP_STDIO_OWNER_BRIDGE_H
/* Private same-process ABI between the distinct signed stdio owner and the
 * fixed worker image. These pointers are never reconstructed from JS data. */
#include "mcp-stdio-protocol.h"
#include "mcp-http-owner-bridge.h"
#define CLIQ_MCP_STDIO_OWNER_ABI 3u
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_MCP_STDIO_ADMIN_RECIPE_TAG = {UINT64_C(0xc5c315e54f214693), UINT64_C(0xa73106c84d2291f7)};
static const napi_type_tag CLIQ_MCP_STDIO_RUN_RECIPE_TAG = {UINT64_C(0xf86b203a75c84901), UINT64_C(0x89b7d14d2a33e6c0)};
static const napi_type_tag CLIQ_MCP_STDIO_ADMIN_PEER_TAG = {UINT64_C(0xbcd04b9749dc7c0d), UINT64_C(0x1930f0c83cf159d3)};
static const napi_type_tag CLIQ_MCP_STDIO_RUN_PEER_TAG = {UINT64_C(0x7362212a70459936), UINT64_C(0x35bc3fdf7ee0533c)};
static const napi_type_tag CLIQ_MCP_STDIO_RECOVERY_RECIPE_TAG = {UINT64_C(0x05247ea5b88b40eb), UINT64_C(0xad45add924031bf7)};
static const napi_type_tag CLIQ_MCP_STDIO_RECOVERY_PEER_TAG = {UINT64_C(0x4f409fba7e8af15a), UINT64_C(0x200a2d09f08af744)};
static const napi_type_tag CLIQ_MCP_STDIO_SERVER_TAG = {UINT64_C(0x2d78569810374d63), UINT64_C(0xa9476ae18b7fd305)};
#endif
struct cliq_mcp_stdio_launch_binding {
    unsigned purpose;
    struct cliq_mcp_admin_binding admin;
    struct cliq_mcp_stdio_run_identity run;
    struct cliq_mcp_stdio_recovery_identity recovery;
    char nonce[65], dispatch[257], token_digest[65];
    uint64_t sequence;
};
struct cliq_mcp_stdio_call_binding {
    struct cliq_mcp_stdio_launch_binding launch;
    uint64_t attempt, sequence;
    char op[257], dispatch[257], request_ref[65], request_digest[65], target_ref[65], target_digest[65];
    char grant_ref[65], grant_digest[65], tool_digest[65], instance_ref[65], instance_digest[65], token_digest[65];
};
struct cliq_mcp_stdio_owner_progress {
    unsigned phase;
    bool protocol_complete, effect_released, status_released, response_refused, owner_drained;
};
static inline bool cliq_mcp_stdio_release_flags_valid(unsigned purpose, bool effect, bool status) {
    return purpose == CLIQ_MCP_STDIO_ADMIN ? !effect && !status :
        purpose == CLIQ_MCP_STDIO_RUN ? !status : purpose == CLIQ_MCP_STDIO_RECOVERY ? !effect : false;
}
struct cliq_mcp_stdio_peer;
struct cliq_mcp_stdio_server_image {
    uint32_t abi_version;
    pid_t creator_pid;
    void *environment;
    int fd;
    uint64_t byte_count;
    char digest[65];
};
struct cliq_mcp_stdio_recipe {
    uint32_t abi_version;
    unsigned purpose;
    pid_t creator_pid;
    void *environment, *owner;
    int fd;
    unsigned char *bytes;
    size_t size;
    char digest[65];
    struct cliq_mcp_stdio_recipe_header header;
    bool consumed;
    bool (*register_peer)(struct cliq_mcp_stdio_recipe *, struct cliq_mcp_stdio_peer *, void *);
    bool (*owner_value)(struct cliq_mcp_stdio_recipe *, void **);
};
struct cliq_mcp_stdio_peer {
    uint32_t abi_version;
    unsigned purpose;
    pid_t creator_pid;
    void *environment, *context;
    struct cliq_mcp_stdio_recipe *recipe;
    atomic_bool revoked, io_joined, physical_joined, output_retired;
    /* Local FD + controller cleanup task only. Never a successful lifecycle,
     * output ACK, complete capture or all-descendant death observation. */
    atomic_bool operation_closed;
    bool (*assert_current)(struct cliq_mcp_stdio_peer *);
    bool (*bind_launch)(struct cliq_mcp_stdio_peer *, const struct cliq_mcp_stdio_launch_binding *);
    int (*release_exec)(struct cliq_mcp_stdio_peer *);
    int (*operation_fd)(struct cliq_mcp_stdio_peer *);
    int (*cancel)(struct cliq_mcp_stdio_peer *, bool abort_io);
    int (*progress)(struct cliq_mcp_stdio_peer *, const struct cliq_mcp_stdio_owner_progress *);
};
#endif
