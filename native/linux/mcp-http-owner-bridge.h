#ifndef CLIQ_MCP_HTTP_OWNER_BRIDGE_H
#define CLIQ_MCP_HTTP_OWNER_BRIDGE_H
/* Private same-process friend ABI. Only the selected worker image publishes
 * the peer table. Tags, ABI, PID, environment and main thread precede unwrap;
 * JS never chooses a descriptor, callback, pointer or process observation. */
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "worker-protocol.h"
#define CLIQ_MCP_OWNER_ABI 1u
#define CLIQ_MCP_ID_BYTES 257u
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_MCP_ADMIN_PEER_TAG = { UINT64_C(0xc869f775b3fe4db8), UINT64_C(0xb30a9c41f01952bc) };
#endif
struct cliq_mcp_admin_binding {
    char operation[CLIQ_MCP_ID_BYTES], principal[CLIQ_MCP_ID_BYTES], method[32], dispatch[CLIQ_MCP_ID_BYTES], supervisor[CLIQ_MCP_ID_BYTES];
    char control_digest[65], target_ref[65], target_digest[65], core_ref[65], core_digest[65], probe_digest[65];
    char containment_ref[65], plan_ref[65], plan_digest[65], spec_ref[65], spec_digest[65];
    uint64_t attempt, owner_epoch, deadline_ms;
};
struct cliq_mcp_run_binding {
    char run[CLIQ_MCP_ID_BYTES], op[CLIQ_MCP_ID_BYTES], dispatch[CLIQ_MCP_ID_BYTES], supervisor[CLIQ_MCP_ID_BYTES];
    char batch_item[CLIQ_MCP_ID_BYTES], call[CLIQ_MCP_ID_BYTES], worker_launch[CLIQ_MCP_ID_BYTES];
    char request_ref[65], request_digest[65], target_ref[65], target_digest[65], grant_ref[65], grant_digest[65];
    char registry_ref[65], manifest_digest[65], tool_digest[65], token_digest[65];
    uint64_t attempt, sequence, call_index, owner_epoch, lease_epoch, deadline_ms;
};
struct cliq_mcp_fixed_frame_view { uint32_t phase; const unsigned char *bytes; size_t size; char digest[65]; };
struct cliq_mcp_screened_message_view { uint32_t phase; const unsigned char *bytes; size_t size; bool acknowledgement; };
struct cliq_mcp_admin_observation {
    bool death_joined, output_acknowledged, output_custody_retired;
    struct cliq_worker_packet packet;
};
struct cliq_mcp_admin_peer {
    void *context;
    int (*release_recipe)(void *, const struct cliq_mcp_admin_binding *);
    int (*poll_fixed_frame)(void *, struct cliq_mcp_fixed_frame_view *);
    int (*deliver_screened_message)(void *, const struct cliq_mcp_screened_message_view *);
    int (*cancel)(void *);
    int (*poll_joined)(void *, struct cliq_mcp_admin_observation *);
    int (*begin_output_ack)(void *);
    int (*poll_output_ack)(void *);
    void (*release)(void *);
};
struct cliq_mcp_admin_peer_handle {
    uint32_t abi_version; pid_t creator_pid; void *environment;
    struct cliq_mcp_admin_binding binding;
    struct cliq_mcp_admin_peer peer;
    bool (*assert_current)(struct cliq_mcp_admin_peer_handle *);
    bool borrowed;
};
#endif
