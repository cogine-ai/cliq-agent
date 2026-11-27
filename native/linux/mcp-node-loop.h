#ifndef CLIQ_MCP_NODE_LOOP_H
#define CLIQ_MCP_NODE_LOOP_H
#include <stdbool.h>
#include <node_api.h>

/* Node gives each addon its own napi_env. A tagged, live peer passed between
 * addons must still belong to this Node event loop. Keep exact napi_env
 * checks whenever an addon operates on one of its own receivers. */
static inline bool cliq_mcp_same_node_loop(napi_env current, napi_env peer) {
    struct uv_loop_s *current_loop = NULL, *peer_loop = NULL;
    return current && peer &&
        napi_get_uv_event_loop(current, &current_loop) == napi_ok && current_loop &&
        napi_get_uv_event_loop(peer, &peer_loop) == napi_ok && peer_loop == current_loop;
}
#endif
