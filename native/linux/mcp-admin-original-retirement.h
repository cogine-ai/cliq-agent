#ifndef CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_H
#define CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_H
/* Fixed read-only current observation, separate from the original birth and
 * kind9. Pure decoding never grants a scope or process/filesystem authority. */
#include "mcp-stdio-protocol.h"
#define CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_MAGIC UINT32_C(0x434d4f52)
enum cliq_mcp_admin_original_transport { CLIQ_MCP_ADMIN_ORIGINAL_HTTP = 1, CLIQ_MCP_ADMIN_ORIGINAL_STDIO = 2 };
struct cliq_mcp_admin_original_source {
    struct cliq_mcp_admin_birth binding;
    struct cliq_mcp_admin_directory root, parent, leaf;
    int64_t controller_pid;
    char controller_token[192], controller_leaf[64];
    struct cliq_worker_packet last;
};
struct cliq_mcp_admin_original_retirement {
    uint32_t magic, version, transport;
    uint64_t original_bytes, observer_epoch, observed_at_ms;
    int64_t observer_pid;
    char observer_supervisor[257], observer_token[192];
    struct cliq_mcp_admin_directory controller_root;
    unsigned char original_digest[32], digest[32];
};
static inline bool cliq_mcp_admin_original_source(const unsigned char *bytes, size_t size, unsigned transport,
    struct cliq_mcp_admin_original_source *out) {
    memset(out, 0, sizeof(*out));
    if (transport == CLIQ_MCP_ADMIN_ORIGINAL_HTTP) {
        struct cliq_mcp_admin_history history;
        if (!cliq_mcp_admin_history_bytes(bytes, size, &history) || !history.count || history.last.kind != 9 ||
            history.last.packet.populated || history.last.packet.remaining_descendants ||
            (history.ready.kind == 5 && history.last.packet.init_reaped != 1)) return false;
        out->binding = history.header; out->root = history.first.controller_root;
        out->parent = history.first.controller_parent; out->leaf = history.first.controller_leaf;
        out->controller_pid = history.first.controller_pid; out->last = history.last.packet;
        memcpy(out->controller_token, history.first.controller_start_token, sizeof(out->controller_token));
        memcpy(out->controller_leaf, history.first.controller_leaf_name, sizeof(out->controller_leaf));
    } else if (transport == CLIQ_MCP_ADMIN_ORIGINAL_STDIO) {
        struct cliq_mcp_stdio_history history;
        if (!cliq_mcp_stdio_history_bytes(bytes, size, &history) || history.purpose != CLIQ_MCP_STDIO_ADMIN || !history.count ||
            history.last.kind != 9 || history.last.packet.populated || history.last.packet.remaining_descendants ||
            !history.last.packet.stdio_owner_drained || (history.ready.kind == 5 && history.last.packet.init_reaped != 1)) return false;
        out->binding = history.header.admin; out->root = history.first.controller_root;
        out->parent = history.first.controller_parent; out->leaf = history.first.controller_leaf;
        out->controller_pid = history.first.controller_pid; out->last = history.last.packet;
        memcpy(out->controller_token, history.first.controller_start_token, sizeof(out->controller_token));
        memcpy(out->controller_leaf, history.first.controller_leaf_name, sizeof(out->controller_leaf));
    } else return false;
    return out->controller_pid > 0 && out->controller_pid <= INT32_MAX && out->root.inode && out->parent.inode && out->leaf.inode &&
        cliq_mcp_stdio_text(out->controller_token, sizeof(out->controller_token)) &&
        cliq_mcp_stdio_text(out->controller_leaf, sizeof(out->controller_leaf)) && !strchr(out->controller_leaf, '/');
}
static inline bool cliq_mcp_admin_original_retirement_bytes(const unsigned char *bytes, size_t size,
    const unsigned char *original, size_t original_size, struct cliq_mcp_admin_original_retirement *out,
    struct cliq_mcp_admin_original_source *source) {
    if (!bytes || size != sizeof(*out) || !original) return false;
    memcpy(out, bytes, sizeof(*out));
    if (out->magic != CLIQ_MCP_ADMIN_ORIGINAL_RETIREMENT_MAGIC || out->version != 1 || out->original_bytes != original_size ||
        !out->observer_epoch || out->observer_epoch > UINT64_C(9007199254740991) ||
        !out->observed_at_ms || out->observed_at_ms > UINT64_C(9007199254740991) ||
        !cliq_mcp_stdio_text(out->observer_supervisor, sizeof(out->observer_supervisor)) ||
        !cliq_mcp_stdio_text(out->observer_token, sizeof(out->observer_token)) ||
        !cliq_mcp_admin_original_source(original, original_size, out->transport, source) ||
        out->observer_pid != source->binding.supervisor_pid || strcmp(out->observer_token, source->binding.supervisor_start_token) ||
        memcmp(&out->controller_root, &source->root, sizeof(source->root)) ||
        out->observed_at_ms < source->last.observed_at_ms) return false;
    unsigned char digest[32]; cliq_mcp_admin_hash(original, original_size, digest);
    if (memcmp(digest, out->original_digest, 32)) return false;
    cliq_mcp_admin_hash(out, offsetof(struct cliq_mcp_admin_original_retirement, digest), digest);
    if (memcmp(digest, out->digest, 32)) return false;
    struct cliq_mcp_admin_original_retirement canonical = {0};
    canonical.magic = out->magic; canonical.version = out->version; canonical.transport = out->transport;
    canonical.original_bytes = out->original_bytes; canonical.observer_epoch = out->observer_epoch;
    canonical.observed_at_ms = out->observed_at_ms; canonical.observer_pid = out->observer_pid;
    canonical.controller_root = out->controller_root;
    memcpy(canonical.observer_supervisor, out->observer_supervisor, strlen(out->observer_supervisor));
    memcpy(canonical.observer_token, out->observer_token, strlen(out->observer_token));
    memcpy(canonical.original_digest, out->original_digest, 32); memcpy(canonical.digest, out->digest, 32);
    return !memcmp(&canonical, out, sizeof(canonical));
}
#endif
