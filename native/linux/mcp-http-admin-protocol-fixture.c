/*
 * Focused real-C data fixture. Root may compile/run on exact Linux separately. No endpoint, Secret Service, SQLite,
 * process child or credential is used. This verifies the actual closed binary decoder, not resource death.
 */
#define _GNU_SOURCE
#include "mcp-http-admin-protocol.h"
#include <assert.h>
static void
fixture_digest(char digest[65])
{
    memset(digest, 'a', 64);
    digest[64] = '\0';
}
int
main(void)
{
    struct cliq_mcp_admin_birth header = {0};
    header.magic = CLIQ_MCP_ADMIN_BIRTH_MAGIC;
    header.version = 1;
    header.supervisor_pid = 123;
    strcpy(header.supervisor_start_token, "linux-proc-start-ticks:42");
    strcpy(header.operation, "admin-fixture");
    strcpy(header.principal, "principal-fixture");
    char           *digests[] = {header.nonce, header.target_ref, header.target_digest, header.core_ref, header.core_digest, header.plan_ref, header.plan_digest, header.spec_ref, header.spec_digest};
    for (size_t i = 0; i < sizeof(digests) / sizeof(*digests); i++)
        fixture_digest(digests[i]);
    cliq_mcp_admin_hash(&header, offsetof(struct cliq_mcp_admin_birth, digest), header.digest);
    struct cliq_mcp_admin_progress frame = {0};
    frame.magic = CLIQ_MCP_ADMIN_PROGRESS_MAGIC;
    frame.version = 1;
    frame.kind = 1;
    frame.ordinal = 1;
    frame.packet.magic = CLIQ_WORKER_MAGIC;
    frame.packet.version = CLIQ_WORKER_VERSION;
    frame.packet.command = CLIQ_MCP_ADMIN_RESERVE;
    frame.controller_pid = 456;
    strcpy(frame.controller_start_token, "linux-proc-start-ticks:84");
    strcpy(frame.controller_leaf_name, "controller-fixture");
    strcpy(frame.packet.admin_operation_id, header.operation);
    strcpy(frame.packet.admin_principal_id, header.principal);
    strcpy(frame.packet.nonce, header.nonce);
    memcpy(frame.previous, header.digest, 32);
    cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_admin_progress, digest), frame.digest);
    memcpy(frame.packet.admin_target_ref, header.target_ref, 65);
    memcpy(frame.packet.admin_target_digest, header.target_digest, 65);
    memcpy(frame.packet.admin_core_ref, header.core_ref, 65);
    memcpy(frame.packet.admin_core_digest, header.core_digest, 65);
    memcpy(frame.packet.plan_ref, header.plan_ref, 65);
    memcpy(frame.packet.admin_plan_digest, header.plan_digest, 65);
    memcpy(frame.packet.sandbox_launch_ref, header.spec_ref, 65);
    memcpy(frame.packet.sandbox_launch_digest, header.spec_digest, 65);
    cliq_mcp_admin_hash(&frame, offsetof(struct cliq_mcp_admin_progress, digest), frame.digest);
    size_t          size = sizeof(header) + sizeof(frame);
    unsigned char  *bytes = malloc(size);
    assert(bytes);
    memcpy(bytes, &header, sizeof(header));
    memcpy(bytes + sizeof(header), &frame, sizeof(frame));
    struct cliq_mcp_admin_history history;
    assert(cliq_mcp_admin_history_bytes(bytes, size, &history));
    assert(history.count == 1 && history.last.kind == 1);
    assert(!cliq_mcp_admin_history_bytes(bytes, size - 1, &history));
    bytes[sizeof(header) + offsetof(struct cliq_mcp_admin_progress, previous)] ^= 1;
    assert(!cliq_mcp_admin_history_bytes(bytes, size, &history));
    bytes[sizeof(header) + offsetof(struct cliq_mcp_admin_progress, previous)] ^= 1;
    struct cliq_mcp_admin_progress foreign = frame;
    strcpy(foreign.packet.admin_operation_id, "foreign-admin");
    cliq_mcp_admin_hash(&foreign, offsetof(struct cliq_mcp_admin_progress, digest), foreign.digest);
    memcpy(bytes + sizeof(header), &foreign, sizeof(foreign));
    assert(!cliq_mcp_admin_history_bytes(bytes, size, &history));
    memset(foreign.packet.admin_operation_id, 'x', sizeof(foreign.packet.admin_operation_id));
    cliq_mcp_admin_hash(&foreign, offsetof(struct cliq_mcp_admin_progress, digest), foreign.digest);
    memcpy(bytes + sizeof(header), &foreign, sizeof(foreign));
    assert(!cliq_mcp_admin_history_bytes(bytes, size, &history));
    struct cliq_worker_packet original = {0}, run = {0};
    strcpy(original.admin_operation_id, "admin-fixture");
    strcpy(original.nonce, header.nonce);
    strcpy(run.source_inspection_id, "source-is-not-admin");
    assert(!cliq_mcp_admin_packet_same(&original, &run));
    free(bytes);
    return 0;
}
