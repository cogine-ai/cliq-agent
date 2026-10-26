#ifndef CLIQ_BUILTIN_RESULT_ACK_H
#define CLIQ_BUILTIN_RESULT_ACK_H

#include "worker-common.h"

/* Closed data/FD helpers only: these do not establish a completed effect,
 * process death, SQL settlement or permission to execute. The original
 * native scope independently gates their only production consumer. */
static inline bool cliq_builtin_result_ack_valid(const struct cliq_worker_packet *packet) {
    if (packet->scope == 0 || packet->scope >= CLIQ_WORKER_MAX_SCOPES || packet->parent == 0 ||
        packet->parent >= CLIQ_WORKER_MAX_SCOPES || packet->parent == packet->scope ||
        packet->observed_at_ms == 0 || packet->observed_at_ms > UINT64_C(9007199254740991) ||
        strnlen(packet->nonce, sizeof(packet->nonce)) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!((packet->nonce[i] >= '0' && packet->nonce[i] <= '9') ||
        (packet->nonce[i] >= 'a' && packet->nonce[i] <= 'f'))) return false;
    struct cliq_worker_packet canonical = cliq_packet(CLIQ_ACK_BUILTIN_RESULT);
    canonical.scope = packet->scope; canonical.parent = packet->parent;
    canonical.observed_at_ms = packet->observed_at_ms; memcpy(canonical.nonce, packet->nonce, 64);
    return memcmp(&canonical, packet, sizeof(canonical)) == 0;
}
static inline bool cliq_builtin_result_ack_same(const struct cliq_worker_packet *packet,
    unsigned int scope, unsigned int parent, const char nonce[65], uint64_t observed_at_ms) {
    return cliq_builtin_result_ack_valid(packet) && packet->scope == scope && packet->parent == parent &&
        packet->observed_at_ms == observed_at_ms && memcmp(packet->nonce, nonce, 65) == 0;
}
/* Both original slots are consumed before either close. Attempt every
 * close once; uncertainty never permits reuse, retry on a recycled FD, or a
 * successful acknowledgement. No caller can supply a path or descriptor. */
static inline bool cliq_builtin_result_retire_outputs(int *output, int *diagnostic) {
    if (!output || !diagnostic || output == diagnostic || *output < 0 || *diagnostic < 0 || *output == *diagnostic) return false;
    int first = *output, second = *diagnostic; *output = *diagnostic = -1;
    bool first_closed = close(first) == 0, second_closed = close(second) == 0;
    return first_closed && second_closed;
}
#endif
