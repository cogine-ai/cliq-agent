#ifndef CLIQ_PREPARATION_FAILURE_RELAY_H
#define CLIQ_PREPARATION_FAILURE_RELAY_H

#include "preparation-git-protocol.h"
#include <sys/wait.h>

/* Diagnostic data only: the real namespace caller supplies its kernel-read
 * original UID after validating the fixed same-attempt namespace packet.
 * Nothing here produces output, a successful result or a death receipt. */
static inline uint32_t cliq_preparation_failure_packet_for_uid(const struct cliq_worker_packet *expected,
    const struct cliq_worker_packet *response, size_t count, uint64_t original_uid) {
    if (!expected->preparation_input_intent_ref[0] || count != 0 || response->command != CLIQ_SOURCE_RESULT ||
        !preparation_same_attempt_for_uid(expected, response, original_uid) || !cliq_source_postready_failure_valid(response->status)) return 0;
    struct cliq_worker_packet canonical; memcpy(&canonical, expected, sizeof(canonical));
    canonical.command = CLIQ_SOURCE_RESULT; canonical.status = response->status;
    return memcmp(&canonical, response, sizeof(canonical)) == 0 ? response->status : 0;
}

/* Consume only the actual original producer's join and channel. In live code
 * this is PID1's child; the bounded component uses its own real fork/socket.
 * A diagnostic send can never convert exit70 into a successful namespace. */
static inline bool cliq_preparation_forward_joined_failure(pid_t child, int *producer_channel, int parent_channel,
    const struct cliq_worker_packet *expected, const struct cliq_worker_packet *response, size_t count, uint64_t original_uid) {
    if (child <= 0 || !producer_channel || *producer_channel < 0 ||
        !cliq_preparation_failure_packet_for_uid(expected, response, count, original_uid)) return false;
    int status = 0; pid_t joined;
    do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
    int held = *producer_channel; *producer_channel = -1;
    bool closed = close(held) == 0;
    return joined == child && WIFEXITED(status) && WEXITSTATUS(status) == 70 && closed &&
        cliq_send(parent_channel, response, NULL, 0);
}

#endif
