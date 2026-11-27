#ifndef CLIQ_VERIFIER_SETUP_H
#define CLIQ_VERIFIER_SETUP_H

#include "worker-protocol.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

enum cliq_verifier_setup_stage {
    CLIQ_VERIFIER_SETUP_ENTRY = 1,
    CLIQ_VERIFIER_SETUP_NODE_CHECK = 2,
    CLIQ_VERIFIER_SETUP_NODE_BIND = 3,
    CLIQ_VERIFIER_SETUP_CONFINEMENT = 4,
    CLIQ_VERIFIER_SETUP_BEFORE_READY = 5
};

static inline struct cliq_worker_packet cliq_verifier_setup_packet(uint32_t scope, uint32_t stage) {
    struct cliq_worker_packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.magic = CLIQ_WORKER_MAGIC; packet.version = CLIQ_WORKER_VERSION;
    packet.command = CLIQ_VERIFIER_SETUP; packet.scope = scope; packet.setup.stage = stage;
    return packet;
}

static inline bool cliq_verifier_setup_accept(const struct cliq_worker_packet *packet, uint32_t scope, uint32_t *stage) {
    if (scope == 0 || scope >= CLIQ_WORKER_MAX_SCOPES ||
        *stage >= CLIQ_VERIFIER_SETUP_BEFORE_READY || packet->setup.stage != *stage + 1) return false;
    struct cliq_worker_packet expected = cliq_verifier_setup_packet(scope, packet->setup.stage);
    if (memcmp(packet, &expected, sizeof(expected)) != 0) return false;
    *stage = packet->setup.stage; return true;
}

static inline bool cliq_verifier_setup_empty(const struct cliq_verifier_setup_observation *observation) {
    const struct cliq_verifier_setup_observation empty = {0};
    return memcmp(observation, &empty, sizeof(empty)) == 0;
}

static inline bool cliq_verifier_setup_valid(const struct cliq_verifier_setup_observation *observation) {
    return observation->stage <= CLIQ_VERIFIER_SETUP_BEFORE_READY &&
        observation->poll_result >= -2 && observation->poll_result <= 1 && observation->poll_revents <= UINT16_MAX &&
        observation->poll_errno <= 4095 && (observation->poll_result == -1) == (observation->poll_errno != 0) &&
        (observation->poll_result == 1 || observation->poll_revents == 0);
}

static inline int64_t cliq_verifier_setup_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (uint64_t)(INT64_MAX - 999) / 1000 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* The caller retains one original absolute deadline across every progress
 * packet and EINTR. No diagnostic is consulted as execution authority. */
static inline bool cliq_verifier_setup_readable(int fd, int64_t started, int64_t deadline,
                                               struct cliq_verifier_setup_observation *observation,
                                               const volatile sig_atomic_t *cancelled) {
    observation->poll_result = -2; observation->poll_revents = 0; observation->poll_errno = 0;
    for (;;) {
        int64_t now = cliq_verifier_setup_now();
        if (now < 0 || now < started || deadline < started || deadline - started > INT_MAX) return false;
        uint64_t elapsed = (uint64_t)(now - started);
        observation->elapsed_ms = elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
        if ((cancelled && *cancelled) || now >= deadline) return false;
        struct pollfd observed = { .fd = fd, .events = POLLIN };
        int result = poll(&observed, 1, (int)(deadline - now));
        const int failure = result < 0 ? errno : 0;
        observation->poll_result = result;
        observation->poll_revents = (uint16_t)observed.revents;
        observation->poll_errno = (uint32_t)failure;
        now = cliq_verifier_setup_now();
        if (now < 0 || now < started) return false;
        elapsed = (uint64_t)(now - started);
        observation->elapsed_ms = elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
        if (result < 0 && failure == EINTR && !(cancelled && *cancelled)) continue;
        return now <= deadline && result == 1 && (observed.revents & POLLIN) != 0;
    }
}

#endif
