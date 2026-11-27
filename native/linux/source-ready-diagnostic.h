#ifndef CLIQ_SOURCE_READY_DIAGNOSTIC_H
#define CLIQ_SOURCE_READY_DIAGNOSTIC_H

#include "worker-protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fixed private pre-READY diagnostics only. These bytes never establish
 * request validity, process identity, release, readiness or retirement. */
#define CLIQ_SOURCE_READY_DIAGNOSTIC_PREFIX "CLIQ_SOURCE_READY_DIAG_V1:"
#define CLIQ_SOURCE_READY_DIAGNOSTIC_BYTES 512
struct cliq_source_ready_diagnostic {
    uint32_t stage, uid, gid, original_uid, map_observed, map_start, map_parent, map_count;
};
static inline bool source_diagnostic_uint(const unsigned char *bytes, size_t length, size_t *at, uint32_t *value) {
    size_t start = *at; uint32_t number = 0;
    while (*at < length && bytes[*at] >= '0' && bytes[*at] <= '9') {
        unsigned int digit = bytes[(*at)++] - '0';
        if (number > (UINT32_MAX - digit) / 10) return false;
        number = number * 10 + digit;
    }
    if (*at == start) return false;
    *value = number; return true;
}
/* Diagnostic parsing deliberately reports the actual single kernel record,
 * including an unexpected range. It is separate from the unchanged strict
 * production namespace-origin decoder and cannot authorize that mapping. */
static inline bool source_diagnostic_map(const unsigned char *bytes, size_t length, uint32_t fields[3]) {
    if (!bytes || !length || length > 255) return false;
    size_t at = 0;
    for (size_t i = 0; i < 3; i++) {
        while (at < length && (bytes[at] == ' ' || bytes[at] == '\t')) at++;
        if (!source_diagnostic_uint(bytes, length, &at, &fields[i]) ||
            (i < 2 && (at >= length || (bytes[at] != ' ' && bytes[at] != '\t')))) return false;
    }
    while (at < length && (bytes[at] == ' ' || bytes[at] == '\t')) at++;
    return at + 1 == length && bytes[at] == '\n';
}
static inline bool source_diagnostic_nonce(const char nonce[65]) {
    if (nonce[64]) return false;
    for (size_t i = 0; i < 64; i++) if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return false;
    return true;
}
static inline void source_ready_diagnostic_write(int fd, const struct cliq_worker_packet *request, uint32_t stage) {
    if (!source_diagnostic_nonce(request->nonce) || request->reservation_uid > UINT32_MAX || stage == 0 || stage > 9) return;
    struct cliq_source_ready_diagnostic data = { .stage = stage, .uid = geteuid(), .gid = getegid(), .original_uid = (uint32_t)request->reservation_uid };
    int map = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (map >= 0) {
        unsigned char bytes[256]; size_t used = 0; bool valid = true;
        while (used < sizeof(bytes)) {
            ssize_t got = read(map, bytes + used, sizeof(bytes) - used);
            if (got < 0 && errno == EINTR) continue;
            if (got < 0) { valid = false; break; }
            if (!got) break;
            used += (size_t)got;
        }
        if (close(map) != 0) valid = false;
        uint32_t fields[3];
        if (valid && source_diagnostic_map(bytes, used, fields)) {
            data.map_observed = 1; data.map_start = fields[0]; data.map_parent = fields[1]; data.map_count = fields[2];
        }
    }
    char bytes[CLIQ_SOURCE_READY_DIAGNOSTIC_BYTES];
    int count = snprintf(bytes, sizeof(bytes), CLIQ_SOURCE_READY_DIAGNOSTIC_PREFIX "%s:%u:%u:%u:%u:%u:%u:%u:%u\n", request->nonce,
        data.stage, data.uid, data.gid, data.original_uid, data.map_observed, data.map_start, data.map_parent, data.map_count);
    if (count <= 0 || (size_t)count >= sizeof(bytes)) return;
    size_t written = 0;
    while (written < (size_t)count) {
        ssize_t done = pwrite(fd, bytes + written, (size_t)count - written, (off_t)written);
        if (done < 0 && errno == EINTR) continue;
        if (done <= 0) return;
        written += (size_t)done;
    }
}
static inline bool source_ready_diagnostic_decode(const unsigned char *bytes, size_t length, const char nonce[65], struct cliq_source_ready_diagnostic *data) {
    const size_t prefix = sizeof(CLIQ_SOURCE_READY_DIAGNOSTIC_PREFIX) - 1;
    if (!bytes || !data || !source_diagnostic_nonce(nonce) || length > CLIQ_SOURCE_READY_DIAGNOSTIC_BYTES || length <= prefix + 65 ||
        memcmp(bytes, CLIQ_SOURCE_READY_DIAGNOSTIC_PREFIX, prefix) || memcmp(bytes + prefix, nonce, 64) || bytes[prefix + 64] != ':') return false;
    struct cliq_source_ready_diagnostic parsed = {0};
    uint32_t *fields[] = { &parsed.stage, &parsed.uid, &parsed.gid, &parsed.original_uid, &parsed.map_observed, &parsed.map_start, &parsed.map_parent, &parsed.map_count };
    size_t at = prefix + 65;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!source_diagnostic_uint(bytes, length, &at, fields[i]) || at >= length || bytes[at++] != (i == 7 ? '\n' : ':')) return false;
    }
    if (!parsed.stage || parsed.stage > 9 || parsed.map_observed > 1 ||
        (!parsed.map_observed && (parsed.map_start || parsed.map_parent || parsed.map_count))) return false;
    for (; at < length; at++) if (bytes[at]) return false;
    *data = parsed; return true;
}
static inline bool source_ready_diagnostic_read(int fd, const struct cliq_worker_packet *request, struct cliq_source_ready_diagnostic *data) {
    struct stat file;
    if (fd < 0 || fstat(fd, &file) != 0 || !S_ISREG(file.st_mode) || file.st_nlink != 0 || file.st_size < 0 ||
        (uint64_t)file.st_size > request->max_output_bytes) return false;
    unsigned char bytes[CLIQ_SOURCE_READY_DIAGNOSTIC_BYTES]; ssize_t count;
    do { count = pread(fd, bytes, sizeof(bytes), 0); } while (count < 0 && errno == EINTR);
    return count > 0 && source_ready_diagnostic_decode(bytes, (size_t)count, request->nonce, data) && data->original_uid == request->reservation_uid;
}
#endif
