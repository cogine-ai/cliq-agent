#ifndef CLIQ_WORKER_COMMON_H
#define CLIQ_WORKER_COMMON_H

#include "worker-protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline bool cliq_hex_digest(const char *value) {
    if (strnlen(value, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) return false;
    }
    return true;
}

/* Never bound descriptor cleanup by the current RLIMIT_NOFILE: limits can
 * already be lower than inherited open descriptors. No weaker fallback. */
static inline bool cliq_close_range(unsigned int first, unsigned int last) {
#ifdef SYS_close_range
    return first > last || syscall(SYS_close_range, first, last, 0) == 0;
#else
    (void)first; (void)last; errno = ENOSYS; return false;
#endif
}

static inline bool cliq_send(int socket, const struct cliq_worker_packet *packet,
                      const int *fds, size_t count) {
    if (count > 5) { errno = EINVAL; return false; }
    struct iovec iov = { .iov_base = (void *)packet, .iov_len = sizeof(*packet) };
    char ancillary[CMSG_SPACE(5 * sizeof(int))];
    memset(ancillary, 0, sizeof(ancillary));
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (count != 0) {
        message.msg_control = ancillary;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(header), fds, count * sizeof(int));
    }
    ssize_t sent;
    do { sent = sendmsg(socket, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)sizeof(*packet);
}

static inline bool cliq_receive_flags(int socket, struct cliq_worker_packet *packet,
                         int fds[5], size_t *count, int flags) {
    *count = 0;
    struct iovec iov = { .iov_base = packet, .iov_len = sizeof(*packet) };
    char ancillary[CMSG_SPACE(5 * sizeof(int))];
    memset(ancillary, 0, sizeof(ancillary));
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary, .msg_controllen = sizeof(ancillary) };
    ssize_t received;
    do { received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC | flags); } while (received < 0 && errno == EINTR);
    if (received < 0) return false;
    bool ancillary_valid = true;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0) || (header->cmsg_len - CMSG_LEN(0)) % sizeof(int) != 0) {
            ancillary_valid = false; continue;
        }
        size_t descriptors = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *passed = (int *)CMSG_DATA(header);
        for (size_t i = 0; i < descriptors; i++) {
            if (*count < 5) fds[(*count)++] = passed[i]; else { ancillary_valid = false; close(passed[i]); }
        }
    }
    bool valid = ancillary_valid && received == (ssize_t)sizeof(*packet) &&
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
        packet->magic == CLIQ_WORKER_MAGIC && packet->version == CLIQ_WORKER_VERSION &&
        packet->nonce[sizeof(packet->nonce) - 1] == '\0' && packet->activation_nonce[sizeof(packet->activation_nonce) - 1] == '\0' &&
        packet->start_token[sizeof(packet->start_token) - 1] == '\0' && packet->init_start_token[sizeof(packet->init_start_token) - 1] == '\0' &&
        packet->init_native_start_token[sizeof(packet->init_native_start_token) - 1] == '\0' &&
        packet->monitor_start_token[sizeof(packet->monitor_start_token) - 1] == '\0' &&
        packet->subreaper_start_token[sizeof(packet->subreaper_start_token) - 1] == '\0' &&
        packet->cgroup_name[sizeof(packet->cgroup_name) - 1] == '\0' &&
        packet->executable_path[sizeof(packet->executable_path) - 1] == '\0' && packet->relative_path[sizeof(packet->relative_path) - 1] == '\0';
    if (!valid) { for (size_t i = 0; i < *count; i++) close(fds[i]); *count = 0; errno = received == 0 ? EPIPE : EPROTO; }
    return valid;
}

static inline bool cliq_receive(int socket, struct cliq_worker_packet *packet, int fds[5], size_t *count) {
    return cliq_receive_flags(socket, packet, fds, count, 0);
}

/* Resolve a host process to its PID in the innermost namespace. Start ticks
 * alone are not unique among siblings created within the same clock tick. */
static inline bool cliq_namespace_pid(pid_t pid, pid_t *output) {
    char filename[64], buffer[8192];
    snprintf(filename, sizeof(filename), "/proc/%ld/status", (long)pid);
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1); close(fd);
    if (bytes <= 0 || (size_t)bytes == sizeof(buffer) - 1) return false;
    buffer[bytes] = '\0';
    char *cursor = strstr(buffer, "\nNSpid:\t");
    if (!cursor) return false;
    cursor += 8; long last = 0;
    while (*cursor && *cursor != '\n') {
        while (*cursor == ' ' || *cursor == '\t') cursor++;
        if (*cursor == '\n') break;
        long value = 0; bool digit = false;
        while (*cursor >= '0' && *cursor <= '9') {
            digit = true; value = value * 10 + *cursor++ - '0';
            if (value > INT32_MAX) return false;
        }
        if (!digit || value <= 0 || (*cursor != '\t' && *cursor != ' ' && *cursor != '\n')) return false;
        last = value;
    }
    if (last <= 0) return false;
    *output = (pid_t)last; return true;
}

/* Kernel mountinfo field 5 is the namespace-relative mount point, field 6
 * the per-mount flags. The physical generation and the RO/RW view are both
 * observed, not inferred from a caller's JSON or a successful helper spawn. */
static inline bool cliq_generation_mount(pid_t pid, uint64_t device, uint64_t inode, bool readonly) {
    char filename[96]; struct stat physical;
    snprintf(filename, sizeof(filename), "/proc/%ld/root/work", (long)pid);
    if (stat(filename, &physical) != 0 || !S_ISDIR(physical.st_mode) ||
        (uint64_t)physical.st_dev != device || (uint64_t)physical.st_ino != inode) return false;
    snprintf(filename, sizeof(filename), "/proc/%ld/mountinfo", (long)pid);
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    char buffer[65536]; ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1); close(fd);
    if (bytes <= 0 || (size_t)bytes == sizeof(buffer) - 1) return false;
    buffer[bytes] = '\0'; bool matched = false;
    char *line = buffer;
    while (*line) {
        char *next = strchr(line, '\n'); if (!next) return false; *next++ = '\0';
        char *field = line;
        for (unsigned int index = 1; index < 5; index++) {
            field = strchr(field, ' '); if (!field) return false; field++;
        }
        char *options = strchr(field, ' '); if (!options) return false; *options++ = '\0';
        char *end = strchr(options, ' '); if (!end) return false; *end = '\0';
        if (strcmp(field, "/work") == 0) {
            if (matched) return false;
            const char *expected = readonly ? "ro" : "rw";
            if (strncmp(options, expected, 2) != 0 || (options[2] != '\0' && options[2] != ',')) return false;
            matched = true;
        }
        line = next;
    }
    return matched;
}

static inline struct cliq_worker_packet cliq_packet(uint32_t command) {
    struct cliq_worker_packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.magic = CLIQ_WORKER_MAGIC;
    packet.version = CLIQ_WORKER_VERSION;
    packet.command = command;
    return packet;
}

/* /proc stat field 22, not a PID-shaped caller string. */
static inline bool cliq_process_token(pid_t pid, char output[CLIQ_WORKER_TOKEN_BYTES]) {
    char filename[64], buffer[4096];
    int length = snprintf(filename, sizeof(filename), "/proc/%ld/stat", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(filename)) return false;
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes <= 0) return false;
    buffer[bytes] = '\0';
    char *cursor = strrchr(buffer, ')');
    if (cursor == NULL || cursor[1] != ' ') return false;
    cursor += 2;
    for (int field = 3; field < 22; field++) {
        cursor = strchr(cursor, ' ');
        if (cursor == NULL) return false;
        cursor++;
    }
    char *end = strchr(cursor, ' ');
    if (end == NULL || end == cursor || (size_t)(end - cursor) >= CLIQ_WORKER_TOKEN_BYTES) return false;
    for (char *digit = cursor; digit < end; digit++) if (*digit < '0' || *digit > '9') return false;
    size_t digits = (size_t)(end - cursor);
    if (digits > 32) return false;
    return snprintf(output, CLIQ_WORKER_TOKEN_BYTES, "linux-proc-start-ticks:%.*s", (int)digits, cursor) > 0;
}

#endif
