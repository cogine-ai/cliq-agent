/* Descriptor-bound native birth facts. Never a cached death receipt or Run state. */
#ifndef CLIQ_WORKER_RESERVATION_H
#define CLIQ_WORKER_RESERVATION_H
#include <sys/file.h>
#include "worker-sha256.h"

#define CLIQ_RESERVATION_BODY 2048U
#define CLIQ_RESERVATION_FOOTER 64U
#define CLIQ_RESERVATION_HEADER_END (CLIQ_RESERVATION_BODY + CLIQ_RESERVATION_FOOTER)
#define CLIQ_RESERVATION_FULL_END (2U * CLIQ_RESERVATION_BODY + 32U + 64U + 256U + 5U * CLIQ_RESERVATION_FOOTER)
enum cliq_reservation_fact { CLIQ_RESERVATION_BINDING = 1, CLIQ_RESERVATION_INTENT = 2,
    CLIQ_RESERVATION_CGROUP = 3, CLIQ_RESERVATION_MONITOR = 4, CLIQ_RESERVATION_READY = 5 };
struct cliq_reservation {
    int fd;
    struct cliq_worker_packet binding;
    size_t bytes;
};
static inline void reservation_u64(unsigned char **cursor, uint64_t value) {
    for (unsigned int i = 0; i < 8; i++) *(*cursor)++ = (unsigned char)(value >> (i * 8));
}
static inline uint64_t reservation_read_u64(const unsigned char **cursor) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; i++) value |= (uint64_t)*(*cursor)++ << (i * 8);
    return value;
}
static inline void reservation_text(unsigned char **cursor, const char *value, size_t width) {
    memcpy(*cursor, value, strnlen(value, width)); *cursor += width;
}
static inline bool reservation_read_text(const unsigned char **cursor, char *value, size_t width) {
    if (!memchr(*cursor, '\0', width)) return false;
    memcpy(value, *cursor, width); *cursor += width; return true;
}
static inline bool reservation_binding_valid(const struct cliq_worker_packet *packet) {
    return cliq_hex_digest(packet->plan_ref) && cliq_hex_digest(packet->sandbox_launch_ref) &&
        cliq_hex_digest(packet->sandbox_launch_digest) && cliq_hex_digest(packet->generation_ref) &&
        cliq_hex_digest(packet->nonce) && cliq_hex_digest(packet->activation_nonce) &&
        strnlen(packet->cgroup_name, sizeof(packet->cgroup_name)) == 69 &&
        memcmp(packet->cgroup_name, "cliq-", 5) == 0 && cliq_hex_digest(packet->cgroup_name + 5) &&
        packet->pid_namespace_reservation[0] != '\0' && packet->subreaper_pid > 0 &&
        packet->subreaper_start_token[0] != '\0' && packet->subreaper_pid <= INT32_MAX &&
        packet->reservation_uid <= UINT32_MAX && packet->reservation_inode != 0 &&
        packet->generation_inode != 0;
}
static inline bool reservation_same_binding(const struct cliq_worker_packet *left,
                                            const struct cliq_worker_packet *right) {
    return left->reservation_device == right->reservation_device && left->reservation_inode == right->reservation_inode &&
        left->reservation_uid == right->reservation_uid && left->generation_device == right->generation_device &&
        left->generation_inode == right->generation_inode && left->subreaper_pid == right->subreaper_pid &&
        strcmp(left->plan_ref, right->plan_ref) == 0 && strcmp(left->sandbox_launch_ref, right->sandbox_launch_ref) == 0 &&
        strcmp(left->sandbox_launch_digest, right->sandbox_launch_digest) == 0 &&
        strcmp(left->generation_ref, right->generation_ref) == 0 && strcmp(left->nonce, right->nonce) == 0 &&
        strcmp(left->activation_nonce, right->activation_nonce) == 0 && strcmp(left->cgroup_name, right->cgroup_name) == 0 &&
        strcmp(left->pid_namespace_reservation, right->pid_namespace_reservation) == 0 &&
        strcmp(left->subreaper_start_token, right->subreaper_start_token) == 0;
}
static inline void reservation_copy_binding(struct cliq_worker_packet *destination,
                                            const struct cliq_worker_packet *source) {
    destination->reservation_device = source->reservation_device; destination->reservation_inode = source->reservation_inode;
    destination->reservation_uid = source->reservation_uid; destination->generation_device = source->generation_device;
    destination->generation_inode = source->generation_inode; destination->subreaper_pid = source->subreaper_pid;
    memcpy(destination->plan_ref, source->plan_ref, sizeof(source->plan_ref));
    memcpy(destination->sandbox_launch_ref, source->sandbox_launch_ref, sizeof(source->sandbox_launch_ref));
    memcpy(destination->sandbox_launch_digest, source->sandbox_launch_digest, sizeof(source->sandbox_launch_digest));
    memcpy(destination->generation_ref, source->generation_ref, sizeof(source->generation_ref));
    memcpy(destination->nonce, source->nonce, sizeof(source->nonce));
    memcpy(destination->activation_nonce, source->activation_nonce, sizeof(source->activation_nonce));
    memcpy(destination->cgroup_name, source->cgroup_name, sizeof(source->cgroup_name));
    memcpy(destination->pid_namespace_reservation, source->pid_namespace_reservation, sizeof(source->pid_namespace_reservation));
    memcpy(destination->subreaper_start_token, source->subreaper_start_token, sizeof(source->subreaper_start_token));
}
/* Explicit little-endian fields and zero padding, not the C struct ABI. */
static inline void reservation_encode(unsigned char body[CLIQ_RESERVATION_BODY], const struct cliq_worker_packet *packet) {
    memset(body, 0, CLIQ_RESERVATION_BODY); memcpy(body, "CLIQWRB1", 8);
    unsigned char *cursor = body + 16;
#define R_NUMBER(name) reservation_u64(&cursor, (uint64_t)packet->name)
    R_NUMBER(reservation_device); R_NUMBER(reservation_inode); R_NUMBER(reservation_uid);
    R_NUMBER(generation_device); R_NUMBER(generation_inode); R_NUMBER(cgroup_device); R_NUMBER(cgroup_inode);
    R_NUMBER(pid_namespace_inode); R_NUMBER(pid); R_NUMBER(namespace_init_pid); R_NUMBER(monitor_pid); R_NUMBER(subreaper_pid);
#undef R_NUMBER
#define R_TEXT(name) reservation_text(&cursor, packet->name, sizeof(packet->name))
    R_TEXT(plan_ref); R_TEXT(sandbox_launch_ref); R_TEXT(sandbox_launch_digest); R_TEXT(generation_ref);
    R_TEXT(nonce); R_TEXT(activation_nonce); R_TEXT(cgroup_name); R_TEXT(pid_namespace_reservation);
    R_TEXT(start_token); R_TEXT(init_start_token); R_TEXT(init_native_start_token); R_TEXT(monitor_start_token); R_TEXT(subreaper_start_token);
#undef R_TEXT
}
static inline bool reservation_decode(const unsigned char body[CLIQ_RESERVATION_BODY], struct cliq_worker_packet *packet) {
    *packet = cliq_packet(CLIQ_BIND_RESERVATION);
    const unsigned char *cursor = body + 16;
#define R_NUMBER(name) packet->name = reservation_read_u64(&cursor)
    R_NUMBER(reservation_device); R_NUMBER(reservation_inode); R_NUMBER(reservation_uid);
    R_NUMBER(generation_device); R_NUMBER(generation_inode); R_NUMBER(cgroup_device); R_NUMBER(cgroup_inode);
    R_NUMBER(pid_namespace_inode); R_NUMBER(pid); R_NUMBER(namespace_init_pid); R_NUMBER(monitor_pid); R_NUMBER(subreaper_pid);
#undef R_NUMBER
#define R_TEXT(name) if (!reservation_read_text(&cursor, packet->name, sizeof(packet->name))) return false
    R_TEXT(plan_ref); R_TEXT(sandbox_launch_ref); R_TEXT(sandbox_launch_digest); R_TEXT(generation_ref);
    R_TEXT(nonce); R_TEXT(activation_nonce); R_TEXT(cgroup_name); R_TEXT(pid_namespace_reservation);
    R_TEXT(start_token); R_TEXT(init_start_token); R_TEXT(init_native_start_token); R_TEXT(monitor_start_token); R_TEXT(subreaper_start_token);
#undef R_TEXT
    unsigned char canonical[CLIQ_RESERVATION_BODY]; reservation_encode(canonical, packet);
    return memcmp(body, canonical, CLIQ_RESERVATION_BODY) == 0 && reservation_binding_valid(packet);
}
static inline bool reservation_birth_empty(const struct cliq_worker_packet *binding) {
    return binding->pid == 0 && binding->namespace_init_pid == 0 && binding->monitor_pid == 0 &&
        binding->cgroup_inode == 0 && binding->cgroup_device == 0 && binding->pid_namespace_inode == 0 &&
        !binding->start_token[0] && !binding->init_start_token[0] &&
        !binding->init_native_start_token[0] && !binding->monitor_start_token[0];
}
static inline bool reservation_file(int fd, const struct cliq_worker_packet *binding, struct stat *metadata) {
    return fstat(fd, metadata) == 0 && S_ISREG(metadata->st_mode) && metadata->st_uid == geteuid() &&
        (metadata->st_mode & 07777) == 0600 && metadata->st_nlink == 1 &&
        (uint64_t)metadata->st_dev == binding->reservation_device &&
        (uint64_t)metadata->st_ino == binding->reservation_inode && (uint64_t)metadata->st_uid == binding->reservation_uid;
}
static inline int reservation_independent(int source, const struct cliq_worker_packet *binding, bool writable) {
    struct stat original, reopened;
    if (!reservation_file(source, binding, &original)) return -1;
    char filename[64]; int length = snprintf(filename, sizeof(filename), "/proc/self/fd/%d", source);
    if (length < 0 || (size_t)length >= sizeof(filename)) return -1;
    int result = open(filename, (writable ? O_RDWR | O_APPEND : O_RDONLY) | O_CLOEXEC);
    if (result < 0) return -1;
    if (!reservation_file(result, binding, &reopened) || original.st_size != reopened.st_size ||
        flock(result, LOCK_EX | LOCK_NB) != 0) { close(result); return -1; }
    return result;
}
static inline bool reservation_write_all(int fd, const unsigned char *bytes, size_t count) {
    while (count != 0) {
        ssize_t written = write(fd, bytes, count);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        bytes += written; count -= (size_t)written;
    }
    return true;
}
static inline void reservation_footer(unsigned char footer[CLIQ_RESERVATION_FOOTER], uint64_t fact, uint64_t end,
                                      const unsigned char *body, size_t length) {
    memset(footer, 0, CLIQ_RESERVATION_FOOTER); memcpy(footer, "CLIQWRF1", 8);
    unsigned char *cursor = footer + 8; reservation_u64(&cursor, fact); reservation_u64(&cursor, end); reservation_u64(&cursor, ~end);
    struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, body, length); sha256_final(&hash, footer + 32);
}
static inline bool reservation_append(struct cliq_reservation *reservation, uint64_t fact,
                                     const unsigned char *body, size_t length) {
    struct stat metadata;
    if (!reservation_file(reservation->fd, &reservation->binding, &metadata) || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size != reservation->bytes || length > CLIQ_RESERVATION_BODY) return false;
    size_t end = reservation->bytes + length + CLIQ_RESERVATION_FOOTER;
    unsigned char footer[CLIQ_RESERVATION_FOOTER]; reservation_footer(footer, fact, end, body, length);
    /* Never create a process, release a barrier or forward READY before both
     * syncs succeed. Any interrupted suffix is rejected by the next owner. */
    if (!reservation_write_all(reservation->fd, body, length) || fsync(reservation->fd) != 0 ||
        !reservation_write_all(reservation->fd, footer, sizeof(footer)) || fsync(reservation->fd) != 0) return false;
    reservation->bytes = end; return true;
}
static inline bool reservation_pread_all(int fd, unsigned char *bytes, size_t length, off_t offset) {
    while (length != 0) {
        ssize_t count = pread(fd, bytes, length, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count; length -= (size_t)count; offset += count;
    }
    return true;
}
static inline bool reservation_frame(int fd, size_t *offset, uint64_t fact, unsigned char *body, size_t length) {
    unsigned char footer[CLIQ_RESERVATION_FOOTER], expected[CLIQ_RESERVATION_FOOTER];
    size_t end = *offset + length + sizeof(footer);
    if (!reservation_pread_all(fd, body, length, (off_t)*offset) ||
        !reservation_pread_all(fd, footer, sizeof(footer), (off_t)(*offset + length))) return false;
    reservation_footer(expected, fact, end, body, length);
    if (memcmp(footer, expected, sizeof(footer)) != 0) return false;
    *offset = end; return true;
}
static inline bool reservation_read(int fd, const struct cliq_worker_packet *expected,
                                   bool *attempted, struct cliq_worker_packet *actual) {
    struct stat before, after; size_t offset = 0; unsigned char body[CLIQ_RESERVATION_BODY];
    if (!reservation_file(fd, expected, &before) ||
        (before.st_size != (off_t)CLIQ_RESERVATION_HEADER_END && before.st_size != (off_t)CLIQ_RESERVATION_FULL_END) ||
        !reservation_frame(fd, &offset, CLIQ_RESERVATION_BINDING, body, sizeof(body))) return false;
    struct cliq_worker_packet binding;
    if (!reservation_decode(body, &binding) || !reservation_same_binding(&binding, expected) ||
        !reservation_birth_empty(&binding)) return false;
    *attempted = before.st_size == (off_t)CLIQ_RESERVATION_FULL_END; *actual = binding;
    if (*attempted) {
        if (!reservation_frame(fd, &offset, CLIQ_RESERVATION_INTENT, body, 32)) return false;
        unsigned char intent[32] = {0}; memcpy(intent, "CREATE1", 7);
        if (memcmp(body, intent, sizeof(intent)) != 0 ||
            !reservation_frame(fd, &offset, CLIQ_RESERVATION_CGROUP, body, 64)) return false;
        const unsigned char *cursor = body; uint64_t device = reservation_read_u64(&cursor), inode = reservation_read_u64(&cursor),
            uid = reservation_read_u64(&cursor), mode = reservation_read_u64(&cursor);
        unsigned char cgroup[64] = {0}; unsigned char *writer = cgroup;
        reservation_u64(&writer, device); reservation_u64(&writer, inode); reservation_u64(&writer, uid); reservation_u64(&writer, mode);
        if (memcmp(body, cgroup, sizeof(cgroup)) != 0 || inode == 0 || uid != expected->reservation_uid || mode > UINT32_MAX ||
            (mode & S_IFMT) != S_IFDIR || (mode & 0022) != 0 ||
            !reservation_frame(fd, &offset, CLIQ_RESERVATION_MONITOR, body, 256)) return false;
        cursor = body; uint64_t monitor = reservation_read_u64(&cursor); char token[CLIQ_WORKER_TOKEN_BYTES];
        if (!reservation_read_text(&cursor, token, sizeof(token)) || monitor == 0 || monitor > INT32_MAX || !token[0]) return false;
        unsigned char monitor_body[256] = {0}; writer = monitor_body; reservation_u64(&writer, monitor);
        reservation_text(&writer, token, sizeof(token));
        if (memcmp(body, monitor_body, sizeof(monitor_body)) != 0 ||
            !reservation_frame(fd, &offset, CLIQ_RESERVATION_READY, body, sizeof(body)) ||
            !reservation_decode(body, actual) || !reservation_same_binding(actual, expected) ||
            actual->cgroup_device != device || actual->cgroup_inode != inode ||
            actual->monitor_pid != (int64_t)monitor || strcmp(actual->monitor_start_token, token) != 0 ||
            actual->pid <= 0 || actual->pid > INT32_MAX || actual->namespace_init_pid <= 0 ||
            actual->namespace_init_pid > INT32_MAX || actual->pid_namespace_inode == 0 ||
            !actual->start_token[0] || !actual->init_start_token[0] || !actual->init_native_start_token[0]) return false;
    }
    return offset == (size_t)before.st_size && reservation_file(fd, expected, &after) && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}
#endif
