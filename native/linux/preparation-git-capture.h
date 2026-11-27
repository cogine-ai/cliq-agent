#ifndef CLIQ_PREPARATION_GIT_CAPTURE_H
#define CLIQ_PREPARATION_GIT_CAPTURE_H

#include "preparation-git-stream.h"
#include "source-git-materialize.h"

/* Only the already-exec'd fixed native producer calls this writer. Parent
 * processes retain no writable memfd alias, and no partial file is borrowed. */
struct cliq_preparation_capture { int files[CLIQ_PREPARATION_INPUT_FILES]; uint64_t bytes[CLIQ_PREPARATION_INPUT_FILES], total, pages;
    char digests[CLIQ_PREPARATION_INPUT_FILES][65]; unsigned char digest[32]; };
static inline void preparation_capture_init(struct cliq_preparation_capture *input) {
    memset(input, 0, sizeof(*input)); for (size_t i = 0; i < CLIQ_PREPARATION_INPUT_FILES; i++) input->files[i] = -1;
}
static inline bool preparation_capture_close(struct cliq_preparation_capture *input) {
    bool joined = true;
    for (size_t i = 0; i < CLIQ_PREPARATION_INPUT_FILES; i++) if (!source_close_fd(&input->files[i])) joined = false;
    return joined;
}
static inline bool preparation_receive_message(int socket, unsigned char *bytes, size_t capacity, size_t *length) {
    struct iovec data = { .iov_base = bytes, .iov_len = capacity };
    char rights[CMSG_SPACE(CLIQ_WORKER_MAX_FDS * sizeof(int))]; memset(rights, 0, sizeof(rights));
    struct msghdr message = { .msg_iov = &data, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights) };
    ssize_t received; do { received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC); } while (received < 0 && errno == EINTR);
    bool valid = received >= 0 && (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0;
    for (struct cmsghdr *entry = CMSG_FIRSTHDR(&message); entry; entry = CMSG_NXTHDR(&message, entry)) {
        valid = false;
        if (entry->cmsg_level != SOL_SOCKET || entry->cmsg_type != SCM_RIGHTS || entry->cmsg_len < CMSG_LEN(0) ||
            (entry->cmsg_len - CMSG_LEN(0)) % sizeof(int)) continue;
        size_t count = (entry->cmsg_len - CMSG_LEN(0)) / sizeof(int); int *descriptors = (int *)CMSG_DATA(entry);
        for (size_t i = 0; i < count; i++) if (!source_close_fd(&descriptors[i])) valid = false;
    }
    *length = received >= 0 ? (size_t)received : 0; return valid;
}
static inline void preparation_capture_hex(const unsigned char digest[32], char text[65]) {
    const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { text[i * 2] = alphabet[digest[i] >> 4]; text[i * 2 + 1] = alphabet[digest[i] & 15]; } text[64] = '\0';
}
static inline bool preparation_capture_input(int socket, const struct cliq_worker_packet *request, const char *metadata_ref,
    uint64_t reserve, struct cliq_preparation_capture *input) {
    unsigned char bytes[CLIQ_PREPARATION_INPUT_HEADER + CLIQ_PREPARATION_INPUT_CHUNK]; size_t length;
    struct cliq_preparation_input_message_data message; struct sha256_context binding; sha256_init(&binding);
    preparation_capture_init(input);
    if (!cliq_hex_digest(metadata_ref) || reserve >= request->max_generation_bytes || CLIQ_PREPARATION_INPUT_FILES + 12 >= request->max_open_files) return false;
    for (uint32_t role = 0; role < CLIQ_PREPARATION_INPUT_FILES; role++) {
        if (!preparation_receive_message(socket, bytes, sizeof(bytes), &length) || length != CLIQ_PREPARATION_INPUT_HEADER ||
            !preparation_stream_decode(bytes, &message) || message.kind != CLIQ_PREPARATION_DECLARE || message.role != role ||
            message.byte_count > request->max_file_bytes || (role == 0 && (message.byte_count > request->max_output_bytes || strcmp(message.digest, metadata_ref) != 0)) ||
            !source_add_u64(&input->total, message.byte_count, request->max_generation_bytes) ||
            !cliq_source_page_add(&input->pages, message.byte_count, request->max_generation_bytes - reserve)) return false;
        sha256_update(&binding, bytes, CLIQ_PREPARATION_INPUT_HEADER);
        input->bytes[role] = message.byte_count; memcpy(input->digests[role], message.digest, sizeof(message.digest));
        int writer = memfd_create("cliq-preparing-git-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (writer < 0) return false;
        struct sha256_context file; sha256_init(&file); uint64_t read_bytes = 0; bool valid = true;
        while (valid) {
            if (!preparation_receive_message(socket, bytes, sizeof(bytes), &length) || length < CLIQ_PREPARATION_INPUT_HEADER ||
                !preparation_stream_decode(bytes, &message) || message.role != role || length != CLIQ_PREPARATION_INPUT_HEADER + message.length) { valid = false; break; }
            if (message.kind == CLIQ_PREPARATION_END) { valid = read_bytes == input->bytes[role]; break; }
            if (message.kind != CLIQ_PREPARATION_CHUNK || message.length > input->bytes[role] - read_bytes ||
                !source_write_all(writer, bytes + CLIQ_PREPARATION_INPUT_HEADER, message.length)) { valid = false; break; }
            sha256_update(&file, bytes + CLIQ_PREPARATION_INPUT_HEADER, message.length); read_bytes += message.length;
        }
        unsigned char digest[32]; char text[65]; sha256_final(&file, digest); preparation_capture_hex(digest, text);
        valid = valid && read_bytes == input->bytes[role] && strcmp(text, input->digests[role]) == 0;
        input->files[role] = valid ? source_sealed_readonly(writer) : -1;
        if (!source_close_fd(&writer)) valid = false;
        if (!valid || input->files[role] < 0) return false;
    }
    if (!preparation_receive_message(socket, bytes, sizeof(bytes), &length) || length != CLIQ_PREPARATION_INPUT_HEADER ||
        !preparation_stream_decode(bytes, &message) || message.kind != CLIQ_PREPARATION_INPUT_COMPLETE ||
        !preparation_receive_message(socket, bytes, sizeof(bytes), &length) || length != 0) return false;
    sha256_final(&binding, input->digest); return true;
}
#endif
