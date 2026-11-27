#ifndef CLIQ_PREPARATION_GIT_STREAM_H
#define CLIQ_PREPARATION_GIT_STREAM_H

/* Fixed binary data transport, no paths, argv, environment or descriptors.
 * This framing grants neither a source read nor preparation/Run authority. */
#include "worker-common.h"
#include "worker-reservation.h"

#define CLIQ_PREPARATION_INPUT_FILES 4U
#define CLIQ_PREPARATION_INPUT_HEADER 96U
#define CLIQ_PREPARATION_INPUT_CHUNK 65536U
enum cliq_preparation_input_message { CLIQ_PREPARATION_DECLARE = 1, CLIQ_PREPARATION_CHUNK = 2,
    CLIQ_PREPARATION_END = 3, CLIQ_PREPARATION_INPUT_COMPLETE = 4 };
struct cliq_preparation_input_message_data { uint32_t kind, role, length; uint64_t byte_count; char digest[65]; };
static inline void preparation_stream_u32(unsigned char *bytes, uint32_t value) {
    for (unsigned int i = 0; i < 4; i++) bytes[i] = (unsigned char)(value >> (8 * i));
}
static inline uint32_t preparation_stream_read_u32(const unsigned char *bytes) {
    uint32_t value = 0; for (unsigned int i = 0; i < 4; i++) value |= (uint32_t)bytes[i] << (8 * i); return value;
}
static inline void preparation_stream_encode(unsigned char bytes[CLIQ_PREPARATION_INPUT_HEADER], const struct cliq_preparation_input_message_data *data) {
    memset(bytes, 0, CLIQ_PREPARATION_INPUT_HEADER); memcpy(bytes, "CLIQGIC1", 8);
    preparation_stream_u32(bytes + 8, data->kind); preparation_stream_u32(bytes + 12, data->role); preparation_stream_u32(bytes + 16, data->length);
    unsigned char *number = bytes + 24; reservation_u64(&number, data->byte_count); memcpy(bytes + 32, data->digest, strnlen(data->digest, 64));
}
static inline bool preparation_stream_decode(const unsigned char bytes[CLIQ_PREPARATION_INPUT_HEADER], struct cliq_preparation_input_message_data *data) {
    memset(data, 0, sizeof(*data)); data->kind = preparation_stream_read_u32(bytes + 8); data->role = preparation_stream_read_u32(bytes + 12);
    data->length = preparation_stream_read_u32(bytes + 16); const unsigned char *number = bytes + 24; data->byte_count = reservation_read_u64(&number);
    memcpy(data->digest, bytes + 32, 64); unsigned char canonical[CLIQ_PREPARATION_INPUT_HEADER]; preparation_stream_encode(canonical, data);
    if (memcmp(canonical, bytes, sizeof(canonical)) != 0) return false;
    bool digest_empty = data->digest[0] == '\0';
    if (data->kind == CLIQ_PREPARATION_DECLARE) return data->role < CLIQ_PREPARATION_INPUT_FILES && data->length == 0 && data->byte_count > 0 && cliq_hex_digest(data->digest);
    if (!digest_empty || data->byte_count) return false;
    if (data->kind == CLIQ_PREPARATION_CHUNK) return data->role < CLIQ_PREPARATION_INPUT_FILES && data->length > 0 && data->length <= CLIQ_PREPARATION_INPUT_CHUNK;
    if (data->kind == CLIQ_PREPARATION_END) return data->role < CLIQ_PREPARATION_INPUT_FILES && data->length == 0;
    return data->kind == CLIQ_PREPARATION_INPUT_COMPLETE && data->role == CLIQ_PREPARATION_INPUT_FILES && data->length == 0;
}
#endif
