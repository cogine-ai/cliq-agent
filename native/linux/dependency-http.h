#ifndef CLIQ_DEPENDENCY_HTTP_H
#define CLIQ_DEPENDENCY_HTTP_H
/* Closed HTTP/1.1 framing for the native public integrity GET. These are C
 * implementation callbacks, never N-API arguments. Bodies never become JSON,
 * exceptions or diagnostic strings. Caller owns TLS, deadline and sink FD. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#define CLIQ_DEPENDENCY_HTTP_HEADER_BYTES 65536u
#define CLIQ_DEPENDENCY_HTTP_CHUNK_BYTES 65536u
struct cliq_dependency_http {
    void *context;
    ssize_t (*read)(void *, unsigned char *, size_t);
    bool (*write_body)(void *, const unsigned char *, size_t);
    uint64_t maximum_bytes, received_bytes; unsigned status;
    size_t header_bytes; bool eof;
};
static inline bool cliq_dependency_http_exact(struct cliq_dependency_http *http, uint64_t wanted) {
    unsigned char bytes[CLIQ_DEPENDENCY_HTTP_CHUNK_BYTES];
    while (wanted) {
        size_t count = wanted > sizeof(bytes) ? sizeof(bytes) : (size_t)wanted;
        ssize_t actual = http->read(http->context, bytes, count);
        if (actual <= 0 || (size_t)actual > count) return false;
        http->received_bytes += (uint64_t)actual;
        if (http->received_bytes > http->maximum_bytes || !http->write_body(http->context, bytes, (size_t)actual)) return false;
        wanted -= (uint64_t)actual;
    }
    return true;
}
static inline bool cliq_dependency_http_line(struct cliq_dependency_http *http, char line[8193]) {
    size_t length = 0;
    for (;;) {
        unsigned char byte;
        if (http->header_bytes >= CLIQ_DEPENDENCY_HTTP_HEADER_BYTES || http->read(http->context,&byte,1) != 1) return false;
        http->header_bytes++;
        if (byte == '\r') {
            if (http->header_bytes >= CLIQ_DEPENDENCY_HTTP_HEADER_BYTES || http->read(http->context,&byte,1) != 1 || byte != '\n') return false;
            http->header_bytes++; line[length] = 0; return true;
        }
        if (length == 8192 || (byte < 0x20 && byte != '\t') || byte > 0x7e) return false;
        line[length++] = (char)byte;
    }
}
static inline bool cliq_dependency_http_number(const char *text, unsigned base, uint64_t *output) {
    if (!text || !*text || strlen(text) > (base == 16 ? 16u : 20u)) return false;
    uint64_t value = 0;
    for (size_t index = 0; text[index]; index++) {
        unsigned char byte = (unsigned char)text[index]; unsigned digit;
        if (byte >= '0' && byte <= '9') digit = byte - '0';
        else if (base == 16 && byte >= 'a' && byte <= 'f') digit = byte - 'a' + 10;
        else if (base == 16 && byte >= 'A' && byte <= 'F') digit = byte - 'A' + 10;
        else return false;
        if (digit >= base || value > (UINT64_MAX - digit) / base) return false;
        value = value * base + digit;
    }
    *output = value; return true;
}
static inline bool cliq_dependency_http_response(struct cliq_dependency_http *http) {
    if (!http || !http->read || !http->write_body || !http->maximum_bytes) return false;
    char line[8193]; unsigned informational = 0;
    bool length_present = false, chunked = false, encoding_present = false;
    uint64_t content_length = 0;
    for (;;) {
        if (!cliq_dependency_http_line(http,line) || strlen(line) < 12 || strncmp(line,"HTTP/1.1 ",9) ||
            line[9] < '1' || line[9] > '5' || line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9' ||
            (line[12] && line[12] != ' ')) return false;
        http->status = (unsigned)(line[9] - '0') * 100 + (unsigned)(line[10] - '0') * 10 + (unsigned)(line[11] - '0');
        unsigned fields = 0; length_present = false; chunked = false; encoding_present = false;
        for (;;) {
            if (!cliq_dependency_http_line(http,line)) return false;
            if (!line[0]) break;
            if (++fields > 128 || line[0] == ' ' || line[0] == '\t') return false;
            char *colon = strchr(line,':'); if (!colon || colon == line) return false;
            *colon = 0;
            if (strspn(line,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~") != strlen(line)) return false;
            char *value = colon + 1; while (*value == ' ' || *value == '\t') value++;
            size_t size = strlen(value); while (size && (value[size - 1] == ' ' || value[size - 1] == '\t')) value[--size] = 0;
            if (!strcasecmp(line,"content-length")) {
                if (length_present || !cliq_dependency_http_number(value,10,&content_length)) return false;
                length_present = true;
            } else if (!strcasecmp(line,"transfer-encoding")) {
                if (chunked || strcasecmp(value,"chunked")) return false;
                chunked = true;
            } else if (!strcasecmp(line,"content-encoding")) {
                if (encoding_present || strcasecmp(value,"identity")) return false;
                encoding_present = true;
            } else if (!strcasecmp(line,"content-range")) return false;
        }
        if (length_present && chunked) return false;
        if (http->status >= 200) break;
        if (++informational > 8 || http->status == 101 || chunked || (length_present && content_length)) return false;
    }
    /* Redirects are never followed. An error response's bounded body is fully
     * consumed by the caller's discard sink; only status/count survive. */
    if (http->status != 200 && http->status < 400) return false;
    if (length_present && content_length > http->maximum_bytes) return false;
    if (chunked) {
        for (;;) {
            uint64_t size;
            if (!cliq_dependency_http_line(http,line) || !cliq_dependency_http_number(line,16,&size) || size > http->maximum_bytes - http->received_bytes) return false;
            if (!size) {
                /* As in the original broker, no trailer state is accepted. */
                if (!cliq_dependency_http_line(http,line) || line[0]) return false;
                break;
            }
            if (!cliq_dependency_http_exact(http,size)) return false;
            unsigned char end[2];
            for (size_t index = 0; index < 2; index++) if (http->read(http->context,end + index,1) != 1) return false;
            if (end[0] != '\r' || end[1] != '\n') return false;
        }
    } else if (length_present) {
        if (!cliq_dependency_http_exact(http,content_length)) return false;
    } else {
        unsigned char bytes[CLIQ_DEPENDENCY_HTTP_CHUNK_BYTES];
        for (;;) {
            /* At the exact unframed ceiling EOF is unknown. Refuse instead
             * of reading an unauthorized extra payload byte or inventing EOF. */
            uint64_t remaining=http->maximum_bytes-http->received_bytes;if(!remaining)return false;
            size_t wanted = remaining >= sizeof(bytes) ? sizeof(bytes) : (size_t)remaining;
            ssize_t count = http->read(http->context,bytes,wanted);
            if (count < 0 || (size_t)count > wanted) return false;
            if (!count) { http->eof = true; break; }
            http->received_bytes += (uint64_t)count;
            if (http->received_bytes > http->maximum_bytes || !http->write_body(http->context,bytes,(size_t)count)) return false;
        }
    }
    if (!http->eof) {
        unsigned char tail;
        if (http->read(http->context,&tail,1) != 0) return false;
        http->eof = true;
    }
    return http->status != 200 || http->received_bytes > 0;
}
#endif
