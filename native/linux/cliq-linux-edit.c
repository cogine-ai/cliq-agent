#define _GNU_SOURCE
#include "worker-common.h"
#include "edit-text.h"
#include <stdlib.h>
#include <strings.h>
#include <sys/prctl.h>

#define MAX_INPUT_BYTES (16 * 1024 * 1024)
#define MAX_EDIT_FILE_BYTES (256 * 1024 * 1024)
struct text { unsigned char *bytes; size_t length; };
struct parser { const unsigned char *cursor, *end; };

static int hex_digit(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
static bool unicode_unit(struct parser *parser, uint32_t *unit) {
    if (parser->end - parser->cursor < 4) return false;
    *unit = 0;
    for (size_t i = 0; i < 4; i++) {
        int digit = hex_digit(*parser->cursor++); if (digit < 0) return false;
        *unit = *unit * 16 + (uint32_t)digit;
    }
    return true;
}
static bool json_string(struct parser *parser, struct text *output) {
    if (parser->cursor == parser->end || *parser->cursor++ != '"') return false;
    output->bytes = malloc((size_t)(parser->end - parser->cursor) + 1); output->length = 0;
    if (!output->bytes) return false;
    while (parser->cursor < parser->end) {
        unsigned char value = *parser->cursor++;
        if (value == '"') { output->bytes[output->length] = 0; return true; }
        if (value < 0x20) return false;
        if (value != '\\') { output->bytes[output->length++] = value; continue; }
        if (parser->cursor == parser->end) return false;
        value = *parser->cursor++;
        switch (value) {
            case '"': case '\\': case '/': output->bytes[output->length++] = value; break;
            case 'b': output->bytes[output->length++] = '\b'; break;
            case 'f': output->bytes[output->length++] = '\f'; break;
            case 'n': output->bytes[output->length++] = '\n'; break;
            case 'r': output->bytes[output->length++] = '\r'; break;
            case 't': output->bytes[output->length++] = '\t'; break;
            case 'u': {
                uint32_t point; if (!unicode_unit(parser, &point)) return false;
                if (point >= 0xd800 && point <= 0xdbff) {
                    if (parser->end - parser->cursor < 6 || parser->cursor[0] != '\\' || parser->cursor[1] != 'u') return false;
                    parser->cursor += 2;
                    uint32_t low; if (!unicode_unit(parser, &low) || low < 0xdc00 || low > 0xdfff) return false;
                    point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                } else if (point >= 0xdc00 && point <= 0xdfff) return false;
                if (point < 0x80) output->bytes[output->length++] = (unsigned char)point;
                else if (point < 0x800) {
                    output->bytes[output->length++] = (unsigned char)(0xc0 | (point >> 6));
                    output->bytes[output->length++] = (unsigned char)(0x80 | (point & 0x3f));
                } else if (point < 0x10000) {
                    output->bytes[output->length++] = (unsigned char)(0xe0 | (point >> 12));
                    output->bytes[output->length++] = (unsigned char)(0x80 | ((point >> 6) & 0x3f));
                    output->bytes[output->length++] = (unsigned char)(0x80 | (point & 0x3f));
                } else {
                    output->bytes[output->length++] = (unsigned char)(0xf0 | (point >> 18));
                    output->bytes[output->length++] = (unsigned char)(0x80 | ((point >> 12) & 0x3f));
                    output->bytes[output->length++] = (unsigned char)(0x80 | ((point >> 6) & 0x3f));
                    output->bytes[output->length++] = (unsigned char)(0x80 | (point & 0x3f));
                }
                break;
            }
            default: return false;
        }
    }
    return false;
}
static bool literal(struct parser *parser, const char *value) {
    size_t length = strlen(value);
    if ((size_t)(parser->end - parser->cursor) < length || memcmp(parser->cursor, value, length) != 0) return false;
    parser->cursor += length; return true;
}
static bool decode_input(int fd, struct text *path, struct text *old, struct text *replacement) {
    struct stat input;
    if (fstat(fd, &input) != 0 || !S_ISREG(input.st_mode) || input.st_size <= 0 || input.st_size > MAX_INPUT_BYTES) return false;
    unsigned char *bytes = malloc((size_t)input.st_size);
    if (!bytes) return false;
    size_t offset = 0;
    while (offset < (size_t)input.st_size) {
        ssize_t count = pread(fd, bytes + offset, (size_t)input.st_size - offset, (off_t)offset);
        if (count <= 0) { free(bytes); return false; } offset += (size_t)count;
    }
    /* Exact JCS key order and closed builtin edit input; no argv or host path. */
    struct parser parser = { bytes, bytes + input.st_size };
    bool valid = literal(&parser, "{\"new_text\":") && json_string(&parser, replacement) &&
        literal(&parser, ",\"old_text\":") && json_string(&parser, old) &&
        literal(&parser, ",\"path\":") && json_string(&parser, path) && literal(&parser, "}") && parser.cursor == parser.end;
    free(bytes); return valid;
}

static int edit_target(const struct text *path, const struct text *old, const struct text *replacement, size_t maximum) {
    if (path->length == 0 || path->length >= CLIQ_WORKER_PATH_BYTES || strlen((char *)path->bytes) != path->length ||
        path->bytes[0] == '/' || memchr(path->bytes, '\\', path->length)) return 1;
    char *copy = strdup((char *)path->bytes); if (!copy) return 1;
    int directory = open("/work", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { free(copy); return 1; }
    char *component = copy, *slash;
    while ((slash = strchr(component, '/')) != NULL) {
        *slash = '\0';
        if (!*component || strcmp(component, ".") == 0 || strcmp(component, "..") == 0 || strcasecmp(component, ".git") == 0) goto error;
        int next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto error;
        close(directory); directory = next; component = slash + 1;
    }
    if (!*component || strcmp(component, ".") == 0 || strcmp(component, "..") == 0 || strcasecmp(component, ".git") == 0) goto error;
    int target = openat(directory, component, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (target < 0) goto error;
    struct stat before, after;
    if (fstat(target, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        before.st_size < 0 || (uint64_t)before.st_size > maximum) { close(target); goto error; }
    size_t size = (size_t)before.st_size;
    unsigned char *contents = malloc(size + 1);
    if (!contents) { close(target); goto error; }
    size_t read_bytes = 0;
    while (read_bytes < size) {
        ssize_t bytes = pread(target, contents + read_bytes, size - read_bytes, (off_t)read_bytes);
        if (bytes <= 0) { free(contents); close(target); goto error; } read_bytes += (size_t)bytes;
    }
    unsigned char *decoded = NULL; size_t decoded_size = 0, utf16_units = 0;
    if (!cliq_decode_utf8(contents, size, maximum, &decoded, &decoded_size, &utf16_units)) {
        free(contents); close(target); goto error;
    }
    free(contents); contents = decoded; size = decoded_size;
    size_t match = 0, matches = 0;
    if (old->length != 0) {
        for (size_t i = 0; i + old->length <= size;) {
            if (memcmp(contents + i, old->bytes, old->length) == 0) { match = i; matches++; i += old->length; }
            else i++;
        }
    } else {
        /* Preserve String.split('') / replace('', ...) for the signed existing
         * contract: exactly two UTF-16 units yield one reported match. */
        matches = utf16_units == 2 ? 1 : 0;
    }
    if (matches != 1 || replacement->length > maximum || size - old->length > maximum - replacement->length ||
        fstat(target, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        free(contents); close(target); goto error;
    }
    size_t result_size = size - old->length + replacement->length;
    unsigned char *result = malloc(result_size + 1);
    if (!result) { free(contents); close(target); goto error; }
    memcpy(result, contents, match);
    memcpy(result + match, replacement->bytes, replacement->length);
    memcpy(result + match + replacement->length, contents + match + old->length, size - match - old->length);
    free(contents);
    bool ok = ftruncate(target, (off_t)result_size) == 0;
    size_t written = 0;
    while (ok && written < result_size) {
        ssize_t bytes = pwrite(target, result + written, result_size - written, (off_t)written);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) { ok = false; break; } written += (size_t)bytes;
    }
    if (ok) ok = fsync(target) == 0 && fsync(directory) == 0;
    free(result); close(target); close(directory); free(copy); return ok ? 0 : 1;
error:
    close(directory); free(copy); return 1;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 2 || getppid() != 1 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 70;
    struct cliq_worker_packet request;
    int descriptors[5]; size_t count;
    struct text path = {0}, old = {0}, replacement = {0};
    if (!cliq_receive(3, &request, descriptors, &count) || count != 1 || request.command != CLIQ_CREATE_WRITE ||
        !cliq_hex_digest(request.nonce)) return 70;
    bool decoded = decode_input(descriptors[0], &path, &old, &replacement); close(descriptors[0]);
    if (!decoded) { free(path.bytes); free(old.bytes); free(replacement.bytes); return 70; }
    struct cliq_worker_packet ready = cliq_packet(CLIQ_WORKER_READY);
    ready.pid = 2;
    if (!cliq_process_token(2, ready.start_token) || !cliq_send(3, &ready, NULL, 0)) return 70;
    struct cliq_worker_packet release;
    if (!cliq_receive(3, &release, descriptors, &count) || count != 0 || release.command != CLIQ_RELEASE_WRITE ||
        strcmp(release.nonce, request.nonce) != 0) return 70;
    size_t maximum = request.max_file_bytes > MAX_EDIT_FILE_BYTES ? MAX_EDIT_FILE_BYTES : (size_t)request.max_file_bytes;
    int outcome = edit_target(&path, &old, &replacement, maximum);
    free(path.bytes); free(old.bytes); free(replacement.bytes);
    struct cliq_worker_packet result = cliq_packet(CLIQ_WRITE_RESULT); result.exit_status = (uint32_t)outcome;
    return cliq_send(3, &result, NULL, 0) ? outcome : 70;
}
