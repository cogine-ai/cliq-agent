#ifndef CLIQ_EDIT_TEXT_H
#define CLIQ_EDIT_TEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Node readFile(..., 'utf8') uses replacement decoding of ill-formed input.
 * A nonempty valid old_text has the same exact-span matches in these UTF-8
 * bytes as in the corresponding JS string. Empty old_text counts UTF-16 units. */
static inline size_t cliq_utf8_part(const unsigned char *input, size_t remaining, bool *valid) {
    unsigned char lead = input[0]; size_t wanted;
    *valid = false;
    if (lead < 0x80) { *valid = true; return 1; }
    if (lead >= 0xc2 && lead <= 0xdf) wanted = 2;
    else if (lead >= 0xe0 && lead <= 0xef) wanted = 3;
    else if (lead >= 0xf0 && lead <= 0xf4) wanted = 4;
    else return 1;
    for (size_t index = 1; index < wanted; index++) {
        if (index == remaining) return index;
        unsigned char next = input[index];
        if ((next & 0xc0) != 0x80 || (index == 1 &&
            ((lead == 0xe0 && next < 0xa0) || (lead == 0xed && next > 0x9f) ||
             (lead == 0xf0 && next < 0x90) || (lead == 0xf4 && next > 0x8f)))) return index;
    }
    *valid = true; return wanted;
}

static inline bool cliq_decode_utf8(const unsigned char *input, size_t size, size_t maximum,
                                   unsigned char **output, size_t *length, size_t *utf16_units) {
    size_t count = 0, units = 0;
    for (size_t offset = 0; offset < size;) {
        bool valid; size_t consumed = cliq_utf8_part(input + offset, size - offset, &valid);
        size_t bytes = valid ? consumed : 3;
        if (bytes > maximum || count > maximum - bytes) return false;
        count += bytes; units += valid && input[offset] >= 0xf0 ? 2 : 1; offset += consumed;
    }
    unsigned char *result = malloc(count + 1);
    if (!result) return false;
    size_t written = 0;
    for (size_t offset = 0; offset < size;) {
        bool valid; size_t consumed = cliq_utf8_part(input + offset, size - offset, &valid);
        if (valid) { memcpy(result + written, input + offset, consumed); written += consumed; }
        else { memcpy(result + written, "\xef\xbf\xbd", 3); written += 3; }
        offset += consumed;
    }
    result[count] = 0; *output = result; *length = count; *utf16_units = units; return true;
}

#endif
