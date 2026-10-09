/* Portable text-contract tests. These do not qualify process containment. */
#include "edit-text.h"
#include <assert.h>
#include <string.h>

static void decoded(const unsigned char *input, size_t length, const char *expected, size_t units) {
    unsigned char *result = NULL; size_t count = 0, observed_units = 0;
    assert(cliq_decode_utf8(input, length, 1024, &result, &count, &observed_units));
    assert(count == strlen(expected) && memcmp(result, expected, count) == 0 && observed_units == units);
    free(result);
}

int main(void) {
    decoded((const unsigned char *)"hello", 5, "hello", 5);
    decoded((const unsigned char *)"\xf0\x9f\x98\x80", 4, "\xf0\x9f\x98\x80", 2);
    decoded((const unsigned char *)"a\xff" "b", 3, "a\xef\xbf\xbd" "b", 3);
    decoded((const unsigned char *)"\xe1\x80", 2, "\xef\xbf\xbd", 1);
    decoded((const unsigned char *)"\xe1\x80" "a", 3, "\xef\xbf\xbd" "a", 2);
    decoded((const unsigned char *)"\xed\xa0\x80", 3, "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd", 3);
    decoded((const unsigned char *)"\xf4\x90\x80\x80", 4, "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd", 4);
    unsigned char *result = NULL; size_t length, units;
    assert(!cliq_decode_utf8((const unsigned char *)"\xff", 1, 2, &result, &length, &units));
    return 0;
}
