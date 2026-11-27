/* Inert mountinfo rows and actual owned FD reads only. This does not mount a
 * filesystem or create native containment, a Run or recovery evidence. */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *fixture;
static unsigned int opened, closed, reads;
static int fixture_open(const char *name, int flags) {
    assert(!strcmp(name, "/proc/self/mountinfo"));
    int fd = open(fixture, flags); assert(fd >= 0); opened++; return fd;
}
static ssize_t fixture_read(int fd, void *bytes, size_t count) {
    reads++; return read(fd, bytes, count > 4096 ? 4096 : count);
}
static int fixture_close(int fd) { closed++; return close(fd); }
#define open fixture_open
#define read fixture_read
#define close fixture_close
#include "verifier-mount.h"
#undef open
#undef read
#undef close

static void text(int fd, const char *value) {
    size_t size = strlen(value), offset = 0;
    while (offset < size) { ssize_t n = write(fd, value + offset, size - offset); assert(n > 0); offset += (size_t)n; }
}
static const char *selected = "900 1 0:1 / /selected ro,nosuid,nodev - tmpfs tmpfs rw\n";
static void populate(unsigned int filler, unsigned int targets, bool trailing) {
    int fd = open(fixture, O_WRONLY | O_TRUNC); assert(fd >= 0);
    for (unsigned int i = 0; i < filler; i++) {
        char row[160]; int n = snprintf(row, sizeof(row), "%u 1 0:1 / /inert-path-%u ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n", i + 1, i);
        assert(n > 0 && (size_t)n < sizeof(row)); text(fd, row);
    }
    for (unsigned int i = 0; i < targets; i++) text(fd, selected);
    if (trailing) text(fd, "incomplete final row");
    assert(close(fd) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2); fixture = argv[1];
    int fd = mkstemp(fixture); assert(fd >= 0); assert(close(fd) == 0);
    populate(128, 1, false);
    assert(verifier_mount_observed("/selected", true, true, false));
    assert(reads > 1 && opened == closed);
    populate(128, 2, false);
    assert(!verifier_mount_observed("/selected", true, true, false));
    populate(128, 0, false);
    assert(!verifier_mount_observed("/selected", true, true, false));
    populate(128, 1, true);
    assert(!verifier_mount_observed("/selected", true, true, false));
    populate(5000, 1, false);
    assert(!verifier_mount_observed("/selected", true, true, false));
    populate(0, 1, false);
    assert(!verifier_mount_observed("/selected", false, true, false));
    assert(!verifier_mount_observed("/selected", true, false, false));
    assert(opened == closed && unlink(fixture) == 0);
    puts("{\"checks\":7,\"shortReadBytes\":4096,\"physicalContainmentQualified\":false}");
    return 0;
}
