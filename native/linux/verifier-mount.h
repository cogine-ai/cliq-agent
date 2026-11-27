#ifndef CLIQ_VERIFIER_MOUNT_H
#define CLIQ_VERIFIER_MOUNT_H
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static bool verifier_option(const char *options, const char *wanted) {
    size_t bytes = strlen(wanted);
    for (const char *at = options; at && *at; at = strchr(at, ',')) {
        if (*at == ',') at++;
        if (strncmp(at, wanted, bytes) == 0 && (at[bytes] == '\0' || at[bytes] == ',')) return true;
    }
    return false;
}

static bool verifier_mount_observed(const char *target, bool readonly, bool executable, bool devices) {
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t bound = 262144; char *bytes = malloc(bound); bool valid = bytes != NULL, found = false;
    size_t count = 0;
    while (valid) {
        ssize_t received = read(fd, bytes + count, bound - 1 - count);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) { valid = false; break; }
        if (received == 0) break;
        count += (size_t)received;
        if (count == bound - 1) { valid = false; break; }
    }
    if (count == 0) valid = false;
    if (close(fd) != 0) valid = false;
    if (valid) {
        bytes[count] = '\0'; char *line = bytes;
        while (line && *line) {
            char *end = strchr(line, '\n');
            if (!end) { valid = false; break; }
            *end++ = '\0'; char *field = line;
            for (unsigned int i = 1; i < 5 && field; i++) { field = strchr(field, ' '); if (field) field++; }
            if (!field) { valid = false; break; }
            char *options = strchr(field, ' ');
            if (!options) { valid = false; break; }
            *options++ = '\0'; char *tail = strchr(options, ' ');
            if (!tail) { valid = false; break; }
            *tail = '\0';
            if (strcmp(field, target) == 0) {
                if (found || !verifier_option(options, readonly ? "ro" : "rw") ||
                    verifier_option(options, "noexec") == executable || !verifier_option(options, "nosuid") ||
                    (!devices && !verifier_option(options, "nodev"))) { valid = false; break; }
                found = true;
            }
            line = end;
        }
    }
    free(bytes); return valid && found;
}

#endif
