#define _GNU_SOURCE
/* Qualification-only positive control. The root orchestrator compiles exactly
 * one frozen-ledger marker path; there is no environment/argv path selector. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#ifndef CLIQ_INSTALLED_PRELOAD_MARKER
#error "the frozen fixture marker must be supplied at compilation"
#endif

__attribute__((constructor)) static void record_actual_loader_execution(void) {
    int marker = open(CLIQ_INSTALLED_PRELOAD_MARKER,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (marker < 0) _exit(86);
    char content[128];
    int length = snprintf(content, sizeof(content),
        "cliq-installed-loader-preload-v1\npid=%ld\nuid=%ld\n",
        (long)getpid(), (long)getuid());
    if (length < 0 || (size_t)length >= sizeof(content)) _exit(86);
    size_t written = 0;
    while (written < (size_t)length) {
        ssize_t bytes = write(marker, content + written, (size_t)length - written);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) _exit(86);
        written += (size_t)bytes;
    }
    if (close(marker) != 0) _exit(86);
}
