#define _GNU_SOURCE
#define CLIQ_CLIENT_STDIO_COMPONENT
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "client-stdio.c"
#define check(condition) do { if (!(condition)) { fprintf(stderr, "client stdio component line=%d errno=%d\n", __LINE__, errno); _exit(91); } } while (0)
static void run_case(int socket_case, int blocking) {
    int pair[2];
    check(socket_case ? socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 : pipe(pair) == 0);
    pid_t child = fork(); check(child >= 0);
    if (child == 0) {
        check(close(pair[0]) == 0); check(dup2(pair[1], STDOUT_FILENO) == STDOUT_FILENO);
        if (pair[1] != STDOUT_FILENO) check(close(pair[1]) == 0);
        int flags = fcntl(STDOUT_FILENO, F_GETFL); check(flags >= 0);
        check(fcntl(STDOUT_FILENO, F_SETFL, blocking ? flags & ~O_NONBLOCK : flags | O_NONBLOCK) == 0);
        flags = fcntl(STDOUT_FILENO, F_GETFL); int retirement_failed = 0;
        int duplicate = client_stdio_duplicate(STDOUT_FILENO, &retirement_failed);
        check(!retirement_failed && fcntl(STDOUT_FILENO, F_GETFL) == flags);
        if (blocking) { check(duplicate == -1); check(write(STDOUT_FILENO, "b", 1) == 1); }
        else {
            check(duplicate >= 3 && duplicate != STDOUT_FILENO);
            check(fcntl(duplicate, F_GETFL) == flags && (fcntl(duplicate, F_GETFD) & FD_CLOEXEC));
            struct stat original, held; check(fstat(STDOUT_FILENO, &original) == 0 && fstat(duplicate, &held) == 0 && client_stdio_same(&original, &held));
            check(write(duplicate, "d", 1) == 1);
            /* Darwin adds its write-observed status bit after the first real
             * write. Compare close against that actual post-write state. */
            int written_flags = fcntl(STDOUT_FILENO, F_GETFL); check(written_flags >= 0);
            check(close(duplicate) == 0);
            errno = 0; check(fcntl(duplicate, F_GETFD) == -1 && errno == EBADF);
            check(write(STDOUT_FILENO, "o", 1) == 1 && fcntl(STDOUT_FILENO, F_GETFL) == written_flags);
        }
        check(close(STDOUT_FILENO) == 0); _exit(0);
    }
    check(close(pair[1]) == 0); char bytes[3] = {0}; size_t count = 0;
    for (;;) { ssize_t got = read(pair[0], bytes + count, sizeof(bytes) - count); if (got < 0 && errno == EINTR) continue; check(got >= 0); if (!got) break; count += (size_t)got; check(count < sizeof(bytes)); }
    check(close(pair[0]) == 0); int status = 0; check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check(blocking ? count == 1 && bytes[0] == 'b' : count == 2 && bytes[0] == 'd' && bytes[1] == 'o');
}
int main(void) { run_case(0, 0); run_case(1, 0); run_case(0, 1); run_case(1, 1); puts("actual pipe/socket dup, flags, CLOEXEC, close, original-writer and child joins: 4 passed"); return 0; }
