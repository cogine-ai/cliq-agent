/* Real Linux lifetime fixture, not authority evidence or a production hook.
 * Keep the original child as a zombie until the observer explicitly reaps it. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 98;
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(98);
        for (;;) pause();
    }
    if (printf("LIVE %ld\n", (long)child) < 0 || fflush(stdout) != 0) goto failed;
    if (getchar() != 'k' || kill(child, SIGKILL) != 0) goto failed;
    siginfo_t information;
    if (waitid(P_PID, child, &information, WEXITED | WNOWAIT) != 0 || information.si_pid != child ||
        information.si_code != CLD_KILLED || information.si_status != SIGKILL) goto failed;
    if (puts("ZOMBIE") < 0 || fflush(stdout) != 0 || getchar() != 'r') goto failed;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 98;
    return puts("REAPED") >= 0 && fflush(stdout) == 0 ? 0 : 98;
failed:
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return 98;
}
