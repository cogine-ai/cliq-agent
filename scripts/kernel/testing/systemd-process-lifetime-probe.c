/* Own only a natural child exit and real WNOWAIT/reap. No process pause,
 * credential, StateOwner, Run, containment or namespace authority. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "dumpable") && strcmp(argv[1], "private"))) return 98;
    int gate[2], ready[2];
    if (pipe(gate) || pipe(ready)) return 98;
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 98;
    if (child == 0) {
        close(gate[1]); close(ready[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
            prctl(PR_SET_DUMPABLE, !strcmp(argv[1], "dumpable"))) _exit(98);
        char command;
        if (write(ready[1], "l", 1) != 1 || close(ready[1]) || read(gate[0], &command, 1) != 1 || command != 'e') _exit(98);
        if (close(gate[0])) _exit(98);
        _exit(0);
    }
    close(gate[0]); close(ready[1]);
    char command;
    if (read(ready[0], &command, 1) != 1 || command != 'l' || close(ready[0])) goto failed;
    if (printf("LIVE %ld\n", (long)child) < 0 || fflush(stdout) || getchar() != 'e' || write(gate[1], "e", 1) != 1) goto failed;
    if (close(gate[1])) goto failed;
    gate[1] = -1;
    siginfo_t information = {0};
    if (waitid(P_PID, (id_t)child, &information, WEXITED | WNOWAIT) || information.si_pid != child ||
        information.si_code != CLD_EXITED || information.si_status != 0) goto failed;
    if (puts("ZOMBIE") < 0 || fflush(stdout) || getchar() != 'r') goto failed;
    int status;
    if (waitpid(child, &status, 0) != child) goto failed;
    child = -1; /* Never signal an already reaped/reusable PID on failure. */
    if (!WIFEXITED(status) || WEXITSTATUS(status)) return 98;
    return puts("REAPED") >= 0 && !fflush(stdout) ? 0 : 98;
failed:
    if (gate[1] >= 0) close(gate[1]);
    if (child > 0) {
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    return 98;
}
