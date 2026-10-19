/* Real Linux lifetime fixture, not authority evidence or a production hook.
 * Keep the original child as a zombie until the observer explicitly reaps it. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* The enroll observer's own test parent retains only an already naturally
 * exited child. Its private IPC controls reap, never a live process pause. */
static int natural_enroll_exit(const char *image, const char *socket_path) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(socket_path) >= sizeof(address.sun_path)) return 98;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    int control = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (control < 0 || connect(control, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (control >= 0) close(control);
        return 98;
    }
    int gate[2];
    if (pipe2(gate, O_CLOEXEC) != 0) { close(control); return 98; }
    pid_t parent = getpid(), child = fork();
    if (child < 0) { close(gate[0]); close(gate[1]); close(control); return 98; }
    if (child == 0) {
        close(control); close(gate[1]);
        if (gate[0] != 3) { if (dup2(gate[0], 3) != 3) _exit(98); close(gate[0]); }
        else if (fcntl(3, F_SETFD, 0) != 0) _exit(98);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(98);
        execl(image, image, "-e", "process.stdin.resume();process.stdin.once('end',()=>{const f=require('node:fs'),b=Buffer.alloc(1);if(f.readSync(3,b,0,1,null)!==1||b[0]!==101)process.exit(98);f.closeSync(3);process.stdout.write('joined-output')})", (char *)NULL);
        _exit(98);
    }
    close(gate[0]);
    char message[64], command;
    int length = snprintf(message, sizeof(message), "LIVE %ld\n", (long)child);
    if (length <= 0 || (size_t)length >= sizeof(message) || write(control, message, (size_t)length) != length) goto failed;
    if (read(control, &command, 1) != 1 || command != 'e' || write(gate[1], "e", 1) != 1) goto failed;
    if (close(gate[1]) != 0) goto failed;
    gate[1] = -1;
    siginfo_t information = {0};
    if (waitid(P_PID, (id_t)child, &information, WEXITED | WNOWAIT) != 0 || information.si_pid != child ||
        information.si_code != CLD_EXITED || information.si_status != 0) goto failed;
    length = snprintf(message, sizeof(message), "ZOMBIE %ld\n", (long)child);
    if (length <= 0 || (size_t)length >= sizeof(message) || write(control, message, (size_t)length) != length) goto failed;
    if (read(control, &command, 1) != 1 || command != 'r') goto failed;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) goto failed;
    return close(control) == 0 ? 0 : 98;
failed:
    if (gate[1] >= 0) close(gate[1]);
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    close(control);
    return 98;
}

static int live_foreign_enroll(const char *image) {
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 98;
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) _exit(98);
        execl(image, image, "--auth-exec-foreign", (char *)NULL);
        _exit(98);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 98;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 98;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--enroll-natural-exit") == 0) return natural_enroll_exit(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "--enroll-live-foreign") == 0) return live_foreign_enroll(argv[2]);
    if (argc == 2 && strcmp(argv[1], "--auth-exec-foreign") == 0) {
        char bytes[4096];
        for (;;) {
            ssize_t count = read(STDIN_FILENO, bytes, sizeof(bytes));
            if (count > 0) { memset(bytes, 0, sizeof(bytes)); continue; }
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return 98;
            break;
        }
        execl("/usr/bin/sleep", "sleep", "30", (char *)NULL);
        return 98;
    }
    if (argc != 1) return 98;
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
