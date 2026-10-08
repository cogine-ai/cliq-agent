#define _GNU_SOURCE
#include "worker-common.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/* This signed entrypoint owns only the authenticated activation channel and a
 * permanently read-only generation. Tools are separate run_invocations. */
static bool deny_child_and_network_creation(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, nr)),
#ifdef __NR_clone
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
#ifdef __NR_clone3
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
#ifdef __NR_fork
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
#ifdef __NR_vfork
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#ifdef __NR_execveat
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getpid() != 2 || getppid() != 1 || !deny_child_and_network_creation()) return 70;
    struct cliq_worker_packet initial;
    int fds[5]; size_t count;
    if (!cliq_receive(CLIQ_WORKER_CHANNEL_FD, &initial, fds, &count) || count != 0 ||
        initial.command != CLIQ_CREATE_WORKER || !cliq_hex_digest(initial.nonce)) return 70;
    struct cliq_worker_packet ready = cliq_packet(CLIQ_WORKER_READY);
    ready.pid = (int64_t)getpid();
    if (!cliq_process_token(getpid(), ready.start_token) ||
        !cliq_send(CLIQ_WORKER_CHANNEL_FD, &ready, NULL, 0)) return 70;
    bool active = false;
    for (;;) {
        struct cliq_worker_packet request;
        if (!cliq_receive(CLIQ_WORKER_CHANNEL_FD, &request, fds, &count)) return 0;
        if (count != 0) { for (size_t i = 0; i < count; i++) close(fds[i]); return 70; }
        if (request.command == CLIQ_ACTIVATE_WORKER && !active &&
            strcmp(request.nonce, initial.nonce) == 0) {
            active = true;
            struct cliq_worker_packet acknowledged = cliq_packet(CLIQ_WORKER_ACTIVATED);
            if (!cliq_send(CLIQ_WORKER_CHANNEL_FD, &acknowledged, NULL, 0)) return 0;
        } else if (request.command == CLIQ_STOP_SCOPE) return 0;
        else return 70;
    }
}
