/* Real Linux-kernel regression at the signed worker's existing filter seam.
 * No production test API, synthetic seccomp_data, or BPF interpreter. */
#define main cliq_worker_entrypoint
#include "cliq-linux-worker.c"
#undef main
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

#if !defined(__x86_64__) || defined(__ILP32__)
#error "This regression requires native x86-64 to exercise i386 and x32 syscalls"
#endif

enum syscall_case { NATIVE_ALLOWED, NATIVE_DENIED, I386_DENIED, X32_DENIED };

struct test_case {
    const char *name;
    enum syscall_case kind;
    long number;
};

static void child_case(const struct test_case *test) {
    pid_t original_pid = getpid();
    alarm(5);
    if (!deny_child_and_network_creation()) _exit(120);
    if (test->kind == NATIVE_ALLOWED) {
        _exit(syscall(__NR_getpid) == original_pid ? 0 : 121);
    }
    if (test->kind == I386_DENIED) {
        long result;
        /* Linux i386 syscall 20 is getpid; no pointer/argument conversion. */
        __asm__ volatile("int $0x80" : "=a"(result) : "0"(20L)
            : "memory", "cc", "r8", "r9", "r10", "r11");
        (void)result;
        _exit(122); /* Returning, including ENOSYS, is not fail-closed. */
    }
    if (test->kind == X32_DENIED) {
        (void)syscall(0x40000000L | __NR_getpid);
        _exit(123);
    }
    errno = 0;
    /* Invalid pointer/descriptor/clone flags prevent effects if a denial
     * regresses. fork/vfork ignore arguments, so join any unexpected child. */
    long result = syscall(test->number, -1L, 0L, 0L, 0L, 0L, 0L);
    if (result >= 0 && (test->number == __NR_fork || test->number == __NR_vfork || test->number == __NR_clone)) {
        if (result == 0) _exit(124);
        pid_t joined;
        do { joined = waitpid((pid_t)result, NULL, 0); } while (joined < 0 && errno == EINTR);
        _exit(125);
    }
    _exit(result == -1 && errno == EPERM ? 0 : 126);
}

int main(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) { perror("setrlimit"); return 1; }
    const struct test_case cases[] = {
        {"native getpid remains allowed", NATIVE_ALLOWED, __NR_getpid},
        {"native clone denied", NATIVE_DENIED, __NR_clone},
#ifdef __NR_clone3
        {"native clone3 denied", NATIVE_DENIED, __NR_clone3},
#endif
        {"native fork denied", NATIVE_DENIED, __NR_fork},
        {"native vfork denied", NATIVE_DENIED, __NR_vfork},
        {"native execve denied", NATIVE_DENIED, __NR_execve},
#ifdef __NR_execveat
        {"native execveat denied", NATIVE_DENIED, __NR_execveat},
#endif
        {"native socket denied", NATIVE_DENIED, __NR_socket},
        {"native connect denied", NATIVE_DENIED, __NR_connect},
        {"i386 int0x80 getpid kills process", I386_DENIED, 20},
        {"x32 getpid kills process", X32_DENIED, 0x40000000L | __NR_getpid}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pid_t child = fork();
        if (child < 0) { perror("fork"); return 1; }
        if (child == 0) child_case(&cases[i]);
        int status;
        pid_t joined;
        do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
        if (joined != child) { perror("waitpid"); return 1; }
        bool kill_expected = cases[i].kind == I386_DENIED || cases[i].kind == X32_DENIED;
        bool passed = kill_expected ? WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS :
            WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (!passed) {
            fprintf(stderr, "FAIL %s: wait status=%d\n", cases[i].name, status);
            return 1;
        }
        printf("PASS %s\n", cases[i].name);
    }
    return 0;
}
