/* Test-only fork observation. No production protocol, process killing or
 * memory/register mutation. The campaign remains the Supervisor's ancestor. */
#define _GNU_SOURCE
#include <node_api.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum trace_state { RUNNING, FORK_STOP, INITIAL_STOP, INTERRUPT_STOP, TERMINAL, UNKNOWN_STOP, RELEASED };
struct tracee { pid_t pid; enum trace_state state; int status; };
/* Static ownership survives caller GC and partial cleanup errors. Only a
 * completely released context can be replaced by a later arm(). */
static struct {
    pid_t thread;
    struct tracee controller, monitor;
    bool interrupt_requested, releasing, unknown_child, controller_loss, monitor_continued;
} active;

static napi_value error(napi_env env, const char *message) {
    napi_throw_error(env, "LINUX_FORK_TRACER", message); return NULL;
}
static napi_value system_error(napi_env env, const char *operation, int number) {
    char message[256];
    snprintf(message, sizeof(message), "%s failed: errno=%d (%s); controller=%ld monitor=%ld",
        operation, number, strerror(number), (long)active.controller.pid, (long)active.monitor.pid);
    return error(env, message);
}
static napi_value status_error(napi_env env, const char *message, const struct tracee *tracee) {
    char detail[256];
    snprintf(detail, sizeof(detail), "%s: pid=%ld wait_status=0x%x; controller=%ld monitor=%ld",
        message, (long)tracee->pid, (unsigned int)tracee->status,
        (long)active.controller.pid, (long)active.monitor.pid);
    return error(env, detail);
}
static bool main_thread(napi_env env) {
    pid_t thread = (pid_t)syscall(SYS_gettid);
    if (thread != getpid() || (active.thread != 0 && thread != active.thread)) {
        error(env, "fork tracing must remain on the campaign's main thread"); return false;
    }
    return true;
}
static bool no_arguments(napi_env env, napi_callback_info info) {
    size_t count = 1; napi_value argument;
    if (napi_get_cb_info(env, info, &count, &argument, NULL, NULL) != napi_ok) {
        error(env, "cannot read tracer arguments"); return false;
    }
    if (count != 0) { error(env, "this tracer operation takes no arguments"); return false; }
    return true;
}
static napi_value boolean(napi_env env, bool value) {
    napi_value result;
    if (napi_get_boolean(env, value, &result) != napi_ok) return error(env, "cannot return tracer cleanup state");
    return result;
}
static bool closed(const struct tracee *tracee) {
    return tracee->pid == 0 || tracee->state == TERMINAL || tracee->state == RELEASED;
}
static bool register_monitor(napi_env env) {
    if (active.controller.state != FORK_STOP || active.monitor.pid != 0) return true;
    unsigned long child = 0;
    if (ptrace(PTRACE_GETEVENTMSG, active.controller.pid, (void *)0, &child) == -1) {
        system_error(env, "PTRACE_GETEVENTMSG", errno); return false;
    }
    if (child == 0 || child > INT_MAX || child == (unsigned long)active.controller.pid || child == (unsigned long)getpid()) {
        error(env, "fork event returned an invalid monitor PID"); return false;
    }
    /* Record the auto-attached child before any further syscall or JS return. */
    active.monitor.pid = (pid_t)child;
    return true;
}
static bool observe(napi_env env, struct tracee *tracee, bool controller) {
    if (closed(tracee)) return true;
    if (tracee->state == UNKNOWN_STOP) {
        status_error(env, "unrecognized trace-stop remains owned", tracee); return false;
    }
    int status; pid_t result;
    do { result = waitpid(tracee->pid, &status, __WALL | WNOHANG); } while (result < 0 && errno == EINTR);
    if (result < 0) { system_error(env, "exact tracee waitpid", errno); return false; }
    if (result != 0) {
        tracee->status = status;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            tracee->state = TERMINAL;
            /* Natural exit cannot cross an uncontinued fork stop. An external
             * signal could instead lose its event and an unregistered child. */
            if (controller && WIFSIGNALED(status) && active.monitor.pid == 0) active.unknown_child = true;
        } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
                   ((unsigned int)status >> 16) == PTRACE_EVENT_FORK && controller) {
            tracee->state = FORK_STOP;
        } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
                   ((unsigned int)status >> 16) == PTRACE_EVENT_STOP &&
                   ((!controller && !active.monitor_continued) || (controller && active.interrupt_requested))) {
            tracee->state = controller ? INTERRUPT_STOP : INITIAL_STOP;
        } else {
            tracee->state = UNKNOWN_STOP;
            status_error(env, "unexpected trace-stop", tracee); return false;
        }
    }
    return !controller || register_monitor(env);
}
static napi_value arm(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; double number;
    if (!main_thread(env)) return NULL;
    if (active.thread != 0) return error(env, "an earlier tracer context is still owned");
    if (napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 1 ||
        napi_get_value_double(env, arguments[0], &number) != napi_ok ||
        !(number >= 1 && number <= INT_MAX) || number != (double)(pid_t)number || (pid_t)number == getpid()) {
        return error(env, "arm requires one positive, distinct integer controller PID");
    }
    pid_t controller = (pid_t)number;
    if (ptrace(PTRACE_SEIZE, controller, (void *)0, (void *)(uintptr_t)PTRACE_O_TRACEFORK) == -1)
        return system_error(env, "PTRACE_SEIZE", errno);
    active.thread = (pid_t)syscall(SYS_gettid); active.controller.pid = controller;
    napi_value result;
    if (napi_get_undefined(env, &result) != napi_ok) return error(env, "cannot return armed tracer state");
    return result;
}
static napi_value poll_fork(napi_env env, napi_callback_info info) {
    if (!main_thread(env) || !no_arguments(env, info)) return NULL;
    if (active.thread == 0 || active.releasing || active.controller_loss)
        return error(env, "fork capture requires an armed, non-releasing tracer");
    if (!observe(env, &active.controller, true)) return NULL;
    if (active.controller.state == TERMINAL) return status_error(env, "controller exited before fork capture", &active.controller);
    if (!observe(env, &active.monitor, false)) return NULL;
    if (active.monitor.state == TERMINAL) return status_error(env, "monitor exited before initial trace-stop", &active.monitor);
    napi_value result;
    if (active.controller.state == FORK_STOP && active.monitor.state == INITIAL_STOP) {
        if (napi_create_int32(env, active.monitor.pid, &result) != napi_ok) return error(env, "cannot return captured monitor PID");
    } else if (napi_get_null(env, &result) != napi_ok) return error(env, "cannot return pending fork capture");
    return result;
}
static bool progress_controller_loss(napi_env env) {
    if (!observe(env, &active.controller, true)) return false;
    if (active.controller.state == FORK_STOP) return true;
    if (active.controller.state != TERMINAL || !WIFSIGNALED(active.controller.status) ||
        WTERMSIG(active.controller.status) != SIGKILL) {
        status_error(env, "controller loss requires its actual SIGKILL termination", &active.controller); return false;
    }
    if (!observe(env, &active.monitor, false)) return false;
    if (!active.monitor_continued) {
        if (active.monitor.state != INITIAL_STOP) {
            status_error(env, "controller loss requires the captured monitor's initial stop", &active.monitor); return false;
        }
        /* Only a joined controller permits the monitor to close its inherited
         * writer and observe genuine EOF. The tracer never sends a signal. */
        if (ptrace(PTRACE_CONT, active.monitor.pid, (void *)0, (void *)0) == -1) {
            system_error(env, "PTRACE_CONT monitor after controller loss", errno); return false;
        }
        active.monitor.state = RUNNING; active.monitor_continued = true;
        return true;
    }
    if (active.monitor.state == RUNNING) return true;
    if (active.monitor.state != TERMINAL || !WIFEXITED(active.monitor.status) ||
        WEXITSTATUS(active.monitor.status) != 70) {
        status_error(env, "monitor did not naturally exit 70 after controller loss", &active.monitor); return false;
    }
    return true;
}
static napi_value finish_controller_loss(napi_env env, napi_callback_info info) {
    if (!main_thread(env) || !no_arguments(env, info)) return NULL;
    if (active.thread == 0 || active.releasing)
        return error(env, "controller loss requires a captured, non-releasing tracer");
    if (!active.controller_loss) {
        if (active.controller.state != FORK_STOP || active.monitor.pid == 0 || active.monitor.state != INITIAL_STOP)
            return error(env, "controller loss requires both genuine captured fork stops");
        active.controller_loss = true;
    }
    if (!progress_controller_loss(env)) return NULL;
    napi_value result;
    if (active.controller.state != TERMINAL || active.monitor.state != TERMINAL) {
        if (napi_get_null(env, &result) != napi_ok) return error(env, "cannot return pending controller loss");
        return result;
    }
    napi_value controller_signal, monitor_exit;
    if (napi_create_object(env, &result) != napi_ok ||
        napi_create_int32(env, WTERMSIG(active.controller.status), &controller_signal) != napi_ok ||
        napi_create_int32(env, WEXITSTATUS(active.monitor.status), &monitor_exit) != napi_ok ||
        napi_set_named_property(env, result, "controllerSignal", controller_signal) != napi_ok ||
        napi_set_named_property(env, result, "monitorExitCode", monitor_exit) != napi_ok)
        return error(env, "cannot return observed controller-loss statuses");
    memset(&active, 0, sizeof(active)); return result;
}
static bool detach(napi_env env, struct tracee *tracee, bool controller) {
    if (closed(tracee)) return true;
    if ((controller && tracee->state != FORK_STOP && tracee->state != INTERRUPT_STOP) ||
        (!controller && tracee->state != INITIAL_STOP)) {
        status_error(env, "cannot detach an unconfirmed trace-stop", tracee); return false;
    }
    if (ptrace(PTRACE_DETACH, tracee->pid, (void *)0, (void *)0) == -1) {
        system_error(env, "PTRACE_DETACH", errno); return false;
    }
    tracee->state = RELEASED; return true;
}
static napi_value release(napi_env env, napi_callback_info info) {
    if (!main_thread(env) || !no_arguments(env, info)) return NULL;
    if (active.thread == 0) return boolean(env, true);
    active.releasing = true;
    if (active.controller_loss) {
        if (!progress_controller_loss(env)) return NULL;
        if (active.controller.state != TERMINAL || active.monitor.state != TERMINAL) return boolean(env, false);
        napi_value result = boolean(env, true);
        if (result != NULL) memset(&active, 0, sizeof(active));
        return result;
    }
    if (!observe(env, &active.controller, true)) return NULL;
    if (active.unknown_child) return status_error(env, "signaled controller may retain an unregistered tracee", &active.controller);
    if (!observe(env, &active.monitor, false)) return NULL;
    if (active.controller.state == RUNNING) {
        if (!active.interrupt_requested) {
            if (ptrace(PTRACE_INTERRUPT, active.controller.pid, (void *)0, (void *)0) == -1)
                return system_error(env, "PTRACE_INTERRUPT", errno);
            active.interrupt_requested = true;
        }
        return boolean(env, false);
    }
    if (active.monitor.pid != 0 && active.monitor.state == RUNNING) return boolean(env, false);
    /* The resumed child still blocks on its genuine barrier until its original
     * controller is detached. No injected signal, shutdown or death claim. */
    if (!detach(env, &active.monitor, false) || !detach(env, &active.controller, true)) return NULL;
    if (!closed(&active.monitor) || !closed(&active.controller)) return error(env, "tracer still owns a process attachment");
    memset(&active, 0, sizeof(active)); return boolean(env, true);
}
static napi_value initialize(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        { "arm", NULL, arm, NULL, NULL, NULL, napi_default, NULL },
        { "pollFork", NULL, poll_fork, NULL, NULL, NULL, napi_default, NULL },
        { "finishControllerLoss", NULL, finish_controller_loss, NULL, NULL, NULL, napi_default, NULL },
        { "release", NULL, release, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_define_properties(env, exports, 4, properties) != napi_ok) return error(env, "cannot install test-only tracer interface");
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
