/* Test-only build of the actual native controller binding. Explicitly armed
 * faults affect only N-API queueing or reporting EIO after a real close.
 * The process-exit probe reaps its own real child before the real proc read.
 * Scopes, Runs and recovery evidence are never fabricated. */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned int fault_queue_calls;
static unsigned int fault_queue_remaining;
static atomic_bool close_fault_armed;
static atomic_uint close_fault_count;
static atomic_int close_fault_retired_fd = -1;
static atomic_int close_fault_reused_fd = -1;
static atomic_uint close_fault_opened_count;
static int close_fault_opened[256];
static dev_t close_fault_root_dev;
static ino_t close_fault_root_ino;
static char close_fault_sentinel[PATH_MAX];
static struct {
    pid_t pid;
    dev_t device;
    ino_t inode;
    int held_fd, exit_fd, read_errno, fresh_calls, fresh_errno, wait_status, error;
    char path[64];
    bool triggered, reaped, proc_retired, fresh_after_retirement;
} process_exit_probe;

static int fault_close(int fd);
static int probe_open(const char *name, int flags, ...);
static int probe_openat(int directory, const char *name, int flags, ...);

static napi_status fault_queue(napi_env env, napi_async_work work) {
    fault_queue_calls++;
    if (fault_queue_remaining > 0) { fault_queue_remaining--; return napi_generic_failure; }
    return napi_queue_async_work(env, work);
}
#define napi_queue_async_work fault_queue
#define close fault_close
#define open probe_open
#define openat probe_openat
#endif

#undef NAPI_MODULE
#define NAPI_MODULE(modname, register)
#include "../../../native/linux/worker-native.c"
#undef napi_queue_async_work
#undef close
#undef open
#undef openat

#if defined(__linux__)
static void reap_process_exit_subject(void) {
    int signaled = kill(process_exit_probe.pid, SIGKILL);
    int signal_error = signaled != 0 ? errno : 0;
    if (signal_error != 0) process_exit_probe.error = signal_error;
    /* EOF also retires the disposable child if signaling failed. Consume
     * this fixture-owned descriptor before close; never retry a reused FD. */
    int exit_fd = process_exit_probe.exit_fd;
    process_exit_probe.exit_fd = -1;
    bool channel_retired = close(exit_fd) == 0;
    if (!channel_retired) process_exit_probe.error = errno;
    pid_t joined;
    int options = signaled == 0 || signal_error == ESRCH || channel_retired ? 0 : WNOHANG;
    do { joined = waitpid(process_exit_probe.pid, &process_exit_probe.wait_status, options); } while (joined < 0 && errno == EINTR);
    process_exit_probe.reaped = joined == process_exit_probe.pid;
    if (!process_exit_probe.reaped && process_exit_probe.error == 0) process_exit_probe.error = joined < 0 ? errno : EBUSY;
}

static int probe_open(const char *name, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    bool fresh = process_exit_probe.triggered && strcmp(name, process_exit_probe.path) == 0;
    if (fresh) process_exit_probe.fresh_after_retirement = process_exit_probe.proc_retired;
    int result = open(name, flags, mode);
    int error = errno;
    if (fresh) {
        /* Record the production sampler's own fresh kernel cut, separately
         * from the independent verification performed after it returns. */
        process_exit_probe.fresh_calls++;
        process_exit_probe.fresh_errno = result < 0 ? error : 0;
    }
    errno = error;
    return result;
}

static int probe_openat(int directory, const char *name, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    struct stat held;
    if (process_exit_probe.pid > 0 && !process_exit_probe.triggered && strcmp(name, "stat") == 0 &&
        fstat(directory, &held) == 0 && held.st_dev == process_exit_probe.device && held.st_ino == process_exit_probe.inode) {
        /* sample_process already opened and validated this actual proc FD.
         * Reap only this fixture's exclusively owned child, then let Linux
         * itself determine the read result. No errno/result is substituted. */
        process_exit_probe.triggered = true;
        process_exit_probe.held_fd = directory;
        reap_process_exit_subject();
        int result = openat(directory, name, flags, mode);
        process_exit_probe.read_errno = result < 0 ? errno : 0;
        return result;
    }
    return openat(directory, name, flags, mode);
}

static int fault_close(int fd) {
    struct stat identity;
    bool identified = fstat(fd, &identity) == 0;
    int status = close(fd);
    if (status != 0) return status;
    if (process_exit_probe.triggered && fd == process_exit_probe.held_fd && identified &&
        identity.st_dev == process_exit_probe.device && identity.st_ino == process_exit_probe.inode)
        process_exit_probe.proc_retired = true;
    if (!identified || !S_ISDIR(identity.st_mode) || identity.st_dev != close_fault_root_dev ||
        identity.st_ino != close_fault_root_ino || !atomic_exchange(&close_fault_armed, false)) return 0;
    atomic_fetch_add(&close_fault_count, 1);
    atomic_store(&close_fault_retired_fd, fd);
    /* All descriptors here are actual opens owned by this test build. Fill
     * lower holes instead of assuming close's descriptor is the lowest one.
     * No JS/N-API callback runs on an async-work thread. The child later
     * verifies and explicitly closes each sentinel descriptor. */
    for (unsigned int index = 0; index < sizeof(close_fault_opened) / sizeof(close_fault_opened[0]); index++) {
        int candidate = open(close_fault_sentinel, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (candidate < 0) break;
        close_fault_opened[index] = candidate;
        atomic_store_explicit(&close_fault_opened_count, index + 1, memory_order_release);
        if (candidate == fd) { atomic_store(&close_fault_reused_fd, candidate); break; }
        if (candidate > fd) break;
    }
    errno = EIO;
    return -1;
}

static napi_value arm_queue_fault(napi_env env, napi_callback_info info) {
    (void)info;
    if (fault_queue_calls != 0) return failure(env, "queue fault must be armed before construction");
    fault_queue_remaining = 2;
    return undefined(env);
}

static napi_value set_close_fault(napi_env env, napi_callback_info info) {
    size_t argc = 2, length;
    napi_value args[2];
    uint64_t root;
    struct stat identity, sentinel;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 ||
        !number(env, args[0], &root) || root > INT32_MAX || fstat((int)root, &identity) != 0 ||
        !S_ISDIR(identity.st_mode) || (identity.st_mode & 07777) != 0700 || identity.st_uid != geteuid() ||
        napi_get_value_string_utf8(env, args[1], NULL, 0, &length) != napi_ok || length == 0 ||
        length >= sizeof(close_fault_sentinel) ||
        napi_get_value_string_utf8(env, args[1], close_fault_sentinel, sizeof(close_fault_sentinel), &length) != napi_ok ||
        strlen(close_fault_sentinel) != length || close_fault_sentinel[0] != '/' ||
        lstat(close_fault_sentinel, &sentinel) != 0 || !S_ISREG(sentinel.st_mode) || sentinel.st_uid != geteuid() ||
        atomic_load(&close_fault_count) != 0 || atomic_load(&close_fault_opened_count) != 0)
        return failure(env, "invalid actual-close test fault");
    close_fault_root_dev = identity.st_dev;
    close_fault_root_ino = identity.st_ino;
    atomic_store(&close_fault_armed, true);
    return undefined(env);
}

static napi_value disarm_close_fault(napi_env env, napi_callback_info info) {
    (void)info;
    atomic_store(&close_fault_armed, false);
    return undefined(env);
}

static napi_value close_fault_state(napi_env env, napi_callback_info info) {
    (void)info;
    napi_value result, opened, value;
    unsigned int count = atomic_load_explicit(&close_fault_opened_count, memory_order_acquire);
    if (napi_create_object(env, &result) != napi_ok || napi_create_array_with_length(env, count, &opened) != napi_ok) return NULL;
    set_number(env, result, "faulted", atomic_load(&close_fault_count));
    set_number(env, result, "retiredFd", atomic_load(&close_fault_retired_fd));
    set_number(env, result, "reusedFd", atomic_load(&close_fault_reused_fd));
    for (unsigned int index = 0; index < count; index++) {
        if (napi_create_int32(env, close_fault_opened[index], &value) != napi_ok ||
            napi_set_element(env, opened, index, value) != napi_ok) return NULL;
    }
    if (napi_set_named_property(env, result, "opened", opened) != napi_ok) return NULL;
    return result;
}

static napi_value queue_count(napi_env env, napi_callback_info info) {
    (void)info;
    napi_value result;
    if (napi_create_uint32(env, fault_queue_calls, &result) != napi_ok) return NULL;
    return result;
}

/* This approved test-only seam exercises the production proc sampler, not a
 * controller/worker/death capability. Its subject is a real disposable child;
 * no scope identity, durable fact or authority-bearing object is created. */
static napi_value sample_reaped_process(napi_env env, napi_callback_info info) {
    (void)info;
    if (process_exit_probe.pid != 0 || fault_queue_calls != 0 || atomic_load(&close_fault_count) != 0)
        return failure(env, "process-exit probe requires a fresh isolated test binding");
    int channel[2];
    if (pipe2(channel, O_CLOEXEC) != 0) return failure(env, "actual process-exit channel unavailable");
    pid_t child = fork();
    if (child < 0) {
        int read_end = close(channel[0]), write_end = close(channel[1]);
        return failure(env, read_end == 0 && write_end == 0 ? "actual process-exit subject could not be born" :
            "failed process-exit birth channel could not retire");
    }
    if (child == 0) {
        if (close(channel[1]) != 0) _exit(70);
        char byte; ssize_t received;
        do { received = read(channel[0], &byte, 1); } while (received < 0 && errno == EINTR);
        _exit(received == 0 ? 0 : 70);
    }
    process_exit_probe.pid = child;
    process_exit_probe.held_fd = -1;
    process_exit_probe.exit_fd = channel[1];
    if (close(channel[0]) != 0) process_exit_probe.error = errno;
    char path[64], token[CLIQ_WORKER_TOKEN_BYTES];
    struct stat identity;
    int length = snprintf(path, sizeof(path), "/proc/%ld", (long)child);
    bool initialized = length > 0 && (size_t)length < sizeof(path) && stat(path, &identity) == 0 &&
        cliq_process_token(child, token);
    if (initialized) {
        process_exit_probe.device = identity.st_dev;
        process_exit_probe.inode = identity.st_ino;
        memcpy(process_exit_probe.path, path, (size_t)length + 1);
    }
    struct controller observer = {0};
    struct process_sample sample = {0};
    bool sampled = initialized && sample_process(&observer, child, &sample, false);
    /* Failure to reach the production read must not abandon this real child.
     * Never signal again after a wait attempt whose ownership is uncertain. */
    if (!process_exit_probe.triggered) reap_process_exit_subject();
    bool held_closed = false;
    if (process_exit_probe.held_fd >= 0) {
        struct stat remaining;
        held_closed = fstat(process_exit_probe.held_fd, &remaining) != 0 && errno == EBADF;
    }
    int fresh = initialized ? open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    int fresh_errno = fresh < 0 ? errno : 0;
    if (fresh >= 0 && close(fresh) != 0) return failure(env, "fresh process probe descriptor could not retire");
    if (!initialized || !process_exit_probe.reaped || process_exit_probe.error != 0)
        return failure(env, "actual process-exit probe failed to establish and join its subject");
    napi_value result;
    if (napi_create_object(env, &result) != napi_ok) return NULL;
    set_number(env, result, "pid", child);
    set_number(env, result, "uid", identity.st_uid);
    set_string(env, result, "originalStartToken", token);
    set_number(env, result, "readReached", process_exit_probe.triggered);
    set_number(env, result, "reapedBySigkill", WIFSIGNALED(process_exit_probe.wait_status) && WTERMSIG(process_exit_probe.wait_status) == SIGKILL);
    set_number(env, result, "readErrno", process_exit_probe.read_errno);
    set_number(env, result, "productionFreshCalls", process_exit_probe.fresh_calls);
    set_number(env, result, "productionFreshErrno", process_exit_probe.fresh_errno);
    set_number(env, result, "productionFreshAfterRetirement", process_exit_probe.fresh_after_retirement);
    set_number(env, result, "freshErrno", fresh_errno);
    set_number(env, result, "heldProcClosed", held_closed);
    set_number(env, result, "sampled", sampled);
    set_number(env, result, "absent", sample.absent);
    set_number(env, result, "retirementFailed", observer.retirement_failed);
    set_number(env, result, "nativeSticky", atomic_load(&native_retirement_failed));
    return result;
}

/* Called only after the test freezes the unsuccessful close observation.
 * Resume the existing real join for that exact branded receiver so a RED
 * result does not abandon its owned FD or hang the cleanup hook. This does
 * not directly settle a promise or manufacture join/authority state. */
static napi_value resume_join(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    struct controller *controller;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1 ||
        !tagged(env, args[0], &CONTROLLER_TAG, (void **)&controller))
        return failure(env, "invalid test cleanup receiver");
    if (!controller->cleanup_done && !close_controller(controller))
        return failure(env, "test cleanup join could not be queued");
    return undefined(env);
}
#endif

NAPI_MODULE_INIT() {
    initialize(env, exports);
#if defined(__linux__)
    const napi_property_descriptor methods[] = {
        { "armQueueFault", NULL, arm_queue_fault, NULL, NULL, NULL, napi_default, NULL },
        { "setCloseFault", NULL, set_close_fault, NULL, NULL, NULL, napi_default, NULL },
        { "disarmCloseFault", NULL, disarm_close_fault, NULL, NULL, NULL, napi_default, NULL },
        { "closeFaultState", NULL, close_fault_state, NULL, NULL, NULL, napi_default, NULL },
        { "queueCalls", NULL, queue_count, NULL, NULL, NULL, napi_default, NULL },
        { "sampleReapedProcess", NULL, sample_reaped_process, NULL, NULL, NULL, napi_default, NULL },
        { "resumeJoin", NULL, resume_join, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return NULL;
#endif
    return exports;
}
