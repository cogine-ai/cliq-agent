/* Test-only build of the actual native controller binding. Explicitly armed
 * faults affect only N-API queueing or reporting EIO after a real close.
 * Process/scopes and recovery evidence are never fabricated. */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

static int fault_close(int fd);

static napi_status fault_queue(napi_env env, napi_async_work work) {
    fault_queue_calls++;
    if (fault_queue_remaining > 0) { fault_queue_remaining--; return napi_generic_failure; }
    return napi_queue_async_work(env, work);
}
#define napi_queue_async_work fault_queue
#define close fault_close
#endif

#undef NAPI_MODULE
#define NAPI_MODULE(modname, register)
#include "../../../native/linux/worker-native.c"
#undef napi_queue_async_work
#undef close

#if defined(__linux__)
static int fault_close(int fd) {
    struct stat identity;
    bool identified = fstat(fd, &identity) == 0;
    int status = close(fd);
    if (status != 0) return status;
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
        { "resumeJoin", NULL, resume_join, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok) return NULL;
#endif
    return exports;
}
