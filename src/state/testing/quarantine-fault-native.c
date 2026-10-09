/* Test-only build of the real helper with deterministic syscall barriers.
 * The production binary has no fault controls or callback seam. */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

static int fault_fsync(int fd);
static int fault_rename(int from, const char *source, int to, const char *target, unsigned int flags);
static int fault_unlink(int directory, const char *name, int flags);
#undef NAPI_MODULE
#define NAPI_MODULE(modname, register)
#define fsync fault_fsync
#define unlinkat fault_unlink
#ifdef __APPLE__
#define renameatx_np fault_rename
#else
#define renameat2 fault_rename
#endif
#include "../../../native/state-owner/state-owner.c"
#undef fsync
#undef unlinkat
#ifdef __APPLE__
#undef renameatx_np
#else
#undef renameat2
#endif

static napi_env fault_env;
static napi_ref fault_callback;
static char fault_point[32];
static int fault_ordinal;

static int inject(const char *point) {
    if (!fault_callback || strcmp(point, fault_point) != 0 || --fault_ordinal != 0) return 0;
    napi_value callback, receiver, result;
    int32_t error;
    if (napi_get_reference_value(fault_env, fault_callback, &callback) != napi_ok ||
        napi_get_undefined(fault_env, &receiver) != napi_ok) return EIO;
    napi_delete_reference(fault_env, fault_callback);
    fault_callback = NULL;
    if (napi_call_function(fault_env, receiver, callback, 0, NULL, &result) != napi_ok ||
        napi_get_value_int32(fault_env, result, &error) != napi_ok) return EIO;
    return error;
}

static int fault_fsync(int fd) {
    int error = inject("fsync");
    if (error) { errno = error; return -1; }
    return fsync(fd);
}

static int fault_unlink(int directory, const char *name, int flags) {
    int error = inject("before_unlink");
    if (error) { errno = error; return -1; }
    return unlinkat(directory, name, flags);
}

static int fault_rename(int from, const char *source, int to, const char *target, unsigned int flags) {
    int error = inject("before_rename");
    if (error) { errno = error; return -1; }
#ifdef __APPLE__
    int status = renameatx_np(from, source, to, target, flags);
#else
    int status = renameat2(from, source, to, target, flags);
#endif
    if (status < 0) return status;
    error = inject("after_rename");
    if (error) { errno = error; return -1; }
    return 0;
}

static napi_value set_fault(napi_env env, napi_callback_info info) {
    size_t argc = 3, length;
    napi_value argv[3], result;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 3 ||
        napi_get_value_string_utf8(env, argv[0], fault_point, sizeof(fault_point), &length) != napi_ok ||
        napi_get_value_int32(env, argv[1], &fault_ordinal) != napi_ok || fault_ordinal < 1) return native_error(env, "invalid test fault");
    if (fault_callback) napi_delete_reference(env, fault_callback);
    if (napi_create_reference(env, argv[2], 1, &fault_callback) != napi_ok) return NULL;
    fault_env = env;
    napi_get_undefined(env, &result);
    return result;
}

NAPI_MODULE_INIT() {
    initialize(env, exports);
    const napi_property_descriptor method = {"setFault", NULL, set_fault, NULL, NULL, NULL, napi_default, NULL};
    if (napi_define_properties(env, exports, 1, &method) != napi_ok) return NULL;
    return exports;
}
