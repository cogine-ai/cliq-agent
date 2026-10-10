/* Test-only build of the real helper. A fault is reported only after the
 * actual close completed; no process observation or authority is fabricated. */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static int fault_close(int fd);
#ifdef __linux__
static int fault_fclose(FILE *file);
#endif
#undef NAPI_MODULE
#define NAPI_MODULE(modname, register)
#define close fault_close
#ifdef __linux__
#define fclose fault_fclose
#endif
#include "../../../native/state-owner/state-owner.c"
#undef close
#undef fclose

static napi_env fault_env;
static napi_ref fault_callback;
static char fault_point[32];
static int fault_ordinal;

static int inject(const char *point, int fd) {
    if (!fault_callback || strcmp(point, fault_point) != 0 || --fault_ordinal != 0) return 0;
    napi_value callback, receiver, argument, result;
    int32_t error;
    if (napi_get_reference_value(fault_env, fault_callback, &callback) != napi_ok ||
        napi_get_undefined(fault_env, &receiver) != napi_ok ||
        napi_create_int32(fault_env, fd, &argument) != napi_ok) return EIO;
    napi_delete_reference(fault_env, fault_callback);
    fault_callback = NULL;
    if (napi_call_function(fault_env, receiver, callback, 1, &argument, &result) != napi_ok ||
        napi_get_value_int32(fault_env, result, &error) != napi_ok) return EIO;
    return error;
}

static int fault_close(int fd) {
    struct stat identity;
    int identified = fstat(fd, &identity) == 0;
    int status = close(fd);
    if (status < 0) return status;
    int error = inject("after_close", fd);
    if (!error && identified && S_ISDIR(identity.st_mode)) error = inject("after_directory_close", fd);
    if (!error && identified && S_ISREG(identity.st_mode) && identity.st_size > 0)
        error = inject("after_image_close", fd);
    if (error) { errno = error; return -1; }
    return 0;
}

#ifdef __linux__
static int fault_fclose(FILE *file) {
    int fd = fileno(file);
    int status = fclose(file);
    if (status < 0) return status;
    int error = inject("after_fclose", fd);
    if (error) { errno = error; return EOF; }
    return 0;
}
#endif

static napi_value set_fault(napi_env env, napi_callback_info info) {
    size_t argc = 3, length;
    napi_value argv[3], result;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc != 3 ||
        napi_get_value_string_utf8(env, argv[0], fault_point, sizeof(fault_point), &length) != napi_ok ||
        napi_get_value_int32(env, argv[1], &fault_ordinal) != napi_ok || fault_ordinal < 1)
        return native_error(env, "invalid test fault");
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
