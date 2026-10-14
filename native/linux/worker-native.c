#define _GNU_SOURCE
#include <node_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "worker-common.h"
#include "worker-reservation.h"
#include <linux/magic.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>

static const napi_type_tag IMAGE_TAG = { UINT64_C(0x671ca1bc736f4411), UINT64_C(0xa1d7e8ec9f001820) };
static const napi_type_tag CONTROLLER_TAG = { UINT64_C(0x875a7b5a31bc4112), UINT64_C(0xbf12ad50275ed149) };
static const napi_type_tag SCOPE_TAG = { UINT64_C(0x00d75ac01fa14d87), UINT64_C(0x9b1c5a0256e81d29) };

/* The fixed loaded native image owns this uncertainty across controllers and
 * N-API environments. A new receiver cannot erase an unjoined resource. */
static atomic_bool native_retirement_failed;

struct image { int fd; };
struct native_scope;
struct controller { int socket, stdout_fd, stderr_fd; pid_t pid; bool closed, ready, cleanup_queued, env_closing, reaped, cleanup_done;
    int anchor_root, controller_parent, controller_leaf, input_fd, child_socket, transfer[4];
    struct stat root_identity, parent_identity, leaf_identity;
    char root_path[PATH_MAX], leaf_name[64];
    bool leaf_owned, leaf_initialized, constructor_failed, retirement_failed;
    unsigned int next_scope, pending; char token[CLIQ_WORKER_TOKEN_BYTES]; unsigned int references;
    struct native_scope *scopes, *pending_scope;
    struct cliq_worker_packet retained, reservation, reservation_inspection;
    bool reservation_bound, inspection_only, retained_observed;
    napi_env env; napi_async_work cleanup_work; napi_async_cleanup_hook_handle cleanup_hook;
    napi_deferred close_deferred; napi_ref close_promise;
};
struct native_scope { struct controller *controller; struct native_scope *next, *parent; unsigned int id, references;
    bool ready, released, activated, stopped, invocation, result_received; int image_fd;
    struct cliq_worker_packet identity, result; };

static napi_value failure(napi_env env, const char *message) {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) != napi_ok || !pending)
        napi_throw_error(env, "RECOVERY_REQUIRED", message);
    return NULL;
}
static napi_value undefined(napi_env env) { napi_value result; napi_get_undefined(env, &result); return result; }

static bool tagged(napi_env env, napi_value value, const napi_type_tag *tag, void **result) {
    bool valid = false;
    return napi_check_object_type_tag(env, value, tag, &valid) == napi_ok && valid &&
        napi_unwrap(env, value, result) == napi_ok && *result != NULL;
}

static bool number(napi_env env, napi_value value, uint64_t *output) {
    double observed;
    if (napi_get_value_double(env, value, &observed) != napi_ok || !isfinite(observed) || observed < 0 || observed > 9007199254740991.0 ||
        observed != (double)(uint64_t)observed) return false;
    *output = (uint64_t)observed; return true;
}

static bool field_number(napi_env env, napi_value value, const char *name, uint64_t *output) {
    napi_value field;
    return napi_get_named_property(env, value, name, &field) == napi_ok && number(env, field, output);
}

static bool field_string(napi_env env, napi_value value, const char *name, char *output, size_t capacity) {
    napi_value field; size_t length;
    if (napi_get_named_property(env, value, name, &field) != napi_ok ||
        napi_get_value_string_utf8(env, field, NULL, 0, &length) != napi_ok || length == 0 || length >= capacity) return false;
    return napi_get_value_string_utf8(env, field, output, capacity, &length) == napi_ok && strlen(output) == length;
}

static void set_number(napi_env env, napi_value object, const char *name, double value) {
    napi_value property; napi_create_double(env, value, &property); napi_set_named_property(env, object, name, property);
}
static void set_string(napi_env env, napi_value object, const char *name, const char *value) {
    napi_value property; napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &property); napi_set_named_property(env, object, name, property);
}

/* Consume before close: an uncertain close is never retried on a reused FD. */
static bool retire_descriptor(int *descriptor) {
    int owned = *descriptor; *descriptor = -1;
    if (owned < 0 || close(owned) == 0) return true;
    atomic_store(&native_retirement_failed, true);
    return false;
}

static bool same_directory(const struct stat *expected, const struct stat *actual) {
    return S_ISDIR(actual->st_mode) && expected->st_dev == actual->st_dev && expected->st_ino == actual->st_ino &&
        expected->st_uid == actual->st_uid && expected->st_gid == actual->st_gid && expected->st_mode == actual->st_mode;
}

static bool private_cgroup(int directory, struct stat *identity) {
    struct statfs filesystem;
    return fstat(directory, identity) == 0 && S_ISDIR(identity->st_mode) && identity->st_uid == geteuid() &&
        identity->st_gid == getegid() && (identity->st_mode & 07777) == 0700 &&
        fstatfs(directory, &filesystem) == 0 && filesystem.f_type == CGROUP2_SUPER_MAGIC;
}

static bool read_bounded(struct controller *controller, int directory, const char *name, char *buffer, size_t capacity) {
    int file = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file < 0) return false;
    size_t used = 0; bool valid = true;
    while (used < capacity - 1) {
        ssize_t bytes = read(file, buffer + used, capacity - 1 - used);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) { valid = false; break; }
        if (bytes == 0) break;
        used += (size_t)bytes;
    }
    if (valid && used == capacity - 1) {
        char extra; ssize_t bytes;
        do { bytes = read(file, &extra, 1); } while (bytes < 0 && errno == EINTR);
        if (bytes != 0) { if (bytes > 0) errno = EOVERFLOW; valid = false; }
    }
    int error = errno;
    if (!retire_descriptor(&file)) { error = errno; valid = false; controller->retirement_failed = true; }
    buffer[used] = '\0'; errno = error; return valid;
}

static bool blank_control(const char *value) {
    for (; *value; value++) if (*value != ' ' && *value != '\t' && *value != '\n') return false;
    return true;
}

static bool domain_without_internal_processes(struct controller *controller, int directory, bool leaf) {
    char value[512];
    if (!read_bounded(controller, directory, "cgroup.type", value, sizeof(value)) || strcmp(value, "domain\n") != 0 ||
        !read_bounded(controller, directory, "cgroup.procs", value, sizeof(value)) || !blank_control(value)) return false;
    return !leaf || (read_bounded(controller, directory, "cgroup.subtree_control", value, sizeof(value)) && blank_control(value));
}

static bool anchor_current(struct controller *controller) {
    struct stat current, named;
    return private_cgroup(controller->anchor_root, &current) && same_directory(&controller->root_identity, &current) &&
        lstat(controller->root_path, &named) == 0 && same_directory(&controller->root_identity, &named) &&
        private_cgroup(controller->controller_parent, &current) && same_directory(&controller->parent_identity, &current) &&
        fstatat(controller->anchor_root, "controllers", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_directory(&controller->parent_identity, &named) &&
        private_cgroup(controller->controller_leaf, &current) && same_directory(&controller->leaf_identity, &current) &&
        fstatat(controller->controller_parent, controller->leaf_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_directory(&controller->leaf_identity, &named);
}

static bool create_controller_leaf(struct controller *controller, int root) {
    controller->anchor_root = fcntl(root, F_DUPFD_CLOEXEC, 4);
    if (controller->anchor_root < 0 || !private_cgroup(controller->anchor_root, &controller->root_identity)) return false;
    char descriptor[64];
    int length = snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", controller->anchor_root);
    if (length < 0 || (size_t)length >= sizeof(descriptor)) return false;
    ssize_t bytes = readlink(descriptor, controller->root_path, sizeof(controller->root_path) - 1);
    if (bytes <= 0 || (size_t)bytes >= sizeof(controller->root_path) - 1) return false;
    controller->root_path[bytes] = '\0';
    const char *mount = "/sys/fs/cgroup/";
    struct stat named;
    if (strncmp(controller->root_path, mount, strlen(mount)) != 0 || strchr(controller->root_path, '\n') ||
        lstat(controller->root_path, &named) != 0 || !same_directory(&controller->root_identity, &named) ||
        !domain_without_internal_processes(controller, controller->anchor_root, false)) return false;
    if (mkdirat(controller->anchor_root, "controllers", 0700) != 0 && errno != EEXIST) return false;
    controller->controller_parent = openat(controller->anchor_root, "controllers", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (controller->controller_parent < 0 || !private_cgroup(controller->controller_parent, &controller->parent_identity) ||
        !domain_without_internal_processes(controller, controller->controller_parent, false)) return false;
    for (unsigned int attempt = 0; attempt < 16; attempt++) {
        unsigned char random[16]; size_t used = 0;
        while (used < sizeof(random)) {
            ssize_t count = getrandom(random + used, sizeof(random) - used, 0);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return false;
            used += (size_t)count;
        }
        static const char digits[] = "0123456789abcdef";
        memcpy(controller->leaf_name, "controller-", 11);
        for (size_t i = 0; i < sizeof(random); i++) {
            controller->leaf_name[11 + i * 2] = digits[random[i] >> 4];
            controller->leaf_name[12 + i * 2] = digits[random[i] & 15];
        }
        controller->leaf_name[43] = '\0';
        if (mkdirat(controller->controller_parent, controller->leaf_name, 0700) == 0) { controller->leaf_owned = true; break; }
        if (errno != EEXIST) return false;
    }
    if (!controller->leaf_owned) return false;
    controller->controller_leaf = openat(controller->controller_parent, controller->leaf_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (controller->controller_leaf < 0 || !private_cgroup(controller->controller_leaf, &controller->leaf_identity) ||
        !domain_without_internal_processes(controller, controller->controller_leaf, true)) return false;
    controller->leaf_initialized = true;
    return anchor_current(controller);
}

struct process_sample { bool absent; uid_t uid; char token[CLIQ_WORKER_TOKEN_BYTES], cgroup[PATH_MAX + 8]; };

/* A zombie retains its original start token. Only kernel absence or a distinct
 * start lifetime is absence; cgroup.procs/populated cannot prove this. */
static bool sample_process(struct controller *controller, pid_t pid, struct process_sample *sample, bool membership) {
    char name[64], value[4096];
    int length = snprintf(name, sizeof(name), "/proc/%ld", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(name)) return false;
    for (unsigned int cut = 0; cut < 2; cut++) {
        memset(sample, 0, sizeof(*sample));
        int process = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (process < 0) { sample->absent = errno == ENOENT; return sample->absent; }
        struct stat identity; struct statfs filesystem;
        bool directory_valid = fstat(process, &identity) == 0 && fstatfs(process, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC;
        bool stat_read = directory_valid && read_bounded(controller, process, "stat", value, sizeof(value));
        int stat_error = stat_read ? 0 : errno;
        bool valid = stat_read && (!membership || read_bounded(controller, process, "cgroup", sample->cgroup, sizeof(sample->cgroup)));
        if (!retire_descriptor(&process)) { controller->retirement_failed = true; return false; }
        if (!valid) {
            /* A reaped held proc subject may fail stat with ENOENT/ESRCH.
             * Only a fresh open after successful retirement can prove absence. */
            if (cut == 0 && directory_valid && !stat_read && (stat_error == ENOENT || stat_error == ESRCH) &&
                !controller->retirement_failed && !atomic_load(&native_retirement_failed)) continue;
            return false;
        }
        sample->uid = identity.st_uid;
        char *cursor = strrchr(value, ')');
        if (!cursor || cursor[1] != ' ') return false;
        cursor += 2;
        for (int field = 3; field < 22; field++) { cursor = strchr(cursor, ' '); if (!cursor) return false; cursor++; }
        char *end = strchr(cursor, ' ');
        if (!end || end == cursor || (size_t)(end - cursor) > 32) return false;
        for (char *digit = cursor; digit < end; digit++) if (*digit < '0' || *digit > '9') return false;
        length = snprintf(sample->token, sizeof(sample->token), "linux-proc-start-ticks:%.*s", (int)(end - cursor), cursor);
        return length > 0 && (size_t)length < sizeof(sample->token);
    }
    return false;
}

static bool controller_placement(struct controller *controller, const char *token) {
    struct process_sample first, last;
    char expected[PATH_MAX + 8];
    int length = snprintf(expected, sizeof(expected), "0::%s/controllers/%s\n", controller->root_path + strlen("/sys/fs/cgroup"), controller->leaf_name);
    return length > 0 && (size_t)length < sizeof(expected) && sample_process(controller, controller->pid, &first, true) && !first.absent &&
        first.uid == geteuid() && strcmp(first.token, token) == 0 && strcmp(first.cgroup, expected) == 0 &&
        anchor_current(controller) && sample_process(controller, controller->pid, &last, true) && !last.absent &&
        last.uid == first.uid && strcmp(last.token, first.token) == 0 && strcmp(last.cgroup, first.cgroup) == 0;
}

static void retire_controller_leaf(struct controller *controller) {
    if (!controller->leaf_owned) return;
    if (!controller->leaf_initialized || !anchor_current(controller)) { controller->retirement_failed = true; return; }
    for (struct native_scope *scope = controller->scopes; scope; scope = scope->next) {
        /* A request without READY may already have forked a birth monitor.
         * Keep its original protected inode; no new ledger or guessed proof. */
        if (!scope->ready) return;
        int64_t producers[] = { scope->identity.monitor_pid, scope->identity.namespace_init_pid, scope->identity.pid };
        const char *tokens[] = { scope->identity.monitor_start_token, scope->identity.init_native_start_token, scope->identity.start_token };
        for (size_t i = 0; i < 3; i++) {
            if (producers[i] <= 0 || producers[i] > INT32_MAX || !*tokens[i]) return;
            struct process_sample current;
            if (!sample_process(controller, (pid_t)producers[i], &current, false)) { controller->retirement_failed = true; return; }
            if (!current.absent && strcmp(current.token, tokens[i]) == 0) return;
        }
    }
    char value[512];
    if (!read_bounded(controller, controller->controller_leaf, "cgroup.events", value, sizeof(value))) { controller->retirement_failed = true; return; }
    bool empty = strncmp(value, "populated 0\n", 12) == 0 || strstr(value, "\npopulated 0\n") != NULL;
    bool populated = strncmp(value, "populated 1\n", 12) == 0 || strstr(value, "\npopulated 1\n") != NULL;
    if (!empty) { if (!populated) controller->retirement_failed = true; return; }
    if (!domain_without_internal_processes(controller, controller->controller_leaf, true) || !anchor_current(controller)) {
        controller->retirement_failed = true; return;
    }
    if (unlinkat(controller->controller_parent, controller->leaf_name, AT_REMOVEDIR) != 0) {
        /* The kernel refuses a concurrently populated or nonempty directory.
         * An attempted but incomplete retirement cannot resolve this join. */
        controller->retirement_failed = true;
        return;
    }
}

static void controller_release(struct controller *controller) {
    if (--controller->references == 0) free(controller);
}

static void scope_release_memory(struct native_scope *scope) {
    if (--scope->references != 0) return;
    if (!retire_descriptor(&scope->image_fd)) scope->controller->retirement_failed = true;
    controller_release(scope->controller); free(scope);
}

static void revoke_controller(struct controller *controller) {
    if (controller->closed) return;
    controller->closed = true;
    if (controller->socket >= 0 && shutdown(controller->socket, SHUT_RDWR) != 0 && errno != ENOTCONN)
        controller->retirement_failed = true;
    if (!retire_descriptor(&controller->socket)) controller->retirement_failed = true;
}

static void reap_controller(napi_env env, void *data) {
    (void)env;
    struct controller *controller = data;
    if (controller->pid <= 0) { controller->reaped = true; retire_controller_leaf(controller); return; }
    /* Channel revocation happened on the main thread before this join. This
     * worker never reads a shared/reused FD and reaps only its exact child. */
    kill(controller->pid, SIGTERM);
    struct timespec pause = { 0, 10000000 };
    bool reaped = false;
    for (unsigned int attempt = 0; attempt < 600; attempt++) {
        pid_t result = waitpid(controller->pid, NULL, WNOHANG);
        if (result == controller->pid || (result < 0 && errno == ECHILD)) { reaped = true; break; }
        nanosleep(&pause, NULL);
    }
    if (!reaped) {
        int signaled = kill(controller->pid, SIGKILL);
        int options = signaled == 0 || errno == ESRCH ? 0 : WNOHANG;
        pid_t result;
        /* A failed signal cannot justify a blocking join of a still-live
         * child. Even after a successful signal, only waitpid's exact-child
         * result (or ECHILD for this exclusively owned child) proves joined. */
        do { result = waitpid(controller->pid, NULL, options); } while (result < 0 && errno == EINTR);
        reaped = result == controller->pid || (result < 0 && errno == ECHILD);
    }
    controller->reaped = reaped;
    if (reaped) retire_controller_leaf(controller);
}

static void settle_controller_close(napi_env env, struct controller *controller) {
    if (!controller->env_closing && controller->close_deferred) {
        if (controller->reaped && !controller->retirement_failed) napi_resolve_deferred(env, controller->close_deferred, undefined(env));
        else {
            napi_value code, message, error;
            napi_create_string_utf8(env, "RECOVERY_REQUIRED", NAPI_AUTO_LENGTH, &code);
            napi_create_string_utf8(env, "native controller resource join failed", NAPI_AUTO_LENGTH, &message);
            napi_create_error(env, code, message, &error); napi_reject_deferred(env, controller->close_deferred, error);
        }
    }
    controller->close_deferred = NULL;
}

static void cleanup_complete(napi_env env, napi_status status, void *data) {
    struct controller *controller = data;
    if (status != napi_ok) {
        /* Work is never explicitly cancelled; no successful close can be
         * published when joining the trusted controller was unavailable. */
        controller->reaped = false;
    }
    int *resources[] = { &controller->stdout_fd, &controller->stderr_fd, &controller->input_fd, &controller->child_socket,
        &controller->controller_leaf, &controller->controller_parent, &controller->anchor_root,
        &controller->transfer[0], &controller->transfer[1], &controller->transfer[2], &controller->transfer[3] };
    for (size_t i = 0; i < sizeof(resources) / sizeof(resources[0]); i++)
        if (!retire_descriptor(resources[i])) controller->retirement_failed = true;
    while (controller->scopes) {
        struct native_scope *scope = controller->scopes; controller->scopes = scope->next;
        if (!retire_descriptor(&scope->image_fd)) controller->retirement_failed = true;
        scope_release_memory(scope);
    }
    if (controller->close_promise) { napi_delete_reference(env, controller->close_promise); controller->close_promise = NULL; }
    napi_delete_async_work(env, controller->cleanup_work); controller->cleanup_work = NULL;
    napi_remove_async_cleanup_hook(controller->cleanup_hook); controller->cleanup_hook = NULL;
    /* Only this main-thread completion publishes fully joined resources.
     * The worker's reaped result must not be read before this callback. */
    controller->cleanup_done = true;
    if (!controller->reaped || controller->retirement_failed) atomic_store(&native_retirement_failed, true);
    settle_controller_close(env, controller);
    controller_release(controller);
}

static bool close_controller(struct controller *controller) {
    revoke_controller(controller);
    if (controller->cleanup_queued) return true;
    controller->cleanup_queued = true;
    if (napi_queue_async_work(controller->env, controller->cleanup_work) == napi_ok) return true;
    controller->cleanup_queued = false; return false;
}

static void cleanup_hook(napi_async_cleanup_hook_handle handle, void *data) {
    (void)handle; struct controller *controller = data;
    controller->env_closing = true;
    (void)close_controller(controller);
}

/* Exactly one outstanding request on this fixed private channel. No durable
 * queue, arbitrary callback or background reader exists. */
static bool begin_request(struct controller *controller, struct native_scope *scope,
                          const struct cliq_worker_packet *request, const int *fds, size_t count) {
    if (controller->closed || !controller->ready || controller->pending != 0) return false;
    if (atomic_load(&native_retirement_failed) && request->command != CLIQ_STOP_SCOPE &&
        request->command != CLIQ_TERMINATE_RETAINED && request->command != CLIQ_INSPECT_RESERVATION) return false;
    controller->pending = request->command; controller->pending_scope = scope;
    if (cliq_send(controller->socket, request, fds, count)) return true;
    (void)close_controller(controller); return false;
}

/* Diagnostics contain only fixed numeric protocol metadata, never tokens,
 * paths, payloads or stderr. boundary: 1=request state, 2=receive, 3=reply.
 * An absent/unvalidated reply is represented by zeros, not decoded bytes. */
static int poll_failure(struct controller *controller, struct native_scope *scope, uint32_t expected,
                        const struct cliq_worker_packet *response, size_t descriptors, int receive_errno,
                        unsigned int boundary) {
    char message[384];
    int length = snprintf(message, sizeof(message),
        "native controller reply failed: request=%u requestScope=%u expected=%u expectedScope=%u "
        "received=%u receivedScope=%u status=%u fds=%zu receiveErrno=%d boundary=%u",
        (unsigned int)controller->pending, scope && controller->pending_scope == scope ? scope->id : 0,
        (unsigned int)expected, scope ? scope->id : 0,
        response ? (unsigned int)response->command : 0, response ? (unsigned int)response->scope : 0,
        response ? (unsigned int)response->status : 0, descriptors, receive_errno, boundary);
    (void)failure(controller->env, length >= 0 && (size_t)length < sizeof(message) ? message :
        "native controller reply failed; diagnostic formatting unavailable");
    return -1;
}

/* 0 = not ready, 1 = exact authenticated reply, -1 = fail closed with a pending exception. */
static int poll_response(struct controller *controller, struct native_scope *scope, uint32_t expected,
                         struct cliq_worker_packet *response) {
    if (controller->closed || controller->pending_scope != scope || controller->pending == 0)
        return poll_failure(controller, scope, expected, NULL, 0, 0, 1);
    int fds[5]; size_t count;
    if (!cliq_receive_flags(controller->socket, response, fds, &count, MSG_DONTWAIT)) {
        int receive_errno = errno;
        if (receive_errno == EAGAIN || receive_errno == EWOULDBLOCK) return 0;
        (void)close_controller(controller);
        return poll_failure(controller, scope, expected, NULL, 0, receive_errno, 2);
    }
    for (size_t i = 0; i < count; i++) close(fds[i]);
    if (count != 0 || response->status != 0 || response->command != expected || response->scope != (scope ? scope->id : 0)) {
        (void)close_controller(controller);
        return poll_failure(controller, scope, expected, response, count, 0, 3);
    }
    controller->pending = 0; controller->pending_scope = NULL; return 1;
}

static void finalize_controller(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    struct controller *controller = data;
    (void)close_controller(controller); controller_release(controller);
}
static void finalize_scope(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    struct native_scope *scope = data;
    /* The actual controller owns its scopes until explicit hierarchy stop or
     * close. Collecting an invocation wrapper must not kill its live parent. */
    scope_release_memory(scope);
}
static void finalize_image(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    struct image *image = data; if (image->fd >= 0) close(image->fd); free(image);
}

static napi_value image_fd(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct image *image;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &IMAGE_TAG, (void **)&image) || image->fd < 0) return failure(env, "invalid held runtime image");
    napi_value result; napi_create_int32(env, image->fd, &result); return result;
}

static napi_value image_close(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct image *image;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &IMAGE_TAG, (void **)&image)) return failure(env, "invalid held runtime image");
    if (image->fd >= 0) { close(image->fd); image->fd = -1; }
    return undefined(env);
}

static napi_value seal_image(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1]; uint64_t source;
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (argc != 1 || !number(env, args[0], &source) || source > INT32_MAX) return failure(env, "invalid installed image descriptor");
    struct stat before, after;
    if (fstat((int)source, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 || before.st_size > 268435456 ||
        (before.st_mode & 0022) != 0 || (before.st_uid != geteuid() && before.st_uid != 0)) return failure(env, "unsafe installed runtime image");
    int sealed = memfd_create("cliq-runtime-image", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (sealed < 0) return failure(env, "sealed executable images are unavailable");
    char buffer[65536]; off_t offset = 0; bool copied = true;
    while (offset < before.st_size) {
        ssize_t bytes = pread((int)source, buffer, sizeof(buffer), offset);
        if (bytes <= 0) { copied = false; break; }
        ssize_t written = write(sealed, buffer, (size_t)bytes);
        if (written != bytes) { copied = false; break; }
        offset += bytes;
    }
    if (!copied || fstat((int)source, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec ||
        fchmod(sealed, 0500) != 0 || fcntl(sealed, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0 ||
        lseek(sealed, 0, SEEK_SET) < 0) { close(sealed); return failure(env, "installed runtime image changed or could not be sealed"); }
    struct image *image = calloc(1, sizeof(*image));
    if (!image) { close(sealed); return failure(env, "runtime image allocation failed"); }
    image->fd = sealed;
    napi_value result; napi_create_object(env, &result);
    napi_wrap(env, result, image, finalize_image, NULL, NULL); napi_type_tag_object(env, result, &IMAGE_TAG);
    napi_property_descriptor properties[] = { { "descriptor", NULL, image_fd, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, image_close, NULL, NULL, NULL, napi_default, NULL } };
    napi_define_properties(env, result, 2, properties); return result;
}

static napi_value seal_input(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1]; void *bytes; size_t length;
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (argc != 1 || napi_get_buffer_info(env, args[0], &bytes, &length) != napi_ok || length == 0 || length > 16777216)
        return failure(env, "canonical edit input exceeds the installed bounded recipe");
    int fd = memfd_create("cliq-canonical-edit-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return failure(env, "sealed canonical input unavailable");
    if (write(fd, bytes, length) != (ssize_t)length || fchmod(fd, 0400) != 0 ||
        fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        close(fd); return failure(env, "canonical edit input could not be sealed");
    }
    struct image *image = calloc(1, sizeof(*image));
    if (!image) { close(fd); return failure(env, "canonical input allocation failed"); }
    image->fd = fd;
    napi_value result; napi_create_object(env, &result);
    napi_wrap(env, result, image, finalize_image, NULL, NULL); napi_type_tag_object(env, result, &IMAGE_TAG);
    napi_property_descriptor properties[] = { { "descriptor", NULL, image_fd, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, image_close, NULL, NULL, NULL, napi_default, NULL } };
    napi_define_properties(env, result, 2, properties); return result;
}

static napi_value scope_observation(napi_env env, const struct cliq_worker_packet *packet) {
    napi_value result; napi_create_object(env, &result);
    set_number(env, result, "pid", (double)packet->pid);
    set_number(env, result, "namespaceInitPid", (double)packet->namespace_init_pid);
    set_string(env, result, "processStartToken", packet->start_token);
    set_string(env, result, "namespaceInitStartToken", packet->init_start_token);
    char value[32];
    snprintf(value, sizeof(value), "%llu", (unsigned long long)packet->cgroup_inode); set_string(env, result, "cgroupId", value);
    snprintf(value, sizeof(value), "%llu", (unsigned long long)packet->pid_namespace_inode); set_string(env, result, "pidNamespaceId", value);
    set_number(env, result, "cgroupPopulated", packet->populated);
    set_number(env, result, "remainingTrackedDescendants", packet->remaining_descendants);
    set_number(env, result, "namespaceInitDeadAndReaped", packet->init_reaped);
    set_number(env, result, "observedAtMs", (double)packet->observed_at_ms);
    return result;
}

/* Reobserve original containment at the synchronous release cut. Names locate
 * only descriptor-relative candidates; retained device/inode and actual procfs
 * membership must still match. No named-root or fork/migration fallback. */
static bool scope_placement_current(struct native_scope *scope) {
    struct controller *controller = scope->controller;
    if (controller->closed || controller->retirement_failed || atomic_load(&native_retirement_failed) ||
        !controller_placement(controller, controller->token)) return false;
    int parent = -1, root = -1, group = -1;
    int root_parent = controller->anchor_root;
    bool valid = true; struct stat identity;
    if (scope->invocation) {
        if (!scope->parent || scope->parent->stopped) valid = false;
        else {
            parent = openat(controller->anchor_root, scope->parent->identity.cgroup_name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            valid = parent >= 0 && private_cgroup(parent, &identity) &&
                (uint64_t)identity.st_dev == scope->parent->identity.cgroup_device &&
                (uint64_t)identity.st_ino == scope->parent->identity.cgroup_inode;
            root_parent = parent;
        }
    }
    if (valid) {
        root = openat(root_parent, scope->identity.cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = root >= 0 && private_cgroup(root, &identity) &&
            (uint64_t)identity.st_dev == scope->identity.cgroup_device && (uint64_t)identity.st_ino == scope->identity.cgroup_inode;
    }
    if (valid && !scope->invocation) {
        group = openat(root, "worker", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = group >= 0 && private_cgroup(group, &identity);
    }
    char expected[PATH_MAX + 256];
    int length = scope->invocation
        ? snprintf(expected, sizeof(expected), "0::%s/%s/%s\n", controller->root_path + strlen("/sys/fs/cgroup"),
            scope->parent ? scope->parent->identity.cgroup_name : "", scope->identity.cgroup_name)
        : snprintf(expected, sizeof(expected), "0::%s/%s/worker\n", controller->root_path + strlen("/sys/fs/cgroup"), scope->identity.cgroup_name);
    struct process_sample first, last;
    valid = valid && length > 0 && (size_t)length < sizeof(expected) &&
        sample_process(controller, (pid_t)scope->identity.pid, &first, true) && !first.absent && first.uid == geteuid() &&
        strcmp(first.token, scope->identity.start_token) == 0 && strcmp(first.cgroup, expected) == 0 &&
        sample_process(controller, (pid_t)scope->identity.pid, &last, true) && !last.absent &&
        last.uid == first.uid && strcmp(last.token, first.token) == 0 && strcmp(last.cgroup, first.cgroup) == 0 &&
        controller_placement(controller, controller->token);
    int *descriptors[] = { &group, &root, &parent };
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); i++) {
        if (!retire_descriptor(descriptors[i])) { controller->retirement_failed = true; valid = false; }
    }
    return valid && !atomic_load(&native_retirement_failed);
}

static bool scope_image_current(struct native_scope *scope) {
    char token[CLIQ_WORKER_TOKEN_BYTES], path[128]; struct stat held, current, owner, namespace;
    if (!scope_placement_current(scope)) return false;
    if (!cliq_process_token((pid_t)scope->identity.pid, token) || strcmp(token, scope->identity.start_token) != 0) return false;
    snprintf(path, sizeof(path), "/proc/%ld", (long)scope->identity.pid);
    if (stat(path, &owner) != 0 || owner.st_uid != geteuid()) return false;
    snprintf(path, sizeof(path), "/proc/%ld/ns/pid", (long)scope->identity.pid);
    if (stat(path, &namespace) != 0 || (uint64_t)namespace.st_ino != scope->identity.pid_namespace_inode) return false;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)scope->identity.pid);
    if (scope->image_fd < 0) scope->image_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (scope->image_fd < 0 || fstat(scope->image_fd, &held) != 0 || !S_ISREG(held.st_mode) ||
        held.st_size <= 0 || held.st_size > 268435456 || stat(path, &current) != 0 ||
        held.st_dev != current.st_dev || held.st_ino != current.st_ino) return false;
    snprintf(path, sizeof(path), "/proc/%ld/root/runtime/%s", (long)scope->identity.pid,
        scope->invocation ? "cliq-linux-edit" : "cliq-linux-worker");
    return stat(path, &current) == 0 && held.st_dev == current.st_dev && held.st_ino == current.st_ino &&
        cliq_generation_mount((pid_t)scope->identity.pid, scope->identity.generation_device, scope->identity.generation_inode, !scope->invocation) &&
        cliq_process_token((pid_t)scope->identity.pid, token) && strcmp(token, scope->identity.start_token) == 0 &&
        scope_placement_current(scope);
}

static napi_value scope_inspect(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || !scope->ready || scope->controller->closed || scope->stopped || !scope_image_current(scope))
        return failure(env, "native worker process or executable identity drifted");
    napi_value result = scope_observation(env, &scope->identity); struct stat image;
    if (fstat(scope->image_fd, &image) != 0) return failure(env, "native executable image unavailable");
    set_number(env, result, "imageFd", scope->image_fd); set_number(env, result, "imageByteCount", (double)image.st_size);
    set_string(env, result, "executableRealpath", scope->invocation ? "/runtime/cliq-linux-edit" : "/runtime/cliq-linux-worker");
    return result;
}
static napi_value scope_activate(napi_env env, napi_callback_info info) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t argc = 1; napi_value args[1], self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != 1 || !tagged(env, self, &SCOPE_TAG, (void **)&scope) || !scope->ready || scope->invocation || scope->stopped || scope->released || scope->controller->closed)
        return failure(env, "native activation capability was revoked or consumed");
    struct cliq_worker_packet request = cliq_packet(CLIQ_ACTIVATE_WORKER);
    size_t length;
    if (napi_get_value_string_utf8(env, args[0], request.nonce, sizeof(request.nonce), &length) != napi_ok ||
        length != 64 || !cliq_hex_digest(request.nonce)) return failure(env, "invalid activation capability");
    scope->released = true; request.scope = scope->id;
    if (!begin_request(scope->controller, scope, &request, NULL, 0)) return failure(env, "native activation failed; reconcile the exact launch");
    return undefined(env);
}

static napi_value scope_poll_activated(napi_env env, napi_callback_info info) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || scope->controller->closed || scope->invocation || !scope->released)
        return failure(env, "invalid native activation observation");
    int observed = 1;
    if (!scope->activated) {
        struct cliq_worker_packet response;
        observed = poll_response(scope->controller, scope, CLIQ_WORKER_ACTIVATED, &response);
        if (observed < 0) return failure(env, "native activation acknowledgment failed");
        if (observed == 1) scope->activated = true;
    }
    napi_value result; napi_get_boolean(env, observed == 1, &result); return result;
}

static napi_value scope_release(napi_env env, napi_callback_info info) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || !scope->ready || !scope->invocation || scope->stopped || scope->released || scope->controller->closed)
        return failure(env, "native invocation release was revoked or consumed");
    struct cliq_worker_packet request = cliq_packet(CLIQ_RELEASE_WRITE); request.scope = scope->id;
    memcpy(request.nonce, scope->identity.nonce, sizeof(request.nonce));
    scope->released = true;
    /* Retained active flags are not evidence that the real parent survived.
     * Consume before checking, so a dead/drifted process cannot be retried as
     * another release under the same permanent dispatch claim. */
    if (!scope->parent || !scope->parent->activated || scope->parent->stopped ||
        !scope_image_current(scope->parent) || !scope_image_current(scope))
        return failure(env, "actual invocation or parent process identity was revoked");
    /* Atomic fixed SOCK_SEQPACKET send only. No await, arbitrary callback,
     * caller target, worker argv or productive filesystem I/O belongs here. */
    if (!begin_request(scope->controller, scope, &request, NULL, 0)) return failure(env, "invocation release failed; reconcile its permanent claim");
    return undefined(env);
}

static napi_value scope_result(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || !scope->invocation || !scope->released || scope->controller->closed)
        return failure(env, "native invocation outcome is indeterminate");
    if (!scope->result_received) {
        int observed = poll_response(scope->controller, scope, CLIQ_WRITE_RESULT, &scope->result);
        if (observed < 0) return failure(env, "native invocation outcome is indeterminate");
        if (observed == 0) return undefined(env);
        if (scope->result.exit_status > 1) return failure(env, "native invocation result is unsupported");
        scope->result_received = true;
    }
    napi_value result; napi_create_uint32(env, scope->result.exit_status, &result); return result;
}
static napi_value scope_stop(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || !scope->ready || scope->controller->closed) return failure(env, "invalid native stop scope");
    struct cliq_worker_packet request = cliq_packet(CLIQ_STOP_SCOPE); request.scope = scope->id;
    if (!begin_request(scope->controller, scope, &request, NULL, 0)) return failure(env, "complete native death could not be requested");
    return undefined(env);
}

static napi_value scope_poll_stopped(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || scope->controller->closed) return failure(env, "invalid native death observation");
    if (!scope->stopped || (scope->controller->pending == CLIQ_STOP_SCOPE && scope->controller->pending_scope == scope)) {
        struct cliq_worker_packet response;
        int observed = poll_response(scope->controller, scope, CLIQ_STOP_SCOPE, &response);
        if (observed < 0) return failure(env, "complete native death could not be proven");
        if (observed == 0) return undefined(env);
        if (response.init_reaped != 1 || response.populated != 0 || response.remaining_descendants != 0 ||
            response.observed_at_ms == 0 || response.observed_at_ms > UINT64_C(9007199254740991) ||
            response.cgroup_device != scope->identity.cgroup_device || response.cgroup_inode != scope->identity.cgroup_inode ||
            response.pid_namespace_inode != scope->identity.pid_namespace_inode || response.pid != scope->identity.pid ||
            response.namespace_init_pid != scope->identity.namespace_init_pid || response.monitor_pid != scope->identity.monitor_pid ||
            strcmp(response.start_token, scope->identity.start_token) != 0 ||
            strcmp(response.init_start_token, scope->identity.init_start_token) != 0 ||
            strcmp(response.monitor_start_token, scope->identity.monitor_start_token) != 0)
            return failure(env, "native death belongs to another scope or lacks its actual observation time");
        scope->identity = response;
        for (struct native_scope *child = scope->controller->scopes; child; child = child->next) {
            if (child == scope || child->parent == scope) {
                if (!child->stopped) child->identity.observed_at_ms = response.observed_at_ms;
                child->stopped = true; child->identity.populated = 0; child->identity.init_reaped = 1; child->identity.remaining_descendants = 0;
                if (!retire_descriptor(&child->image_fd)) {
                    scope->controller->retirement_failed = true;
                    (void)close_controller(scope->controller); return failure(env, "native scope image retirement failed");
                }
            }
        }
    }
    return scope_observation(env, &scope->identity);
}

static napi_value scope_poll_ready(napi_env env, napi_callback_info info) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t argc = 0; napi_value self; struct native_scope *scope;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &SCOPE_TAG, (void **)&scope) || scope->controller->closed) return failure(env, "invalid native blocked scope");
    int observed = 1;
    if (!scope->ready) {
        struct cliq_worker_packet response;
        observed = poll_response(scope->controller, scope, CLIQ_WORKER_READY, &response);
        if (observed < 0) return failure(env, "blocked scope could not be natively observed");
        if (observed == 1) {
            if (response.pid <= 0 || response.namespace_init_pid <= 0 || response.cgroup_inode == 0 || response.pid_namespace_inode == 0 ||
                response.generation_device != scope->identity.generation_device || response.generation_inode != scope->identity.generation_inode ||
                strcmp(response.nonce, scope->identity.nonce) != 0 || strcmp(response.activation_nonce, scope->identity.activation_nonce) != 0 ||
                strcmp(response.cgroup_name, scope->identity.cgroup_name) != 0) {
                (void)close_controller(scope->controller); return failure(env, "blocked reply differs from the exact reservation");
            }
            scope->identity = response; scope->ready = true;
        }
    }
    napi_value result; napi_get_boolean(env, observed == 1, &result); return result;
}

static napi_value create_scope(napi_env env, napi_callback_info info, bool invocation) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t expected = invocation ? 7 : 6;
    size_t argc = expected; napi_value args[7], self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != expected || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready || controller->pending != 0 ||
        controller->next_scope >= CLIQ_WORKER_MAX_SCOPES || controller->inspection_only ||
        (!invocation && !controller->reservation_bound)) return failure(env, "invalid held Linux controller");
    uint64_t generation, cgroup = 0; struct image *helper, *worker, *bwrap, *input = NULL; struct native_scope *parent = NULL;
    if (!number(env, args[0], &generation) || generation > INT32_MAX ||
        (invocation ? !tagged(env, args[1], &SCOPE_TAG, (void **)&parent) || parent->controller != controller || parent->invocation ||
            parent->stopped || !parent->activated : !number(env, args[1], &cgroup) || cgroup > INT32_MAX) ||
        !tagged(env, args[2], &IMAGE_TAG, (void **)&helper) || !tagged(env, args[3], &IMAGE_TAG, (void **)&worker) ||
        !tagged(env, args[4], &IMAGE_TAG, (void **)&bwrap) ||
        (invocation && !tagged(env, args[5], &IMAGE_TAG, (void **)&input))) return failure(env, "scope requires held generation, parent and sealed installed images");
    struct cliq_worker_packet request = cliq_packet(invocation ? CLIQ_CREATE_WRITE : CLIQ_CREATE_WORKER);
    request.scope = controller->next_scope++;
    if (invocation) request.parent = parent->id;
    napi_value config = args[invocation ? 6 : 5];
    if (!field_string(env, config, "cgroupName", request.cgroup_name, sizeof(request.cgroup_name)) ||
        !field_string(env, config, "spawnNonceDigest", request.nonce, sizeof(request.nonce)) ||
        !field_string(env, config, "activationNonceDigest", request.activation_nonce, sizeof(request.activation_nonce)) ||
        !field_number(env, config, "generationDevice", &request.generation_device) ||
        !field_number(env, config, "generationInode", &request.generation_inode) ||
        !field_number(env, config, "maxProcesses", &request.max_processes) ||
        !field_number(env, config, "memoryBytes", &request.memory_bytes) ||
        !field_number(env, config, "cpuQuotaMicrosPerSecond", &request.cpu_quota) ||
        !field_number(env, config, "maxOpenFiles", &request.max_open_files) ||
        !field_number(env, config, "maxSingleFileBytes", &request.max_file_bytes) ||
        !field_number(env, config, "maxGenerationBytes", &request.max_generation_bytes) ||
        !field_number(env, config, "maxInvocationOutputBytes", &request.max_output_bytes)) return failure(env, "invalid closed scope projection");
    if (!invocation) {
        const struct cliq_worker_packet *binding = &controller->reservation;
        if (request.generation_device != binding->generation_device || request.generation_inode != binding->generation_inode ||
            strcmp(request.nonce, binding->nonce) != 0 || strcmp(request.activation_nonce, binding->activation_nonce) != 0 ||
            strcmp(request.cgroup_name, binding->cgroup_name) != 0) return failure(env, "worker differs from its native reservation");
        reservation_copy_binding(&request, binding);
    }
    int descriptors[] = { (int)generation, invocation ? helper->fd : (int)cgroup,
        invocation ? worker->fd : helper->fd, invocation ? bwrap->fd : worker->fd, invocation ? input->fd : bwrap->fd };
    struct native_scope *scope = calloc(1, sizeof(*scope));
    if (!scope) return failure(env, "native scope allocation failed");
    scope->controller = controller; scope->id = request.scope; scope->identity = request; scope->image_fd = -1; scope->invocation = invocation;
    scope->parent = parent; scope->references = 2; scope->next = controller->scopes; controller->scopes = scope;
    controller->references++;
    if (!begin_request(controller, scope, &request, descriptors, 5)) {
        (void)close_controller(controller); scope_release_memory(scope); return failure(env, "blocked scope could not be created");
    }
    napi_value result; napi_create_object(env, &result);
    napi_wrap(env, result, scope, finalize_scope, NULL, NULL); napi_type_tag_object(env, result, &SCOPE_TAG);
    napi_property_descriptor properties[] = {
        { "observe", NULL, scope_inspect, NULL, NULL, NULL, napi_default, NULL },
        { "pollReady", NULL, scope_poll_ready, NULL, NULL, NULL, napi_default, NULL },
        { "activate", NULL, scope_activate, NULL, NULL, NULL, napi_default, NULL },
        { "pollActivated", NULL, scope_poll_activated, NULL, NULL, NULL, napi_default, NULL },
        { "stop", NULL, scope_stop, NULL, NULL, NULL, napi_default, NULL },
        { "pollStopped", NULL, scope_poll_stopped, NULL, NULL, NULL, napi_default, NULL },
        { "release", NULL, scope_release, NULL, NULL, NULL, napi_default, NULL },
        { "result", NULL, scope_result, NULL, NULL, NULL, napi_default, NULL }
    };
    napi_define_properties(env, result, 8, properties); return result;
}
static napi_value create_worker(napi_env env, napi_callback_info info) { return create_scope(env, info, false); }
static napi_value create_invocation(napi_env env, napi_callback_info info) { return create_scope(env, info, true); }

static bool parse_retained_tokens(const char *init_token, const char *subreaper_token, struct cliq_worker_packet *request) {
    int consumed = 0;
    char init_pid[11] = {0}, monitor_pid[11] = {0}, subreaper_pid[11] = {0};
    char init_ticks[33] = {0}, monitor_ticks[33] = {0}, subreaper_ticks[33] = {0};
    if (sscanf(init_token, "linux-namespace-init:%10[0-9]:%32[0-9]:monitor:%10[0-9]:%32[0-9]%n",
            init_pid, init_ticks, monitor_pid, monitor_ticks, &consumed) != 4 || init_token[consumed] != '\0') return false;
    long init = strtol(init_pid, NULL, 10), monitor = strtol(monitor_pid, NULL, 10);
    if (init_pid[0] == '0' || monitor_pid[0] == '0' ||
        init <= 0 || init > INT32_MAX || monitor <= 0 || monitor > INT32_MAX) return false;
    request->namespace_init_pid = init; request->monitor_pid = monitor;
    snprintf(request->init_native_start_token, sizeof(request->init_native_start_token), "linux-proc-start-ticks:%s", init_ticks);
    snprintf(request->monitor_start_token, sizeof(request->monitor_start_token), "linux-proc-start-ticks:%s", monitor_ticks);
    consumed = 0;
    if (sscanf(subreaper_token, "linux-subreaper:%10[0-9]:linux-proc-start-ticks:%32[0-9]%n", subreaper_pid, subreaper_ticks, &consumed) != 2 ||
        subreaper_token[consumed] != '\0') return false;
    long subreaper = strtol(subreaper_pid, NULL, 10);
    if (subreaper_pid[0] == '0' || subreaper <= 0 || subreaper > INT32_MAX) return false;
    request->subreaper_pid = subreaper;
    snprintf(request->subreaper_start_token, sizeof(request->subreaper_start_token), "linux-proc-start-ticks:%s", subreaper_ticks);
    return true;
}

static bool parse_reservation_subreaper(const char *value, struct cliq_worker_packet *request) {
    int consumed = 0; char pid_text[11] = {0}, ticks[33] = {0};
    if (sscanf(value, "linux-subreaper:%10[0-9]:linux-proc-start-ticks:%32[0-9]%n",
        pid_text, ticks, &consumed) != 2 || value[consumed] != '\0' || pid_text[0] == '0') return false;
    long pid = strtol(pid_text, NULL, 10);
    if (pid <= 0 || pid > INT32_MAX) return false;
    request->subreaper_pid = pid;
    int length = snprintf(request->subreaper_start_token, sizeof(request->subreaper_start_token), "linux-proc-start-ticks:%s", ticks);
    return length >= 0 && (size_t)length < sizeof(request->subreaper_start_token);
}
static bool reservation_projection(napi_env env, napi_value value, struct cliq_worker_packet *request) {
    char subreaper[CLIQ_WORKER_TOKEN_BYTES];
    return field_string(env, value, "planRef", request->plan_ref, sizeof(request->plan_ref)) &&
        field_string(env, value, "sandboxLaunchSpecRef", request->sandbox_launch_ref, sizeof(request->sandbox_launch_ref)) &&
        field_string(env, value, "sandboxLaunchSpecDigest", request->sandbox_launch_digest, sizeof(request->sandbox_launch_digest)) &&
        field_string(env, value, "workspaceGenerationRef", request->generation_ref, sizeof(request->generation_ref)) &&
        field_string(env, value, "spawnNonceDigest", request->nonce, sizeof(request->nonce)) &&
        field_string(env, value, "activationNonceDigest", request->activation_nonce, sizeof(request->activation_nonce)) &&
        field_string(env, value, "cgroupName", request->cgroup_name, sizeof(request->cgroup_name)) &&
        field_string(env, value, "pidNamespaceReservationId", request->pid_namespace_reservation, sizeof(request->pid_namespace_reservation)) &&
        field_string(env, value, "subreaperStartToken", subreaper, sizeof(subreaper)) &&
        parse_reservation_subreaper(subreaper, request) &&
        field_number(env, value, "reservationDevice", &request->reservation_device) &&
        field_number(env, value, "reservationInode", &request->reservation_inode) &&
        field_number(env, value, "reservationOwnerUid", &request->reservation_uid) &&
        field_number(env, value, "generationDevice", &request->generation_device) &&
        field_number(env, value, "generationInode", &request->generation_inode) && reservation_binding_valid(request);
}
static napi_value controller_bind_reservation(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2], self; struct controller *controller; uint64_t descriptor;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != 2 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready ||
        controller->pending != 0 || controller->reservation_bound || controller->inspection_only || controller->scopes ||
        !number(env, args[0], &descriptor) || descriptor > INT32_MAX) return failure(env, "invalid native worker reservation binding");
    struct cliq_worker_packet request = cliq_packet(CLIQ_BIND_RESERVATION); char token[CLIQ_WORKER_TOKEN_BYTES];
    if (!reservation_projection(env, args[1], &request) || request.subreaper_pid != controller->pid ||
        strcmp(request.subreaper_start_token, controller->token) != 0 ||
        !cliq_process_token(controller->pid, token) || strcmp(token, controller->token) != 0)
        return failure(env, "reservation selects another native controller");
    controller->reservation = request; int held = (int)descriptor;
    if (!begin_request(controller, NULL, &request, &held, 1)) return failure(env, "native reservation could not be bound");
    return undefined(env);
}
static napi_value controller_poll_bound(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed)
        return failure(env, "invalid bound reservation controller");
    int observed = 1;
    if (!controller->reservation_bound) {
        struct cliq_worker_packet response;
        observed = poll_response(controller, NULL, CLIQ_BIND_RESERVATION, &response);
        if (observed < 0) return failure(env, "native reservation persistence was not observed");
        if (observed == 1) controller->reservation_bound = true;
    }
    napi_value result; napi_get_boolean(env, observed == 1, &result); return result;
}
static napi_value controller_inspect_reservation(napi_env env, napi_callback_info info) {
    size_t argc = 3; napi_value args[3], self; struct controller *controller; uint64_t cgroup, reservation;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != 3 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed || !controller->ready ||
        controller->pending != 0 || controller->reservation_bound || controller->scopes ||
        !number(env, args[0], &cgroup) || cgroup > INT32_MAX ||
        !number(env, args[1], &reservation) || reservation > INT32_MAX) return failure(env, "invalid native reservation inspector");
    struct cliq_worker_packet request = cliq_packet(CLIQ_INSPECT_RESERVATION);
    if (!reservation_projection(env, args[2], &request)) return failure(env, "invalid retained reservation binding");
    controller->inspection_only = true; controller->reservation_inspection = request;
    int descriptors[] = { (int)cgroup, (int)reservation };
    if (!begin_request(controller, NULL, &request, descriptors, 2)) return failure(env, "native reservation could not be inspected");
    return undefined(env);
}
static napi_value controller_poll_reservation(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || !controller->inspection_only)
        return failure(env, "invalid native reservation observation");
    struct cliq_worker_packet response;
    int observed = poll_response(controller, NULL, CLIQ_INSPECT_RESERVATION, &response);
    if (observed < 0) return failure(env, "native reservation closure could not be proven");
    if (observed == 0) return undefined(env);
    if (!reservation_same_binding(&response, &controller->reservation_inspection) ||
        response.observed_at_ms == 0 || response.observed_at_ms > UINT64_C(9007199254740991))
        return failure(env, "native reservation observation belongs to another launch or lacks its actual observation time");
    napi_value result;
    if (response.reservation_observation == 1 && response.cgroup_inode == 0 && response.pid_namespace_inode == 0 &&
        response.pid == 0 && response.namespace_init_pid == 0 && response.monitor_pid == 0) {
        napi_create_object(env, &result); set_string(env, result, "kind", "not_attempted");
        napi_value present; napi_get_boolean(env, false, &present); napi_set_named_property(env, result, "cgroupPresent", present);
    } else if (response.reservation_observation == 2 && response.cgroup_inode != 0 && response.pid_namespace_inode != 0 &&
        response.pid > 0 && response.namespace_init_pid > 0 && response.monitor_pid > 0 &&
        response.init_reaped == 1 && response.populated == 0 && response.remaining_descendants == 0) {
        result = scope_observation(env, &response); set_string(env, result, "kind", "created_dead");
    } else return failure(env, "native reservation closure observation is incomplete");
    set_number(env, result, "observedAtMs", (double)response.observed_at_ms);
    napi_object_freeze(env, result); return result;
}

static napi_value terminate_retained(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2], self; struct controller *controller; uint64_t cgroup, pid;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != 2 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) || controller->closed ||
        !number(env, args[0], &cgroup) || cgroup > INT32_MAX) return failure(env, "invalid retained inspection controller");
    struct cliq_worker_packet request = cliq_packet(CLIQ_TERMINATE_RETAINED);
    char subreaper[CLIQ_WORKER_TOKEN_BYTES];
    if (!field_string(env, args[1], "cgroupName", request.cgroup_name, sizeof(request.cgroup_name)) ||
        !field_string(env, args[1], "namespaceInitStartToken", request.init_start_token, sizeof(request.init_start_token)) ||
        !field_string(env, args[1], "subreaperStartToken", subreaper, sizeof(subreaper)) ||
        !field_string(env, args[1], "processStartToken", request.start_token, sizeof(request.start_token)) ||
        !field_number(env, args[1], "workerPid", &pid) || pid == 0 || pid > INT32_MAX ||
        !field_number(env, args[1], "cgroupId", &request.cgroup_inode) || request.cgroup_inode == 0 ||
        !field_number(env, args[1], "pidNamespaceId", &request.pid_namespace_inode) || request.pid_namespace_inode == 0 ||
        !parse_retained_tokens(request.init_start_token, subreaper, &request)) return failure(env, "retained native identity is unsupported or malformed");
    request.pid = (int64_t)pid;
    int held = (int)cgroup;
    controller->retained_observed = false; controller->retained = request;
    if (!begin_request(controller, NULL, &request, &held, 1)) return failure(env, "retained whole-hierarchy death could not be requested");
    return undefined(env);
}

static napi_value poll_retained(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller)) return failure(env, "invalid retained observation controller");
    struct cliq_worker_packet response;
    int observed = poll_response(controller, NULL, CLIQ_TERMINATE_RETAINED, &response);
    if (observed < 0) return failure(env, "retained native death could not be proven");
    if (observed == 0) return undefined(env);
    if (response.init_reaped != 1 || response.populated != 0 || response.remaining_descendants != 0 ||
        response.observed_at_ms == 0 || response.observed_at_ms > UINT64_C(9007199254740991) ||
        response.cgroup_inode != controller->retained.cgroup_inode || response.pid_namespace_inode != controller->retained.pid_namespace_inode ||
        strcmp(response.init_start_token, controller->retained.init_start_token) != 0) return failure(env, "retained native death belongs to another reservation");
    controller->retained_observed = true;
    return scope_observation(env, &response);
}

/* A closed inspector cannot resurrect or adopt its original worker. Verify
 * both completed native joins and current kernel observations, using only the
 * original held installation-root identity and retained process lifetimes. */
static napi_value assert_retained_retired(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1], self; struct controller *controller; uint64_t root;
    napi_get_cb_info(env, info, &argc, args, &self, NULL);
    if (argc != 1 || !tagged(env, self, &CONTROLLER_TAG, (void **)&controller) ||
        !controller->closed || !controller->cleanup_done || !controller->reaped || !controller->retained_observed ||
        controller->retirement_failed || atomic_load(&native_retirement_failed) || controller->scopes ||
        !number(env, args[0], &root) || root > INT32_MAX)
        return failure(env, "retained namespace/resource owners have not positively retired");
    struct stat held, scope_identity; char events[512];
    if (!private_cgroup((int)root, &held) || !same_directory(&controller->root_identity, &held))
        return failure(env, "retained retirement lost its original installation root");
    int scope = openat((int)root, controller->retained.cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool valid = scope >= 0 && private_cgroup(scope, &scope_identity) &&
        scope_identity.st_dev == held.st_dev && (uint64_t)scope_identity.st_ino == controller->retained.cgroup_inode &&
        read_bounded(controller, scope, "cgroup.events", events, sizeof(events)) &&
        (strncmp(events, "populated 0\n", 12) == 0 || strstr(events, "\npopulated 0\n") != NULL) &&
        !(strncmp(events, "populated 1\n", 12) == 0 || strstr(events, "\npopulated 1\n") != NULL);
    int64_t pids[] = { controller->retained.pid, controller->retained.namespace_init_pid,
        controller->retained.monitor_pid, controller->retained.subreaper_pid };
    const char *tokens[] = { controller->retained.start_token, controller->retained.init_native_start_token,
        controller->retained.monitor_start_token, controller->retained.subreaper_start_token };
    for (size_t i = 0; valid && i < sizeof(pids) / sizeof(pids[0]); i++) {
        struct process_sample sample;
        valid = pids[i] > 0 && pids[i] <= INT32_MAX && *tokens[i] && sample_process(controller, (pid_t)pids[i], &sample, false) &&
            (sample.absent || strcmp(sample.token, tokens[i]) != 0);
    }
    struct stat current;
    valid = valid && fstat(scope, &current) == 0 && same_directory(&scope_identity, &current) &&
        private_cgroup((int)root, &current) && same_directory(&controller->root_identity, &current);
    if (!retire_descriptor(&scope)) controller->retirement_failed = true;
    if (controller->retirement_failed || atomic_load(&native_retirement_failed)) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "retained retirement inspection descriptors did not retire"); return NULL;
    }
    if (!valid) return failure(env, "retained containment or namespace owner is not currently empty and dead");
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0) return failure(env, "retained retirement observation time unavailable");
    double observed = (double)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    if (observed <= 0 || observed > 9007199254740991.0) return failure(env, "retained retirement observation time invalid");
    napi_value result; napi_create_double(env, observed, &result); return result;
}

static napi_value controller_close(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller)) return failure(env, "invalid held controller");
    napi_value promise;
    if (controller->close_promise) { napi_get_reference_value(env, controller->close_promise, &promise); return promise; }
    if (napi_create_promise(env, &controller->close_deferred, &promise) != napi_ok) {
        (void)close_controller(controller); return failure(env, "controller close promise unavailable");
    }
    if (controller->cleanup_done) { settle_controller_close(env, controller); return promise; }
    napi_create_reference(env, promise, 1, &controller->close_promise);
    if (!close_controller(controller)) {
        /* No work was submitted. Reject this attempt, retain actual ownership
         * and let a later close queue the same join. Never cache an unsettled
         * promise or confuse queue failure with uncertain descriptor close. */
        napi_delete_reference(env, controller->close_promise); controller->close_promise = NULL;
        settle_controller_close(env, controller);
    }
    return promise;
}

static napi_value controller_pid(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self, result; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller) ||
        napi_create_double(env, (double)controller->pid, &result) != napi_ok) return failure(env, "controller PID unavailable");
    return result;
}

static napi_value controller_token(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self, result; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller) ||
        napi_create_string_utf8(env, controller->token, NAPI_AUTO_LENGTH, &result) != napi_ok)
        return failure(env, "controller start lifetime unavailable");
    return result;
}

static napi_value controller_poll_ready(napi_env env, napi_callback_info info) {
    size_t argc = 0; napi_value self; struct controller *controller;
    napi_get_cb_info(env, info, &argc, NULL, &self, NULL);
    if (!tagged(env, self, &CONTROLLER_TAG, (void **)&controller)) return failure(env, "invalid starting controller");
    /* Revocation is main-thread-only and precedes queueing cleanup. Do not
     * read worker-written retirement state once that join is in flight. */
    if (controller->closed) return failure(env, "invalid starting controller");
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    if (controller->constructor_failed || controller->retirement_failed) {
        (void)close_controller(controller); return failure(env, "native atomic controller construction failed; no fallback");
    }
    int observed = 1;
    if (!controller->ready) {
        struct cliq_worker_packet hello;
        observed = poll_response(controller, NULL, CLIQ_CONTROLLER_HELLO, &hello);
        if (observed < 0) return failure(env, "native controller identity unavailable");
        if (observed == 1) {
            if (hello.pid != controller->pid || !controller_placement(controller, hello.start_token)) {
                controller->retirement_failed = true;
                (void)close_controller(controller); return failure(env, "native controller identity changed");
            }
            memcpy(controller->token, hello.start_token, sizeof(controller->token)); controller->ready = true;
        }
    }
    napi_value result; napi_get_boolean(env, observed == 1, &result); return result;
}

static bool prepare_controller_io(struct controller *controller) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) return false;
    controller->socket = sockets[0]; controller->child_socket = sockets[1];
    /* Closed stdin and bounded private captured outputs, never inherited host
     * streams. Fixed trusted images emit no productive tool bytes here. */
    controller->input_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    controller->stdout_fd = memfd_create("cliq-captured-stdout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    controller->stderr_fd = memfd_create("cliq-captured-stderr", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (controller->input_fd < 0 || controller->stdout_fd < 0 || controller->stderr_fd < 0 ||
        ftruncate(controller->stdout_fd, 1048576) != 0 || ftruncate(controller->stderr_fd, 1048576) != 0 ||
        fcntl(controller->stdout_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) != 0 ||
        fcntl(controller->stderr_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) != 0) return false;
    int source[] = { controller->input_fd, controller->stdout_fd, controller->stderr_fd, controller->child_socket };
    for (size_t i = 0; i < 4; i++) {
        controller->transfer[i] = fcntl(source[i], F_DUPFD_CLOEXEC, 20);
        if (controller->transfer[i] < 0) return false;
    }
    int flags = fcntl(controller->socket, F_GETFL);
    return flags >= 0 && fcntl(controller->socket, F_SETFL, flags | O_NONBLOCK) == 0;
}

static napi_value open_controller(napi_env env, napi_callback_info info) {
    if (atomic_load(&native_retirement_failed)) return failure(env, "native resource retirement remains uncertain");
    size_t argc = 2; napi_value args[2]; struct image *helper; uint64_t root;
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (argc != 2 || !tagged(env, args[0], &IMAGE_TAG, (void **)&helper) || helper->fd < 0 ||
        !number(env, args[1], &root) || root > INT32_MAX) return failure(env, "controller requires the sealed helper and held anchor root");
    struct controller *controller = calloc(1, sizeof(*controller));
    if (!controller) return failure(env, "controller allocation failed");
    controller->env = env;
    controller->socket = controller->stdout_fd = controller->stderr_fd = controller->input_fd = controller->child_socket = -1;
    controller->anchor_root = controller->controller_parent = controller->controller_leaf = -1;
    for (size_t i = 0; i < 4; i++) controller->transfer[i] = -1;
    controller->references = 1; controller->next_scope = 1; controller->pending = CLIQ_CONTROLLER_HELLO;
    napi_value result, resource;
    napi_property_descriptor properties[] = {
        { "pid", NULL, NULL, controller_pid, NULL, NULL, napi_default, NULL },
        { "processStartToken", NULL, NULL, controller_token, NULL, NULL, napi_default, NULL },
        { "pollReady", NULL, controller_poll_ready, NULL, NULL, NULL, napi_default, NULL },
        { "bindReservation", NULL, controller_bind_reservation, NULL, NULL, NULL, napi_default, NULL },
        { "pollBound", NULL, controller_poll_bound, NULL, NULL, NULL, napi_default, NULL },
        { "inspectReservation", NULL, controller_inspect_reservation, NULL, NULL, NULL, napi_default, NULL },
        { "pollReservation", NULL, controller_poll_reservation, NULL, NULL, NULL, napi_default, NULL },
        { "createWorker", NULL, create_worker, NULL, NULL, NULL, napi_default, NULL },
        { "createInvocation", NULL, create_invocation, NULL, NULL, NULL, napi_default, NULL },
        { "terminateRetained", NULL, terminate_retained, NULL, NULL, NULL, napi_default, NULL },
        { "pollRetained", NULL, poll_retained, NULL, NULL, NULL, napi_default, NULL },
        { "assertRetainedRetired", NULL, assert_retained_retired, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, controller_close, NULL, NULL, NULL, napi_default, NULL }
    };
    /* All receiver allocation/branding and async ownership precede the first
     * child. Subsequent construction failures return this joinable receiver;
     * the public wrapper rejects pollReady and awaits its exact close. */
    if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &CONTROLLER_TAG) != napi_ok ||
        napi_define_properties(env, result, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok ||
        napi_create_string_utf8(env, "cliq-controller-join", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
        napi_create_async_work(env, NULL, resource, reap_controller, cleanup_complete, controller, &controller->cleanup_work) != napi_ok ||
        napi_add_async_cleanup_hook(env, cleanup_hook, controller, &controller->cleanup_hook) != napi_ok ||
        napi_wrap(env, result, controller, finalize_controller, NULL, NULL) != napi_ok) {
        if (controller->cleanup_hook) {
            if (napi_remove_async_cleanup_hook(controller->cleanup_hook) != napi_ok)
                return failure(env, "controller asynchronous ownership could not retire");
            controller->cleanup_hook = NULL;
        }
        if (controller->cleanup_work) napi_delete_async_work(env, controller->cleanup_work);
        free(controller);
        return failure(env, "controller asynchronous lifetime is unavailable");
    }
    controller->references++; /* Async cleanup hook owns the join until done. */
    if (!create_controller_leaf(controller, (int)root) || !prepare_controller_io(controller)) {
        controller->constructor_failed = true; (void)close_controller(controller); return result;
    }
    struct clone_args birth;
    memset(&birth, 0, sizeof(birth)); birth.flags = CLONE_INTO_CGROUP; birth.exit_signal = SIGCHLD;
    birth.cgroup = (uint64_t)controller->controller_leaf;
    pid_t child = (pid_t)syscall(SYS_clone3, &birth, sizeof(birth));
    if (child < 0) {
        controller->constructor_failed = true; (void)close_controller(controller); return result;
    }
    if (child == 0) {
        int executable = fcntl(helper->fd, F_DUPFD_CLOEXEC, 20);
        if (executable < 0 || dup2(controller->transfer[0], 0) < 0 || dup2(controller->transfer[1], 1) < 0 ||
            dup2(controller->transfer[2], 2) < 0 || dup2(controller->transfer[3], 3) < 0) _exit(70);
        if (!cliq_close_range(4, (unsigned int)executable - 1) || !cliq_close_range((unsigned int)executable + 1, UINT_MAX)) _exit(70);
        char *const arguments[] = { "cliq-linux-worker-controller", NULL };
        char *const environment[] = { "LANG=C", "LC_ALL=C", NULL };
        fexecve(executable, arguments, environment); _exit(70);
    }
    controller->pid = child;
    for (size_t i = 0; i < 4; i++) if (!retire_descriptor(&controller->transfer[i])) controller->retirement_failed = true;
    if (!retire_descriptor(&controller->input_fd)) controller->retirement_failed = true;
    if (!retire_descriptor(&controller->child_socket)) controller->retirement_failed = true;
    if (controller->retirement_failed) (void)close_controller(controller);
    return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        { "sealImage", NULL, seal_image, NULL, NULL, NULL, napi_default, NULL },
        { "sealImageBuffer", NULL, seal_input, NULL, NULL, NULL, napi_default, NULL },
        { "openController", NULL, open_controller, NULL, NULL, NULL, napi_default, NULL }
    };
    napi_define_properties(env, exports, 3, properties); set_number(env, exports, "interfaceVersion", 3); return exports;
}
#else
static napi_value unsupported(napi_env env, napi_callback_info info) {
    (void)info; napi_throw_error(env, "UNSUPPORTED_PLATFORM", "Linux worker lifecycle requires Linux"); return NULL;
}
static napi_value initialize(napi_env env, napi_value exports) {
    napi_property_descriptor property = { "openController", NULL, unsupported, NULL, NULL, NULL, napi_default, NULL };
    napi_define_properties(env, exports, 1, &property); return exports;
}
#endif

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
