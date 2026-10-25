#ifndef CLIQ_SOURCE_GIT_CONTROLLER_H
#define CLIQ_SOURCE_GIT_CONTROLLER_H

#include "source-input-bridge.h"
#include "source-git-protocol.h"
#include "preparation-git-protocol.h"
#include <sys/file.h>

/* One original source attempt per original controller. This family cannot
 * be mixed with a resident Worker/Run reservation or an invocation parent. */
struct source_controller_scope {
    bool attempted, created, blocked, released, sealed, continued, result, dead, retired, failed, monitor_joined, monitor_success;
    int anchor, cgroup, channel, birth, root, git, config_fd, helper, bwrap, inspector;
    int stdout_fd, stderr_fd, output[CLIQ_SOURCE_TRANSFER_OUTPUTS], files[CLIQ_SOURCE_MAX_FILES];
    struct stat anchor_identity, cgroup_identity;
    struct cliq_source_birth binding;
    struct cliq_source_controller_birth creator;
    struct cliq_source_config config;
    struct cliq_worker_packet identity, sealed_packet, result_packet;
    struct scope process;
    uint32_t birth_step;
    unsigned char birth_digest[32];
    bool preparation, preparation_completed;
    int preparation_stream;
    struct cliq_preparation_origin preparation_origin;
};
static struct source_controller_scope source_scope;
static bool source_controller_initialized;
static void source_controller_init(void) {
    if (source_controller_initialized) return;
    source_controller_initialized = true;
    int *fields[] = { &source_scope.anchor, &source_scope.cgroup, &source_scope.channel, &source_scope.birth,
        &source_scope.root, &source_scope.git, &source_scope.config_fd, &source_scope.helper, &source_scope.bwrap,
        &source_scope.inspector, &source_scope.stdout_fd, &source_scope.stderr_fd, &source_scope.preparation_stream };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) *fields[i] = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_MAX_FILES; i++) source_scope.files[i] = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) source_scope.output[i] = -1;
    source_scope.process.channel = -1; source_scope.process.cgroup = -1; source_scope.process.process_group = -1;
    source_scope.process.stdout_fd = source_scope.process.stderr_fd = source_scope.process.stdout_pipe = source_scope.process.stderr_pipe = -1;
}
/* Native birth progress is append-only under the original exclusive FD lock.
 * It is cleanup provenance, never a grant/death attestation by its existence. */
static bool source_birth_step(uint32_t kind, const struct cliq_worker_packet *packet) {
    if (source_scope.preparation) return preparation_birth_step(kind, packet);
    struct cliq_source_birth_record record;
    memset(&record, 0, sizeof(record));
    record.step = source_scope.birth_step + 1; record.kind = kind;
    memcpy(record.previous, source_scope.birth_digest, sizeof(record.previous)); record.packet = *packet;
    struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)&record, offsetof(struct cliq_source_birth_record, digest)); sha256_final(&hash, record.digest);
    off_t expected = (off_t)sizeof(struct cliq_source_birth) + (off_t)sizeof(struct cliq_source_controller_birth) +
        (off_t)source_scope.birth_step * (off_t)sizeof(record);
    struct stat file;
    if (kind == 0 || kind > 12 || source_scope.birth_step >= 12 || fstat(source_scope.birth, &file) != 0 ||
        !S_ISREG(file.st_mode) || file.st_nlink != 1 || (file.st_mode & 07777) != 0600 || file.st_uid != geteuid() ||
        source_scope.binding.birth_device != (uint64_t)file.st_dev || source_scope.binding.birth_inode != (uint64_t)file.st_ino ||
        file.st_size != expected || lseek(source_scope.birth, expected, SEEK_SET) != expected ||
        !source_write_all(source_scope.birth, &record, sizeof(record)) || fsync(source_scope.birth) != 0) return false;
    source_scope.birth_step = record.step; memcpy(source_scope.birth_digest, record.digest, sizeof(record.digest)); return true;
}
static bool source_controller_same(const struct cliq_worker_packet *request) {
    return source_scope.attempted && cliq_fixed_git_same_attempt(&source_scope.identity, request) &&
        strcmp(source_scope.identity.cgroup_name, request->cgroup_name) == 0 &&
        (!source_scope.blocked || cliq_fixed_git_same_prepared(&source_scope.identity, request));
}
static bool source_controller_root_current(void) {
    struct stat root, group, named;
    return native_cgroup(source_scope.anchor) && fstat(source_scope.anchor, &root) == 0 &&
        root.st_dev == source_scope.anchor_identity.st_dev && root.st_ino == source_scope.anchor_identity.st_ino &&
        root.st_uid == source_scope.anchor_identity.st_uid && root.st_gid == source_scope.anchor_identity.st_gid &&
        root.st_mode == source_scope.anchor_identity.st_mode && native_cgroup(source_scope.cgroup) &&
        fstat(source_scope.cgroup, &group) == 0 && group.st_dev == source_scope.cgroup_identity.st_dev &&
        group.st_ino == source_scope.cgroup_identity.st_ino && group.st_uid == source_scope.cgroup_identity.st_uid &&
        group.st_mode == source_scope.cgroup_identity.st_mode &&
        fstatat(source_scope.anchor, source_scope.identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        group.st_dev == named.st_dev && group.st_ino == named.st_ino && group.st_mode == named.st_mode && group.st_uid == named.st_uid;
}
static bool source_control_equals(int group, const char *name, const char *expected) {
    int fd = openat(group, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); char text[128];
    if (fd < 0) return false;
    ssize_t bytes; do { bytes = read(fd, text, sizeof(text) - 1); } while (bytes < 0 && errno == EINTR);
    bool valid = bytes > 0 && bytes < (ssize_t)sizeof(text) - 1;
    if (!source_close_fd(&fd)) valid = false;
    if (!valid) return false;
    text[bytes] = '\0'; return strcmp(text, expected) == 0;
}
static bool source_resources(const struct cliq_worker_packet *request) {
    if (!resources(source_scope.cgroup, request)) return false;
    char text[128];
    snprintf(text, sizeof(text), "%llu\n", (unsigned long long)request->max_processes);
    if (!source_control_equals(source_scope.cgroup, "pids.max", text)) return false;
    snprintf(text, sizeof(text), "%llu\n", (unsigned long long)request->memory_bytes);
    if (!source_control_equals(source_scope.cgroup, "memory.max", text) || !source_control_equals(source_scope.cgroup, "memory.swap.max", "0\n")) return false;
    snprintf(text, sizeof(text), "%llu 1000000\n", (unsigned long long)request->cpu_quota);
    return source_control_equals(source_scope.cgroup, "cpu.max", text);
}
static bool source_reserve(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response) {
    source_controller_init();
    if (source_scope.attempted || worker_reservation.fd >= 0 || worker_creation_attempted || request->scope == 0 ||
        request->scope >= CLIQ_WORKER_MAX_SCOPES || !cliq_source_request_valid(request) || count < 10 || count > CLIQ_WORKER_MAX_FDS ||
        strncmp(request->cgroup_name, "cliq-source-", 12) != 0 || !cliq_source_digest(request->cgroup_name + 12)) return false;
    for (size_t i = 1; i < CLIQ_WORKER_MAX_SCOPES; i++) if (scopes[i].created) return false;
    struct cliq_source_birth birth;
    struct stat root, git, file, anchor;
    bool valid = native_cgroup(passed[0]) && fstat(passed[0], &anchor) == 0 &&
        fstat(passed[1], &root) == 0 && S_ISDIR(root.st_mode) && root.st_uid == geteuid() &&
        fstat(passed[2], &git) == 0 && S_ISDIR(git.st_mode) && git.st_uid == geteuid() && root.st_dev == git.st_dev &&
        fstat(passed[3], &file) == 0 && S_ISREG(file.st_mode) && file.st_nlink == 1 && file.st_uid == geteuid() &&
        (file.st_mode & 07777) == 0600 && file.st_size == (off_t)sizeof(birth) + (off_t)sizeof(source_scope.creator) &&
        pread(passed[3], &birth, sizeof(birth), 0) == (ssize_t)sizeof(birth) &&
        cliq_source_birth_origin_valid(&birth) && birth.owner_uid == (uint64_t)geteuid() &&
        birth.birth_device == (uint64_t)file.st_dev && birth.birth_inode == (uint64_t)file.st_ino &&
        birth.workspace_device == (uint64_t)root.st_dev && birth.workspace_inode == (uint64_t)root.st_ino &&
        birth.git_device == (uint64_t)git.st_dev && birth.git_inode == (uint64_t)git.st_ino &&
        memcmp(birth.inspection_id, request->source_inspection_id, sizeof(birth.inspection_id)) == 0 &&
        memcmp(birth.staging_nonce, request->nonce, sizeof(birth.staging_nonce)) == 0 &&
        memcmp(birth.target_ref, request->source_target_ref, sizeof(birth.target_ref)) == 0 &&
        memcmp(birth.input_intent_ref, request->source_input_intent_ref, sizeof(birth.input_intent_ref)) == 0;
    unsigned char digest[32]; struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)&birth, offsetof(struct cliq_source_birth, digest)); sha256_final(&hash, digest);
    valid = valid && memcmp(digest, birth.digest, sizeof(digest)) == 0 &&
        pread(passed[3], &source_scope.creator, sizeof(source_scope.creator), (off_t)sizeof(birth)) == (ssize_t)sizeof(source_scope.creator) &&
        cliq_source_controller_frame_valid(&source_scope.creator, &birth) && source_scope.creator.pid == getpid() &&
        cliq_source_directory_matches(&source_scope.creator.root, &anchor) && source_read_config(passed[4], &source_scope.config) &&
        count == 8 + source_scope.config.file_count;
    int controllers = valid ? openat(passed[0], "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int original_leaf = controllers >= 0 ? openat(controllers, source_scope.creator.leaf_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat original; char token[CLIQ_WORKER_TOKEN_BYTES], pid_text[32];
    snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
    valid = valid && controllers >= 0 && original_leaf >= 0 && native_cgroup(controllers) && native_cgroup(original_leaf) &&
        fstat(controllers, &original) == 0 && cliq_source_directory_matches(&source_scope.creator.parent, &original) &&
        fstat(original_leaf, &original) == 0 && cliq_source_directory_matches(&source_scope.creator.leaf, &original) &&
        source_control_equals(original_leaf, "cgroup.procs", pid_text) && cliq_process_token(getpid(), token) &&
        strcmp(token, source_scope.creator.process_start_token) == 0;
    if (!source_close_fd(&original_leaf)) valid = false;
    if (!source_close_fd(&controllers)) valid = false;
    for (size_t i = 5; valid && i < count; i++) {
        struct stat image; int seals = fcntl(passed[i], F_GET_SEALS);
        uint64_t expected = i == 5 ? source_scope.config.init_bytes : i == 7 ? source_scope.config.inspector_bytes : i >= 8 ? source_scope.config.files[i - 8].byte_count : 0;
        valid = fstat(passed[i], &image) == 0 && S_ISREG(image.st_mode) && image.st_size > 0 &&
            image.st_size <= 268435456 && (expected == 0 || (uint64_t)image.st_size == expected) &&
            seals == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    }
    uint64_t runtime_budget, storage_reserve;
    if (!valid || !cliq_source_storage_reserve(&source_scope.config, request, &runtime_budget, &storage_reserve) ||
        flock(passed[3], LOCK_EX | LOCK_NB) != 0) return false;
    source_scope.attempted = true; source_scope.identity = *request; source_scope.binding = birth; source_scope.anchor_identity = anchor;
    int *slots[] = { &source_scope.anchor, &source_scope.root, &source_scope.git, &source_scope.birth,
        &source_scope.config_fd, &source_scope.helper, &source_scope.bwrap, &source_scope.inspector };
    for (size_t i = 0; i < 8; i++) { *slots[i] = passed[i]; passed[i] = -1; }
    for (uint32_t i = 0; i < source_scope.config.file_count; i++) { source_scope.files[i] = passed[8 + i]; passed[8 + i] = -1; }
    memcpy(source_scope.birth_digest, source_scope.creator.digest, sizeof(source_scope.birth_digest));
    struct cliq_worker_packet intent = *request;
    intent.subreaper_pid = getpid();
    if (!cliq_process_token(getpid(), intent.subreaper_start_token) || !source_birth_step(1, &intent) ||
        mkdirat(source_scope.anchor, request->cgroup_name, 0700) != 0) return false;
    source_scope.cgroup = openat(source_scope.anchor, request->cgroup_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (source_scope.cgroup < 0 || !native_cgroup(source_scope.cgroup) || fstat(source_scope.cgroup, &source_scope.cgroup_identity) != 0) return false;
    source_scope.created = true;
    source_scope.identity.cgroup_device = (uint64_t)source_scope.cgroup_identity.st_dev;
    source_scope.identity.cgroup_inode = (uint64_t)source_scope.cgroup_identity.st_ino;
    source_scope.identity.subreaper_pid = intent.subreaper_pid;
    memcpy(source_scope.identity.subreaper_start_token, intent.subreaper_start_token, sizeof(intent.subreaper_start_token));
    if (!source_birth_step(2, &source_scope.identity) || !cgroup_empty(source_scope.cgroup) || !source_resources(request) ||
        !source_controller_root_current()) return false;
    *response = source_scope.identity; response->command = CLIQ_SOURCE_RESERVE;
    return stamp_observation(response);
}
static void source_bubblewrap(void) {
    int keep[CLIQ_WORKER_MAX_FDS]; size_t count = 0;
    keep[count++] = source_scope.helper; keep[count++] = source_scope.bwrap; keep[count++] = source_scope.inspector;
    for (uint32_t i = 0; i < source_scope.config.file_count; i++) keep[count++] = source_scope.files[i];
    if (!retain_descriptors(keep, count)) _exit(70);
    int helper = independent_image_fd(source_scope.helper, 4);
    if (helper < 0 || close(source_scope.helper) != 0) _exit(70);
    int bwrap = fcntl(source_scope.bwrap, F_DUPFD_CLOEXEC, 4);
    if (bwrap < 0 || close(source_scope.bwrap) != 0) _exit(70);
    int inspector = independent_image_fd(source_scope.inspector, 4);
    if (inspector < 0 || close(source_scope.inspector) != 0) _exit(70);
    count = 0; keep[count++] = helper; keep[count++] = bwrap; keep[count++] = inspector;
    char descriptors[CLIQ_SOURCE_MAX_FILES + 2][24];
    snprintf(descriptors[0], sizeof(descriptors[0]), "%d", helper);
    snprintf(descriptors[1], sizeof(descriptors[1]), "%d", inspector);
    for (uint32_t i = 0; i < source_scope.config.file_count; i++) {
        int file = independent_image_fd(source_scope.files[i], 4);
        if (file < 0 || close(source_scope.files[i]) != 0) _exit(70);
        keep[count++] = file; snprintf(descriptors[i + 2], sizeof(descriptors[i + 2]), "%d", file);
    }
    if (!retain_descriptors(keep, count)) _exit(70);
    char *arguments[256]; size_t at = 0; char quota[32], root_quota[32]; uint64_t runtime_budget, storage_reserve;
    if (!cliq_source_storage_reserve(&source_scope.config, &source_scope.identity, &runtime_budget, &storage_reserve)) _exit(70);
    snprintf(quota, sizeof(quota), "%llu", (unsigned long long)source_scope.identity.max_generation_bytes);
    snprintf(root_quota, sizeof(root_quota), "%llu", (unsigned long long)runtime_budget);
#define SOURCE_ARG(value) do { if (at >= sizeof(arguments) / sizeof(arguments[0]) - 1) _exit(70); arguments[at++] = (char *)(value); } while (0)
    SOURCE_ARG("bwrap"); SOURCE_ARG("--unshare-user"); SOURCE_ARG("--uid"); SOURCE_ARG("0"); SOURCE_ARG("--gid"); SOURCE_ARG("0");
    SOURCE_ARG("--unshare-pid"); SOURCE_ARG("--as-pid-1"); SOURCE_ARG("--unshare-net"); SOURCE_ARG("--unshare-ipc");
    SOURCE_ARG("--unshare-uts"); SOURCE_ARG("--unshare-cgroup"); SOURCE_ARG("--new-session"); SOURCE_ARG("--die-with-parent");
    SOURCE_ARG("--cap-drop"); SOURCE_ARG("ALL"); SOURCE_ARG("--cap-add"); SOURCE_ARG("CAP_SYS_ADMIN"); SOURCE_ARG("--cap-add"); SOURCE_ARG("CAP_SETPCAP");
    SOURCE_ARG("--clearenv"); SOURCE_ARG("--size"); SOURCE_ARG(root_quota); SOURCE_ARG("--tmpfs"); SOURCE_ARG("/"); SOURCE_ARG("--dir"); SOURCE_ARG("/runtime");
    SOURCE_ARG("--perms"); SOURCE_ARG("0555"); SOURCE_ARG("--ro-bind-data"); SOURCE_ARG(descriptors[0]); SOURCE_ARG("/runtime/cliq-linux-worker-init");
    SOURCE_ARG("--perms"); SOURCE_ARG("0444"); SOURCE_ARG("--ro-bind-data"); SOURCE_ARG(descriptors[1]); SOURCE_ARG("/runtime/cliq-source-git-inspector.mjs");
    const char *directories[] = { "/usr", "/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/lib", "/lib/x86_64-linux-gnu", "/lib64" };
    for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) { SOURCE_ARG("--dir"); SOURCE_ARG(directories[i]); }
    for (size_t i = 0; i < sizeof(cliq_source_profile_directories) / sizeof(cliq_source_profile_directories[0]); i++) {
        SOURCE_ARG("--perms"); SOURCE_ARG("0555"); SOURCE_ARG("--dir"); SOURCE_ARG(cliq_source_profile_directories[i]);
    }
    for (uint32_t i = 0; i < source_scope.config.file_count; i++) {
        SOURCE_ARG("--perms"); SOURCE_ARG("0555");
        SOURCE_ARG(strcmp(source_scope.config.files[i].path, "/usr/bin/node") == 0 || strcmp(source_scope.config.files[i].path, "/usr/bin/git") == 0 ? "--file" : "--ro-bind-data");
        SOURCE_ARG(descriptors[i + 2]); SOURCE_ARG(source_scope.config.files[i].path);
    }
    SOURCE_ARG("--proc"); SOURCE_ARG("/proc"); SOURCE_ARG("--dev"); SOURCE_ARG("/dev");
    SOURCE_ARG("--size"); SOURCE_ARG(quota); SOURCE_ARG("--tmpfs"); SOURCE_ARG("/scratch"); SOURCE_ARG("--chdir"); SOURCE_ARG("/scratch");
    SOURCE_ARG("--"); SOURCE_ARG("/runtime/cliq-linux-worker-init"); arguments[at] = NULL;
#undef SOURCE_ARG
    char *const environment[] = { "LANG=C", "LC_ALL=C", NULL };
    fexecve(bwrap, arguments, environment); _exit(70);
}
static bool source_create_blocked(struct cliq_worker_packet *request, struct cliq_worker_packet *response) {
    if (!source_controller_same(request) || !source_scope.created || source_scope.blocked || source_scope.failed ||
        !source_controller_root_current() || !cgroup_empty(source_scope.cgroup) ||
        (source_scope.preparation ? !cliq_preparation_request_valid(request) : !cliq_source_digest(request->plan_ref) ||
        !cliq_source_digest(request->sandbox_launch_ref) || !cliq_source_digest(request->sandbox_launch_digest) || request->generation_ref[0])) return false;
    uint64_t cgroup_device = source_scope.identity.cgroup_device, cgroup_inode = source_scope.identity.cgroup_inode;
    source_scope.identity = *request; source_scope.identity.cgroup_device = cgroup_device; source_scope.identity.cgroup_inode = cgroup_inode;
    if (!source_birth_step(3, &source_scope.identity)) return false;
    source_scope.stdout_fd = memfd_create("cliq-source-stdout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    source_scope.stderr_fd = memfd_create("cliq-source-stderr", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    int channel[2], barrier[2];
    if (source_scope.stdout_fd < 0 || source_scope.stderr_fd < 0 || socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) return false;
    if (pipe2(barrier, O_CLOEXEC) != 0) { close(channel[0]); close(channel[1]); return false; }
    struct scope *process = &source_scope.process;
    process->monitor = fork();
    if (process->monitor < 0) { close(channel[0]); close(channel[1]); close(barrier[0]); close(barrier[1]); return false; }
    if (process->monitor == 0) {
        close(channel[0]); close(barrier[1]); char go;
        if (read(barrier[0], &go, 1) != 1 || go != '1' || dup2(source_scope.stdout_fd, 1) < 0 ||
            dup2(source_scope.stderr_fd, 2) < 0 || !configure_limits(request) || dup2(channel[1], 3) < 0) _exit(70);
        source_bubblewrap(); _exit(70);
    }
    close(channel[1]); close(barrier[0]); source_scope.channel = channel[0];
    process->cgroup = source_scope.cgroup; process->process_group = source_scope.cgroup; process->channel = source_scope.channel;
    if (!cliq_process_token(process->monitor, process->monitor_start_token)) { close(barrier[1]); return false; }
    source_scope.identity.monitor_pid = process->monitor;
    memcpy(source_scope.identity.monitor_start_token, process->monitor_start_token, sizeof(process->monitor_start_token));
    if (!source_birth_step(4, &source_scope.identity)) { close(barrier[1]); return false; }
    char pid[32]; snprintf(pid, sizeof(pid), "%ld", (long)process->monitor);
    bool placed = write_control(source_scope.cgroup, "cgroup.procs", pid) && write(barrier[1], "1", 1) == 1;
    if (close(barrier[1]) != 0) placed = false;
    int input[] = { source_scope.config_fd, source_scope.preparation ? source_scope.preparation_stream : source_scope.root, source_scope.git }; size_t count;
    struct cliq_worker_packet ready;
    if (!placed || !cliq_send(source_scope.channel, &source_scope.identity, input, source_scope.preparation ? 2 : 3) || !readable(source_scope.channel, OBSERVATION_TIMEOUT_MS) ||
        !cliq_receive(source_scope.channel, &ready, NULL, 0, &count) || ready.command != CLIQ_WORKER_READY ||
        !cliq_fixed_git_same_attempt(&source_scope.identity, &ready) || !inspect_processes(process, &ready)) return false;
    if (cgroup_empty(source_scope.cgroup)) return false;
    source_scope.identity.populated = 1;
    source_scope.identity.pid = process->worker; source_scope.identity.namespace_init_pid = process->init;
    source_scope.identity.pid_namespace_inode = ready.pid_namespace_inode;
    memcpy(source_scope.identity.start_token, ready.start_token, sizeof(ready.start_token));
    memcpy(source_scope.identity.init_native_start_token, ready.init_start_token, sizeof(ready.init_start_token));
    int length = snprintf(source_scope.identity.init_start_token, sizeof(source_scope.identity.init_start_token),
        "linux-namespace-init:%ld:%s:monitor:%ld:%s", (long)process->init,
        ready.init_start_token + strlen("linux-proc-start-ticks:"), (long)process->monitor,
        process->monitor_start_token + strlen("linux-proc-start-ticks:"));
    if (length <= 0 || (size_t)length >= sizeof(source_scope.identity.init_start_token)) return false;
    process->identity = source_scope.identity; process->created = true;
    source_scope.blocked = true;
    if (!source_birth_step(5, &source_scope.identity)) return false;
    *response = source_scope.identity; response->command = CLIQ_SOURCE_CREATE_BLOCKED; return stamp_observation(response);
}
static bool source_process_current(void) {
    struct scope *process = &source_scope.process;
    char token[CLIQ_WORKER_TOKEN_BYTES], path[128]; struct stat image, named, namespace;
    if (!source_scope.blocked || source_scope.dead || !source_controller_root_current() ||
        !cliq_process_token(process->worker, token) || strcmp(token, source_scope.identity.start_token) != 0) return false;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)process->worker);
    if (stat(path, &image) != 0 || !S_ISREG(image.st_mode)) return false;
    snprintf(path, sizeof(path), "/proc/%ld/root/runtime/cliq-linux-worker-init", (long)process->worker);
    if (stat(path, &named) != 0 || named.st_dev != image.st_dev || named.st_ino != image.st_ino) return false;
    snprintf(path, sizeof(path), "/proc/%ld/ns/pid", (long)process->worker);
    struct tracked_set members = {0}; bool placed = false;
    if (!collect_processes(source_scope.cgroup, &members, 0)) return false;
    for (size_t i = 0; i < members.count; i++) if (members.process[i].pid == process->worker &&
        strcmp(members.process[i].token, source_scope.identity.start_token) == 0) placed = true;
    return placed && stat(path, &namespace) == 0 && (uint64_t)namespace.st_ino == source_scope.identity.pid_namespace_inode &&
        cliq_process_token(process->worker, token) && strcmp(token, source_scope.identity.start_token) == 0;
}
static bool source_stop(struct cliq_worker_packet *response) {
    if (!source_scope.created || !source_controller_root_current()) return false;
    if (!source_scope.dead) {
        struct tracked_set tracked = {0}; struct scope *process = &source_scope.process;
        if (!collect_processes(source_scope.cgroup, &tracked, 0)) return false;
        if (process->monitor > 0 && (!*process->monitor_start_token ||
            !track_process(&tracked, process->monitor, process->monitor_start_token))) return false;
        if (source_scope.blocked && (!track_process(&tracked, process->init, source_scope.identity.init_native_start_token) ||
            !track_process(&tracked, process->worker, source_scope.identity.start_token))) return false;
        if (!write_control(source_scope.cgroup, "cgroup.kill", "1")) return false;
        /* The recorded monitor may still be blocked before cgroup attach.
         * Its original child relationship plus start token, not a reused PID,
         * is required before signalling and joining this creation prefix. */
        if (process->monitor > 0 && !source_scope.monitor_joined && !original_process_absent(process->monitor, process->monitor_start_token)) {
            char token[CLIQ_WORKER_TOKEN_BYTES];
            if (!cliq_process_token(process->monitor, token) || strcmp(token, process->monitor_start_token) != 0 ||
                (kill(process->monitor, SIGKILL) != 0 && errno != ESRCH)) return false;
        }
        if (!source_close_fd(&source_scope.channel)) return false;
        process->channel = -1;
        int64_t start = milliseconds(); if (start < 0) return false;
        for (;;) {
            int status; pid_t joined;
            while ((joined = waitpid(-1, &status, WNOHANG)) > 0)
                if (joined == process->monitor) {
                    source_scope.monitor_joined = true;
                    source_scope.monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                }
            bool exact_dead = source_scope.blocked ? held_scope_dead(process) : cgroup_empty(source_scope.cgroup);
            if (exact_dead && tracked_absent(&tracked) && (process->monitor <= 0 || source_scope.monitor_joined)) {
                source_scope.dead = true; break;
            }
            int64_t now = milliseconds(); if (now < start || now - start > OBSERVATION_TIMEOUT_MS) return false;
            struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
        }
    } else if (source_scope.blocked ? !held_scope_dead(&source_scope.process) : !cgroup_empty(source_scope.cgroup)) return false;
    *response = source_scope.identity; response->command = CLIQ_SOURCE_STOP;
    response->populated = 0; response->remaining_descendants = 0; response->init_reaped = source_scope.blocked ? 1 : 0;
    return stamp_observation(response);
}
/* A successful result cannot use kill to hide the producer/PID1 close or
 * exit status. Every normal layer first closes and exits naturally; only then
 * may the original controller expose the result and whole-domain death. */
static bool source_result_joined(void) {
    struct scope *process = &source_scope.process;
    if (!source_scope.result || !source_scope.blocked || !source_controller_root_current()) return false;
    if (!source_scope.monitor_joined) {
        int status; pid_t joined;
        do { joined = waitpid(process->monitor, &status, WNOHANG); } while (joined < 0 && errno == EINTR);
        if (joined == 0) return false;
        if (joined != process->monitor) { source_scope.failed = true; return false; }
        source_scope.monitor_joined = true; source_scope.monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (!source_scope.monitor_success) { source_scope.failed = true; return false; }
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    if (!held_scope_dead(process)) return false;
    source_scope.dead = true; return true;
}
static bool source_pump(void) {
    if (!source_scope.blocked || source_scope.dead || source_scope.result || source_scope.failed) return true;
    struct pollfd ready = { .fd = source_scope.channel, .events = POLLIN };
    int available; do { available = poll(&ready, 1, 0); } while (available < 0 && errno == EINTR);
    if (available < 0) return false;
    if (available == 0) return true;
    if (!(ready.revents & POLLIN)) { source_scope.failed = true; return true; }
    struct cliq_worker_packet packet; int files[CLIQ_SOURCE_TRANSFER_OUTPUTS] = {-1, -1, -1, -1, -1}; size_t count;
    bool valid = cliq_receive(source_scope.channel, &packet, files, CLIQ_SOURCE_TRANSFER_OUTPUTS, &count) &&
        cliq_fixed_git_same_prepared(&source_scope.identity, &packet);
    if (valid && packet.command == CLIQ_SOURCE_SEALED && source_scope.released && !source_scope.sealed && !source_scope.continued && count == 0 &&
        cliq_source_digest(packet.source_snapshot_digest) && packet.source_shard_count > 0 && packet.source_shard_count <= CLIQ_SOURCE_MAX_SHARDS &&
        packet.source_entry_count > 0 && packet.source_entry_count <= CLIQ_SOURCE_MAX_ENTRIES && packet.source_byte_count > 0 &&
        packet.source_byte_count <= source_scope.identity.max_generation_bytes) {
        source_scope.sealed = true; source_scope.sealed_packet = source_scope.identity;
        source_scope.sealed_packet.source_byte_count = packet.source_byte_count;
        source_scope.sealed_packet.source_entry_count = packet.source_entry_count;
        source_scope.sealed_packet.source_shard_count = packet.source_shard_count;
        memcpy(source_scope.sealed_packet.source_snapshot_digest, packet.source_snapshot_digest, sizeof(packet.source_snapshot_digest));
        valid = source_birth_step(7, &source_scope.sealed_packet);
    } else if (valid && packet.command == CLIQ_SOURCE_RESULT && source_scope.continued && !source_scope.result && cliq_source_rule_result_valid(&packet) &&
        count == CLIQ_SOURCE_OUTPUTS + packet.source_rule_present &&
        strcmp(packet.source_snapshot_digest, source_scope.sealed_packet.source_snapshot_digest) == 0 &&
        packet.source_byte_count == source_scope.sealed_packet.source_byte_count && packet.source_entry_count == source_scope.sealed_packet.source_entry_count &&
        packet.source_shard_count == source_scope.sealed_packet.source_shard_count) {
        for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) {
            struct stat file; int seals = fcntl(files[i], F_GET_SEALS);
            valid = valid && fstat(files[i], &file) == 0 && S_ISREG(file.st_mode) && file.st_size >= 0 &&
                (uint64_t)file.st_size <= source_scope.identity.max_file_bytes &&
                (i != 0 || (uint64_t)file.st_size <= source_scope.identity.max_output_bytes) &&
                (uint64_t)file.st_size == packet.source_output_bytes[i] && cliq_source_digest(packet.source_output_digests[i]) &&
                seals == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        }
        if (valid && packet.source_rule_present) {
            struct stat rule;
            valid = fstat(files[4], &rule) == 0 && S_ISREG(rule.st_mode) && rule.st_nlink == 0 && rule.st_size >= 0 &&
                (uint64_t)rule.st_size == packet.source_rule_bytes &&
                fcntl(files[4], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        }
        if (valid) {
            for (size_t i = 0; i < count; i++) { source_scope.output[i] = files[i]; files[i] = -1; }
            source_scope.result_packet = source_scope.sealed_packet;
            memcpy(source_scope.result_packet.source_output_bytes, packet.source_output_bytes, sizeof(packet.source_output_bytes));
            memcpy(source_scope.result_packet.source_output_digests, packet.source_output_digests, sizeof(packet.source_output_digests));
            source_scope.result_packet.source_rule_present = packet.source_rule_present;
            source_scope.result_packet.source_rule_bytes = packet.source_rule_bytes;
            memcpy(source_scope.result_packet.source_rule_digest, packet.source_rule_digest, sizeof(packet.source_rule_digest));
            source_scope.result = source_birth_step(9, &source_scope.result_packet); valid = source_scope.result;
        }
    } else valid = false;
    for (size_t i = 0; i < count; i++) if (!source_close_fd(&files[i])) valid = false;
    if (!valid) source_scope.failed = true;
    return true;
}
static bool source_retire(struct cliq_worker_packet *response) {
    if (source_scope.retired) return false;
    struct cliq_worker_packet death;
    if (!source_stop(&death) || !source_controller_root_current()) return false;
    bool joined = true;
    int *slots[] = { &source_scope.channel, &source_scope.root, &source_scope.git, &source_scope.config_fd,
        &source_scope.helper, &source_scope.bwrap, &source_scope.inspector, &source_scope.stdout_fd, &source_scope.stderr_fd, &source_scope.preparation_stream };
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) if (!source_close_fd(slots[i])) joined = false;
    source_scope.process.channel = -1;
    for (size_t i = 0; i < CLIQ_SOURCE_MAX_FILES; i++) if (!source_close_fd(&source_scope.files[i])) joined = false;
    for (size_t i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (!source_close_fd(&source_scope.output[i])) joined = false;
    if (!joined || !source_birth_step(11, &death) || !source_controller_root_current() ||
        unlinkat(source_scope.anchor, source_scope.identity.cgroup_name, AT_REMOVEDIR) != 0) return false;
    struct stat named, anchor;
    if (fstatat(source_scope.anchor, source_scope.identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        fstat(source_scope.anchor, &anchor) != 0 || anchor.st_dev != source_scope.anchor_identity.st_dev ||
        anchor.st_ino != source_scope.anchor_identity.st_ino || anchor.st_uid != source_scope.anchor_identity.st_uid ||
        anchor.st_mode != source_scope.anchor_identity.st_mode || !source_birth_step(12, &death)) return false;
    if (!source_close_fd(&source_scope.cgroup)) joined = false;
    source_scope.process.cgroup = source_scope.process.process_group = -1;
    if (!source_close_fd(&source_scope.anchor)) joined = false;
    if (!source_close_fd(&source_scope.birth)) joined = false;
    if (!joined) return false;
    source_scope.retired = true; *response = death; response->command = CLIQ_SOURCE_RETIRE; return stamp_observation(response);
}
static bool source_command(struct cliq_worker_packet *request, int *passed, size_t count,
    struct cliq_worker_packet *response, int *outputs, size_t *output_count) {
    if (request->command == CLIQ_SOURCE_RESERVE) {
        bool valid = source_reserve(request, passed, count, response);
        if (valid) { outputs[0] = source_scope.cgroup; *output_count = 1; }
        return valid;
    }
    if (count != 0 || !source_controller_same(request)) return false;
    if (request->command == CLIQ_SOURCE_CREATE_BLOCKED) return source_create_blocked(request, response);
    if (request->command == CLIQ_SOURCE_RELEASE_CAPTURE) {
        if (source_scope.released || source_scope.failed || !source_process_current() || !source_birth_step(6, request) ||
            !cliq_send(source_scope.channel, request, NULL, 0)) return false;
        source_scope.released = true; *response = source_scope.identity; response->command = request->command; return true;
    }
    if (request->command == CLIQ_SOURCE_POLL_SEALED) {
        if (!source_scope.released || source_scope.failed) return false;
        *response = source_scope.sealed ? source_scope.sealed_packet : source_scope.identity;
        response->command = CLIQ_SOURCE_POLL_SEALED; response->exit_status = source_scope.sealed ? 1 : 0; return true;
    }
    if (request->command == CLIQ_SOURCE_CONTINUE_GIT) {
        if (!source_scope.sealed || source_scope.continued || source_scope.failed || !source_process_current() ||
            strcmp(request->source_snapshot_digest, source_scope.sealed_packet.source_snapshot_digest) != 0 ||
            !source_birth_step(8, request) || !cliq_send(source_scope.channel, request, NULL, 0)) return false;
        source_scope.continued = true; *response = source_scope.identity; response->command = request->command; return true;
    }
    if (request->command == CLIQ_SOURCE_POLL_RESULT) {
        if (!source_scope.continued || source_scope.failed) return false;
        *response = source_scope.identity; response->command = CLIQ_SOURCE_POLL_RESULT;
        if (!source_scope.result || !source_result_joined()) return !source_scope.failed;
        struct cliq_worker_packet death;
        if (!source_stop(&death)) return false;
        *response = source_scope.result_packet; response->command = CLIQ_SOURCE_POLL_RESULT; response->exit_status = 1;
        response->populated = death.populated; response->remaining_descendants = death.remaining_descendants; response->init_reaped = death.init_reaped;
        response->observed_at_ms = death.observed_at_ms;
        if (source_scope.preparation && !preparation_record_result(response)) return false;
        *output_count = CLIQ_SOURCE_OUTPUTS + response->source_rule_present;
        for (size_t i = 0; i < *output_count; i++) outputs[i] = source_scope.output[i];
        return true;
    }
    if (request->command == CLIQ_SOURCE_STOP) return source_stop(response);
    if (request->command == CLIQ_SOURCE_RETIRE) return source_retire(response);
    return false;
}
#endif
