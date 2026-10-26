#ifndef CLIQ_SOURCE_GIT_INIT_H
#define CLIQ_SOURCE_GIT_INIT_H

#include "source-git-materialize.h"
#include "preparation-git-protocol.h"
#include "preparation-failure-relay.h"
#include "source-storage.h"
#include <sys/statvfs.h>

static bool source_initial_storage_current(const struct cliq_source_config *config, const struct cliq_worker_packet *request) {
    uint64_t root_limit, reserve;
    if (!cliq_source_storage_reserve(config, request, &root_limit, &reserve)) return false;
    int root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int scratch = open("/scratch", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat root_object, scratch_object;
    bool valid = root >= 0 && scratch >= 0 && fstat(root, &root_object) == 0 && fstat(scratch, &scratch_object) == 0 &&
        root_object.st_uid == geteuid() && scratch_object.st_uid == geteuid() && root_object.st_dev != scratch_object.st_dev &&
        source_tmpfs_within(root, root_limit) && source_tmpfs_within(scratch, request->max_generation_bytes);
    if (!source_close_fd(&root)) valid = false;
    if (!source_close_fd(&scratch)) valid = false;
    return valid;
}

static void source_hex(const unsigned char digest[32], char encoded[65]) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) { encoded[i * 2] = alphabet[digest[i] >> 4]; encoded[i * 2 + 1] = alphabet[digest[i] & 15]; }
    encoded[64] = '\0';
}
static bool source_read_config(int fd, struct cliq_source_config *config) {
    struct stat file; int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(fd, &file) != 0 || !S_ISREG(file.st_mode) || file.st_size != (off_t)sizeof(*config) ||
        fcntl(fd, F_GET_SEALS) != required) return false;
    size_t offset = 0;
    while (offset < sizeof(*config)) {
        ssize_t count = pread(fd, (unsigned char *)config + offset, sizeof(*config) - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return cliq_source_config_valid(config);
}
static bool source_named_runtime_current(int parent, int fd, const char *name, const struct stat *held) {
    struct stat file, named;
    return fstat(fd, &file) == 0 && fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(file.st_mode) && file.st_uid == geteuid() && file.st_gid == getegid() && file.st_nlink == 1 &&
        (file.st_mode & 07777) == 0555 && source_stat_same(held, &file) && source_stat_same(held, &named);
}
/* Node and Git need named executable inodes for their own execPath/fixed
 * child execs. Both are freshly fully read and self-bound before exec rights
 * are enabled. No metadata/image/currentness cache replaces these reads. */
static bool source_bind_runtime(const struct cliq_source_config *config, const char *name) {
    int usr = open("/usr/bin", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (usr < 0) return false;
    const char *path = strcmp(name, "node") == 0 ? "/usr/bin/node" : "/usr/bin/git";
    const char *digest = NULL; uint64_t expected = 0;
    for (uint32_t i = 0; i < config->file_count; i++) if (strcmp(config->files[i].path, path) == 0) {
        digest = config->files[i].digest; expected = config->files[i].byte_count;
    }
    int image = digest ? openat(usr, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) : -1;
    struct stat held; bool valid = image >= 0 && fstat(image, &held) == 0 && held.st_size > 0 &&
        (uint64_t)held.st_size == expected && source_named_runtime_current(usr, image, name, &held);
    struct sha256_context hash; sha256_init(&hash); unsigned char buffer[65536]; uint64_t offset = 0;
    while (valid && offset < expected) {
        size_t wanted = expected - offset < sizeof(buffer) ? (size_t)(expected - offset) : sizeof(buffer);
        ssize_t count = pread(image, buffer, wanted, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = false; break; }
        sha256_update(&hash, buffer, (size_t)count); offset += (uint64_t)count;
    }
    unsigned char bytes[32]; char encoded[65]; sha256_final(&hash, bytes); source_hex(bytes, encoded);
    char source[64]; snprintf(source, sizeof(source), "/proc/self/fd/%d", image);
    valid = valid && offset == expected && strcmp(encoded, digest) == 0 && source_named_runtime_current(usr, image, name, &held) &&
        mount(source, path, NULL, MS_BIND, NULL) == 0 && source_named_runtime_current(usr, image, name, &held);
    if (!source_close_fd(&image)) valid = false;
    if (!source_close_fd(&usr)) valid = false;
    return valid;
}
static bool source_confinement(const struct cliq_source_config *config, uint32_t *stage) {
#define SOURCE_CONFINEMENT_STAGE(number) do { if (stage) *stage = (number); } while (0)
    SOURCE_CONFINEMENT_STAGE(2); if (!source_bind_runtime(config, "node")) return false;
    SOURCE_CONFINEMENT_STAGE(3); if (!source_bind_runtime(config, "git")) return false;
    SOURCE_CONFINEMENT_STAGE(4); if (mount("/scratch/input", "/scratch/input", NULL, MS_BIND | MS_REC, NULL) != 0) return false;
    SOURCE_CONFINEMENT_STAGE(5); if (!verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0)) return false;
    SOURCE_CONFINEMENT_STAGE(6); if (!verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0)) return false;
    SOURCE_CONFINEMENT_STAGE(7); if (!verifier_mount_attributes("/scratch/input", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0)) return false;
    SOURCE_CONFINEMENT_STAGE(8); if (!verifier_mount_attributes("/scratch", 0, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0)) return false;
    SOURCE_CONFINEMENT_STAGE(9); if (!verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0)) return false;
    SOURCE_CONFINEMENT_STAGE(10);
    for (uint32_t i = 0; i < config->file_count; i++)
        if (!verifier_mount_attributes(config->files[i].path, 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC)) return false;
    SOURCE_CONFINEMENT_STAGE(11); if (!verifier_mount_observed("/", true, false, false)) return false;
    SOURCE_CONFINEMENT_STAGE(12); if (!verifier_mount_observed("/scratch", false, false, false)) return false;
    SOURCE_CONFINEMENT_STAGE(13); if (!verifier_mount_observed("/scratch/input", true, false, false)) return false;
    SOURCE_CONFINEMENT_STAGE(14); if (!verifier_mount_observed("/proc", true, false, false)) return false;
    SOURCE_CONFINEMENT_STAGE(15); if (!verifier_mount_observed("/dev", false, false, true)) return false;
    SOURCE_CONFINEMENT_STAGE(16);
    for (uint32_t i = 0; i < config->file_count; i++) if (!verifier_mount_observed(config->files[i].path, true, true, false)) return false;
    SOURCE_CONFINEMENT_STAGE(17); if (!verifier_drop_capabilities()) return false;
    SOURCE_CONFINEMENT_STAGE(18); return verifier_filter();
#undef SOURCE_CONFINEMENT_STAGE
}

static int fixed_git_intent(const struct cliq_worker_packet *request, const struct cliq_source_config *config, bool preparation) {
    char json[4096];
    int bytes = cliq_fixed_git_intent_json(json, sizeof(json), request, config, preparation);
    if (bytes <= 0 || (size_t)bytes >= sizeof(json)) return -1;
    int writer = memfd_create("cliq-source-fixed-intent", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    bool valid = writer >= 0 && source_write_all(writer, json, (size_t)bytes);
    int sealed = valid ? source_sealed_readonly(writer) : -1;
    if (!source_close_fd(&writer)) { source_close_fd(&sealed); return -1; }
    return sealed;
}
static int source_intent(const struct cliq_worker_packet *request, const struct cliq_source_config *config) {
    return fixed_git_intent(request, config, false);
}
static bool source_scratch_limit(uint64_t bytes) {
    bytes = source_tmpfs_budget(bytes);
    if (bytes < 1048576) return false;
    char options[128]; int length = snprintf(options, sizeof(options), "size=%llu,mode=0700", (unsigned long long)bytes);
    return length > 0 && (size_t)length < sizeof(options) && mount("tmpfs", "/scratch", "tmpfs", MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC, options) == 0;
}
static bool source_script_current(const struct cliq_source_config *config) {
    int file = open("/runtime/cliq-source-git-inspector.mjs", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat before, after, named; struct sha256_context hash; sha256_init(&hash);
    bool valid = file >= 0 && fstat(file, &before) == 0 && S_ISREG(before.st_mode) && before.st_nlink == 1 &&
        before.st_uid == geteuid() && (before.st_mode & 07777) == 0444 && before.st_size > 0 &&
        (uint64_t)before.st_size == config->inspector_bytes;
    unsigned char buffer[65536]; uint64_t bytes = 0;
    while (valid && bytes < config->inspector_bytes) {
        size_t wanted = config->inspector_bytes - bytes < sizeof(buffer) ? (size_t)(config->inspector_bytes - bytes) : sizeof(buffer);
        ssize_t count = read(file, buffer, wanted);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = false; break; }
        sha256_update(&hash, buffer, (size_t)count); bytes += (uint64_t)count;
    }
    unsigned char extra, digest[32]; char encoded[65]; ssize_t count = -1;
    if (valid) do { count = read(file, &extra, 1); } while (count < 0 && errno == EINTR);
    sha256_final(&hash, digest); source_hex(digest, encoded);
    valid = valid && count == 0 && strcmp(encoded, config->inspector_digest) == 0 &&
        fstat(file, &after) == 0 && source_stat_same(&before, &after) &&
        lstat("/runtime/cliq-source-git-inspector.mjs", &named) == 0 && source_stat_same(&before, &named);
    if (!source_close_fd(&file)) valid = false;
    return valid;
}
static bool source_bound_logs(const struct cliq_worker_packet *request) {
    uint64_t limit = request->max_output_bytes < request->max_file_bytes ? request->max_output_bytes : request->max_file_bytes;
    for (int fd = 1; fd <= 2; fd++) {
        struct stat file;
        if (limit > INT64_MAX || fstat(fd, &file) != 0 || !S_ISREG(file.st_mode) || file.st_size != 0 ||
            ftruncate(fd, (off_t)limit) != 0 || lseek(fd, 0, SEEK_SET) != 0 ||
            fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) != 0 ||
            fcntl(fd, F_GET_SEALS) != (F_SEAL_GROW | F_SEAL_SEAL)) return false;
    }
    return true;
}
static bool fixed_git_run_helper(int raw_config, int intent, int exclude, const struct cliq_source_config *config, bool preparation, uint32_t *diagnosis) {
    int execution[2];
    if (pipe2(execution, O_CLOEXEC) != 0) { source_close_fd(&raw_config); source_close_fd(&intent); return false; }
    pid_t child = fork();
    if (child < 0) { source_close_fd(&execution[0]); source_close_fd(&execution[1]); source_close_fd(&raw_config); source_close_fd(&intent); return false; }
    if (child == 0) {
        close(execution[0]);
        /* An independently granted rule is not a helper/Git input, even as
         * an inherited alias. The trusted non-dumpable producer alone holds
         * it while the fixed helper runs. */
        uint32_t stage = 1;
        if (!source_close_fd(&exclude) || !source_confinement(config, &stage)) {
            if (!cliq_write_exec_diagnostic(execution[1], -(int)stage)) { _exit(70); }
            _exit(70);
        }
        int raw = fcntl(raw_config, F_DUPFD_CLOEXEC, 10), fixed = fcntl(intent, F_DUPFD_CLOEXEC, 11), error = fcntl(execution[1], F_DUPFD_CLOEXEC, 12);
        if (raw < 0 || fixed < 0 || error < 0) {
            if (!cliq_write_exec_diagnostic(execution[1], -19)) { _exit(70); }
            _exit(70);
        }
        if (dup2(raw, 3) < 0 || dup2(fixed, 4) < 0 || dup3(error, 5, O_CLOEXEC) < 0) {
            if (!cliq_write_exec_diagnostic(error, -19)) { _exit(70); }
            _exit(70);
        }
        if (!cliq_close_range(6, UINT_MAX) || chdir("/scratch/input") != 0) {
            if (!cliq_write_exec_diagnostic(5, -19)) { _exit(70); }
            _exit(70);
        }
        char *const argv[] = { "/usr/bin/node", "/runtime/cliq-source-git-inspector.mjs", preparation ? "--prepare-private-git" : NULL, NULL };
        char *const environment[] = { "LANG=C", "LC_ALL=C", "HOME=/scratch/home", "TMPDIR=/scratch/tmp", "PATH=/usr/bin", NULL };
        execve(argv[0], argv, environment);
        int failed = errno; if (!cliq_write_exec_diagnostic(5, failed)) _exit(70); _exit(70);
    }
    bool joined = source_close_fd(&execution[1]);
    if (!source_close_fd(&raw_config)) joined = false;
    if (!source_close_fd(&intent)) joined = false;
    int status = 0; pid_t done;
    do { done = waitpid(child, &status, 0); } while (done < 0 && errno == EINTR);
    int error = 0; ssize_t bytes;
    do { bytes = read(execution[0], &error, sizeof(error)); } while (bytes < 0 && errno == EINTR);
    if (!source_close_fd(&execution[0])) joined = false;
    if (diagnosis) *diagnosis = cliq_source_helper_failure(joined && done == child, status, bytes, error);
    return joined && done == child && bytes == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool source_run_helper(int raw_config, int intent, int exclude, const struct cliq_source_config *config) {
    return fixed_git_run_helper(raw_config, intent, exclude, config, false, NULL);
}
#include "source-git-output.h"

static bool source_output_files(const struct cliq_worker_packet *request, uint64_t reserve,
    int outputs[CLIQ_SOURCE_OUTPUTS], struct cliq_worker_packet *result, uint32_t *failure) {
    source_output_stage(failure, CLIQ_SOURCE_OUTPUT_DIRECTORY);
    int directory = open("/scratch/output", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return false;
    uint64_t copy_capacity = 0, quota = 0;
    bool valid = source_output_inventory(directory, request, &copy_capacity, failure);
    /* Helper/Git have actually joined. Reserve all simultaneous immutable
     * copies before touching their first page, within the same scratch cap. */
    if (valid) {
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_RESERVE);
        valid = reserve < request->max_generation_bytes && copy_capacity < request->max_generation_bytes - reserve;
    }
    if (valid) {
        quota = request->max_generation_bytes - reserve - copy_capacity;
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_REMOUNT);
        valid = source_scratch_limit(quota);
    }
    struct statvfs filesystem;
    if (valid) {
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_FILESYSTEM);
        valid = fstatvfs(directory, &filesystem) == 0 && filesystem.f_frsize > 0;
    }
    if (valid) {
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_USED);
        valid = filesystem.f_bfree <= filesystem.f_blocks && filesystem.f_blocks - filesystem.f_bfree <= quota / filesystem.f_frsize;
    }
    if (valid) valid = source_output_copy(directory, request, outputs, result, failure);
    if (!source_close_fd(&directory)) { source_output_stage(failure, CLIQ_SOURCE_OUTPUT_DIRECTORY_CLOSE); valid = false; }
    if (!valid) for (unsigned int i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) if (!source_close_fd(&outputs[i]))
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_RETIREMENT);
    if (valid) source_output_stage(failure, 0);
    return valid;
}
static bool source_rule_result(int rule, uint64_t expected, struct cliq_worker_packet *result) {
    if (rule < 0) return expected == 0;
    struct stat before, after; struct sha256_context hash; sha256_init(&hash);
    bool valid = result->source_exclude_grant_digest[0] && fstat(rule, &before) == 0 && S_ISREG(before.st_mode) && before.st_nlink == 0 &&
        before.st_size >= 0 && (uint64_t)before.st_size == expected && expected <= result->max_file_bytes && expected <= result->max_output_bytes &&
        fcntl(rule, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    unsigned char buffer[65536]; uint64_t offset = 0;
    while (valid && offset < expected) {
        size_t wanted = expected - offset < sizeof(buffer) ? (size_t)(expected - offset) : sizeof(buffer);
        ssize_t count = pread(rule, buffer, wanted, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = false; break; }
        sha256_update(&hash, buffer, (size_t)count); offset += (uint64_t)count;
    }
    unsigned char digest[32], extra; ssize_t eof = -1;
    if (valid) do { eof = pread(rule, &extra, 1, (off_t)offset); } while (eof < 0 && errno == EINTR);
    sha256_final(&hash, digest); memset(buffer, 0, sizeof(buffer));
    valid = valid && eof == 0 && fstat(rule, &after) == 0 && source_stat_same(&before, &after);
    if (valid) { result->source_rule_present = 1; result->source_rule_bytes = expected; source_hex(digest, result->source_rule_digest); }
    return valid;
}
static int source_producer(void) {
    if (getpid() != 2 || getppid() != 1 || !close_above_channel() || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) return 70;
    struct cliq_worker_packet request; int files[3] = {-1, -1, -1}, raw_rule = -1; size_t count;
    if (!cliq_receive(3, &request, files, 3, &count) || request.command != CLIQ_SOURCE_CREATE_BLOCKED || count != 3 ||
        !cliq_source_request_valid(&request)) return 70;
    struct cliq_source_config *config = calloc(1, sizeof(*config));
    bool valid = config && source_read_config(files[0], config) && source_bound_logs(&request) && source_initial_storage_current(config, &request);
    if (!source_close_fd(&files[0])) valid = false;
    struct stat root, git, named;
    uint64_t runtime_budget = 0, storage_reserve = 0;
    valid = valid && cliq_source_storage_reserve(config, &request, &runtime_budget, &storage_reserve) &&
        source_script_current(config) && fstat(files[1], &root) == 0 && S_ISDIR(root.st_mode) && root.st_uid == geteuid() &&
        fstat(files[2], &git) == 0 && S_ISDIR(git.st_mode) && git.st_uid == geteuid() && root.st_dev == git.st_dev &&
        fstatat(files[1], ".git", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_stat_same(&git, &named);
    struct cliq_worker_packet ready = request; ready.command = CLIQ_WORKER_READY;
    struct stat namespace;
    ready.pid = getpid(); ready.namespace_init_pid = 1;
    valid = valid && cliq_process_token(2, ready.start_token) && cliq_process_token(1, ready.init_start_token) &&
        stat("/proc/self/ns/pid", &namespace) == 0;
    ready.pid_namespace_inode = valid ? (uint64_t)namespace.st_ino : 0;
    if (!valid || !cliq_send(3, &ready, NULL, 0)) goto failed;
    struct cliq_worker_packet release;
    if (!cliq_receive(3, &release, NULL, 0, &count) || release.command != CLIQ_SOURCE_RELEASE_CAPTURE ||
        !cliq_fixed_git_same_prepared(&request, &release)) goto failed;
    struct cliq_source_snapshot snapshot;
    source_snapshot_init(&snapshot, &request);
    valid = source_capture_snapshot(files[2], &request, &snapshot, storage_reserve) && fstat(files[1], &named) == 0 && source_stat_same(&root, &named) &&
        fstatat(files[1], ".git", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_stat_same(&git, &named);
    if (!source_close_fd(&files[1])) valid = false;
    if (!source_close_fd(&files[2])) valid = false;
    if (!valid) { source_snapshot_close(&snapshot); goto failed; }
    struct cliq_worker_packet sealed = request; sealed.command = CLIQ_SOURCE_SEALED;
    source_hex(snapshot.digest, sealed.source_snapshot_digest);
    sealed.source_byte_count = snapshot.bytes; sealed.source_entry_count = snapshot.entries; sealed.source_shard_count = snapshot.count;
    if (!cliq_send(3, &sealed, NULL, 0)) { source_snapshot_close(&snapshot); goto failed; }
    struct cliq_worker_packet continuation;
    if (!cliq_receive(3, &continuation, NULL, 0, &count) || continuation.command != CLIQ_SOURCE_CONTINUE_GIT ||
        !cliq_fixed_git_same_prepared(&request, &continuation) || strcmp(continuation.source_snapshot_digest, sealed.source_snapshot_digest) != 0) {
        source_snapshot_close(&snapshot); goto failed;
    }
    uint64_t allocation = 0;
    for (uint32_t i = 0; i < snapshot.count; i++)
        if (!source_add_u64(&allocation, (snapshot.shard_bytes[i] + 4095) & ~UINT64_C(4095), request.max_generation_bytes)) valid = false;
    int raw_config = -1, intent = -1, input = -1;
    if (snapshot.rule_present && !cliq_source_page_add(&storage_reserve, snapshot.rule_bytes, request.max_generation_bytes)) valid = false;
    valid = valid && storage_reserve < request.max_generation_bytes && allocation < request.max_generation_bytes - storage_reserve &&
        source_scratch_limit(request.max_generation_bytes - storage_reserve - allocation) &&
        mkdir("/scratch/input", 0700) == 0 && mkdir("/scratch/input/.git", 0700) == 0 &&
        mkdir("/scratch/tmp", 0700) == 0 && mkdir("/scratch/home", 0700) == 0;
    input = valid ? open("/scratch/input/.git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    valid = valid && input >= 0 && source_materialize_snapshot(&snapshot, input, &raw_config, &raw_rule);
    if (!source_close_fd(&input)) valid = false;
    if (!source_snapshot_close(&snapshot)) valid = false;
    intent = valid ? source_intent(&request, config) : -1;
    valid = valid && intent >= 0 && source_scratch_limit(request.max_generation_bytes - storage_reserve);
    if (!valid) { source_close_fd(&raw_config); source_close_fd(&intent); goto failed; }
    valid = source_run_helper(raw_config, intent, raw_rule, config);
    raw_config = intent = -1;
    int outputs[CLIQ_SOURCE_TRANSFER_OUTPUTS] = {-1, -1, -1, -1, -1};
    struct cliq_worker_packet result = sealed; result.command = CLIQ_SOURCE_RESULT;
    if (!valid || !source_rule_result(raw_rule, snapshot.rule_bytes, &result) ||
        !source_output_files(&request, storage_reserve, outputs, &result, NULL)) goto failed;
    outputs[4] = raw_rule; raw_rule = -1;
    valid = cliq_send(3, &result, outputs, CLIQ_SOURCE_OUTPUTS + result.source_rule_present);
    for (unsigned int i = 0; i < CLIQ_SOURCE_TRANSFER_OUTPUTS; i++) if (!source_close_fd(&outputs[i])) valid = false;
    free(config); return valid ? 0 : 70;
failed:
    for (size_t i = 0; i < 3; i++) source_close_fd(&files[i]);
    source_close_fd(&raw_rule);
    free(config); return 70;
}

#include "preparation-git-producer.h"

/* PID1 never interprets payload or writes a growing parent memfd. It closes
 * all original host copies after forwarding them to the native producer. */
static int source_namespace(struct cliq_worker_packet request, int passed[3]) {
    const bool preparation = request.preparation_input_intent_ref[0] != '\0';
    const size_t passed_count = preparation ? 2 : 3;
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) return 70;
    pid_t child = fork();
    if (child < 0) { close(channel[0]); close(channel[1]); return 70; }
    if (child == 0) {
        close(channel[0]);
        if (dup2(channel[1], 3) < 0 || !close_above_channel()) _exit(70);
        char *const argv[] = { "/runtime/cliq-linux-worker-init", preparation ? "--preparation-producer" : "--source-producer", NULL };
        char *const environment[] = { "LANG=C", "LC_ALL=C", NULL };
        execve(argv[0], argv, environment); _exit(70);
    }
    close(channel[1]);
    bool valid = cliq_send(channel[0], &request, passed, passed_count);
    for (size_t i = 0; i < passed_count; i++) if (!source_close_fd(&passed[i])) valid = false;
    bool released = false, continued = false, result = false;
    while (valid) {
        struct pollfd fds[2] = { { .fd = 3, .events = POLLIN }, { .fd = channel[0], .events = POLLIN } };
        int ready; do { ready = poll(fds, 2, -1); } while (ready < 0 && errno == EINTR);
        if (ready < 0) break;
        if (fds[0].revents) {
            struct cliq_worker_packet command; size_t count;
            if (!(fds[0].revents & POLLIN) || !cliq_receive(3, &command, NULL, 0, &count) || !cliq_fixed_git_namespace_same_prepared(&request, &command)) break;
            if (command.command == CLIQ_SOURCE_RELEASE_CAPTURE && !released) released = true;
            else if (command.command == CLIQ_SOURCE_CONTINUE_GIT && released && !continued) continued = true;
            else break;
            if (!cliq_send(channel[0], &command, NULL, 0)) break;
        }
        if (fds[1].revents) {
            struct cliq_worker_packet response; int outputs[CLIQ_SOURCE_TRANSFER_OUTPUTS] = {-1, -1, -1, -1, -1}; size_t count;
            if (!(fds[1].revents & POLLIN) || !cliq_receive(channel[0], &response, outputs, CLIQ_SOURCE_TRANSFER_OUTPUTS, &count) ||
                !cliq_fixed_git_namespace_same_prepared(&request, &response)) break;
            uint64_t original_uid = 0;
            if (preparation && released && !result && preparation_namespace_origin_uid(&original_uid) &&
                cliq_preparation_failure_packet_for_uid(&request, &response, count, original_uid)) {
                // Keep this a failure: join the real original exit70, then
                // forward only its exact zero-FD diagnosis on the same channel.
                valid = cliq_preparation_forward_joined_failure(child, &channel[0], 3, &request, &response, count, original_uid);
                break;
            }
            valid = response.status == 0 && !result && ((response.command == CLIQ_WORKER_READY && !released && count == 0) ||
                (response.command == CLIQ_SOURCE_SEALED && released && !continued && count == 0) ||
                (response.command == CLIQ_SOURCE_RESULT && continued && cliq_source_rule_result_valid(&response) &&
                    count == CLIQ_SOURCE_OUTPUTS + response.source_rule_present));
            if (response.command == CLIQ_SOURCE_RESULT && valid) {
                int status; pid_t joined; do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
                valid = joined == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
                if (!source_close_fd(&channel[0])) valid = false;
            }
            if (valid) valid = cliq_send(3, &response, count ? outputs : NULL, count);
            for (size_t i = 0; i < count; i++) if (!source_close_fd(&outputs[i])) valid = false;
            if (response.command == CLIQ_SOURCE_RESULT) { result = valid; break; }
        }
    }
    if (!source_close_fd(&channel[0])) valid = false;
    kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) { errno = 0; }
    return valid && result ? 0 : 70;
}
#endif
