#ifndef CLIQ_PREPARATION_GIT_PRODUCER_H
#define CLIQ_PREPARATION_GIT_PRODUCER_H

#include "preparation-git-capture.h"
#include "source-ready-diagnostic.h"

static bool preparation_materialize_files(struct cliq_preparation_capture *input) {
    const char *names[] = { NULL, "canonical.index", "reachable.pack", "reachable.idx" };
    int root = open("/scratch/input", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return false;
    bool valid = true; unsigned char bytes[65536];
    for (size_t role = 1; valid && role < CLIQ_PREPARATION_INPUT_FILES; role++) {
        struct stat sealed, before, after, named;
        valid = fstat(input->files[role], &sealed) == 0 && S_ISREG(sealed.st_mode) && sealed.st_nlink == 0 &&
            sealed.st_size >= 0 && (uint64_t)sealed.st_size == input->bytes[role] &&
            (fcntl(input->files[role], F_GETFL) & O_ACCMODE) == O_RDONLY &&
            fcntl(input->files[role], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
        int target = valid ? openat(root, names[role], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
        valid = valid && target >= 0 && fstat(target, &before) == 0 && S_ISREG(before.st_mode) && before.st_nlink == 1 &&
            before.st_uid == geteuid() && (before.st_mode & 07777) == 0600 && before.st_size == 0;
        struct sha256_context hash; sha256_init(&hash); uint64_t offset = 0;
        while (valid && offset < input->bytes[role]) {
            size_t wanted = input->bytes[role] - offset < sizeof(bytes) ? (size_t)(input->bytes[role] - offset) : sizeof(bytes);
            ssize_t read_bytes = pread(input->files[role], bytes, wanted, (off_t)offset);
            if (read_bytes < 0 && errno == EINTR) continue;
            if (read_bytes <= 0 || !source_write_all(target, bytes, (size_t)read_bytes)) { valid = false; break; }
            sha256_update(&hash, bytes, (size_t)read_bytes); offset += (uint64_t)read_bytes;
        }
        unsigned char extra, digest[32]; char text[65]; sha256_final(&hash, digest); preparation_capture_hex(digest, text);
        valid = valid && offset == input->bytes[role] && strcmp(text, input->digests[role]) == 0 &&
            pread(input->files[role], &extra, 1, (off_t)offset) == 0 && fstat(target, &after) == 0 &&
            after.st_dev == before.st_dev && after.st_ino == before.st_ino && after.st_uid == before.st_uid && after.st_gid == before.st_gid &&
            after.st_mode == before.st_mode && after.st_nlink == 1 && after.st_size == (off_t)offset &&
            fstatat(root, names[role], &named, AT_SYMLINK_NOFOLLOW) == 0 && source_stat_same(&after, &named);
        if (!source_close_fd(&target)) valid = false;
        if (!source_close_fd(&input->files[role])) valid = false;
    }
    if (!source_close_fd(&root)) valid = false;
    return valid;
}
static int preparation_producer(void) {
    if (getpid() != 2 || getppid() != 1 || !close_above_channel() || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) return 70;
    struct cliq_worker_packet request; int files[2] = { -1, -1 }, intent = -1, outputs[CLIQ_SOURCE_OUTPUTS] = { -1, -1, -1, -1 }; size_t count;
    struct cliq_preparation_capture input; preparation_capture_init(&input);
    struct cliq_source_config *config = calloc(1, sizeof(*config)); bool valid = false;
    uint32_t diagnostic_stage = 0;
    if (!config || !cliq_receive(3, &request, files, 2, &count)) goto failed;
    diagnostic_stage = 2;
    if (request.command != CLIQ_SOURCE_CREATE_BLOCKED || count != 2) goto failed;
    diagnostic_stage = 3;
    if (!cliq_preparation_namespace_request_valid(&request)) goto failed;
    uint64_t runtime = 0, reserve = 0;
    diagnostic_stage = 4; if (!source_read_config(files[0], config)) goto failed;
    diagnostic_stage = 5; if (!source_bound_logs(&request)) goto failed;
    diagnostic_stage = 6; if (!source_script_current(config)) goto failed;
    diagnostic_stage = 7; if (!cliq_source_storage_reserve(config, &request, &runtime, &reserve)) goto failed;
    diagnostic_stage = 8;
    valid = source_close_fd(&files[0]);
    struct cliq_worker_packet ready = request; ready.command = CLIQ_WORKER_READY; ready.pid = getpid(); ready.namespace_init_pid = 1;
    struct stat namespace;
    valid = valid && cliq_process_token(2, ready.start_token) && cliq_process_token(1, ready.init_start_token) && stat("/proc/self/ns/pid", &namespace) == 0;
    ready.pid_namespace_inode = valid ? (uint64_t)namespace.st_ino : 0;
    if (!valid) goto failed;
    diagnostic_stage = 9;
    source_ready_diagnostic_write(2, &request, diagnostic_stage);
    if (!cliq_send(3, &ready, NULL, 0)) goto failed;
    diagnostic_stage = 0; /* No payload/helper failure is eligible for this pre-READY marker. */
    struct cliq_worker_packet release;
    if (!cliq_receive(3, &release, NULL, 0, &count) || release.command != CLIQ_SOURCE_RELEASE_CAPTURE ||
        !cliq_preparation_namespace_same_attempt(&request, &release) ||
        !preparation_capture_input(files[1], &request, request.preparation_input_intent_ref, reserve, &input)) goto failed;
    if (!source_close_fd(&files[1])) goto failed;
    struct cliq_worker_packet sealed = request; sealed.command = CLIQ_SOURCE_SEALED;
    preparation_capture_hex(input.digest, sealed.source_snapshot_digest);
    sealed.source_byte_count = input.total; sealed.source_entry_count = CLIQ_PREPARATION_INPUT_FILES; sealed.source_shard_count = CLIQ_PREPARATION_INPUT_FILES;
    if (!cliq_send(3, &sealed, NULL, 0)) goto failed;
    struct cliq_worker_packet continuation;
    if (!cliq_receive(3, &continuation, NULL, 0, &count) || continuation.command != CLIQ_SOURCE_CONTINUE_GIT ||
        !cliq_preparation_namespace_same_attempt(&request, &continuation) || strcmp(continuation.source_snapshot_digest, sealed.source_snapshot_digest) != 0) goto failed;
    /* Both the original sealed bytes and their private nlink-one copies fit
     * the unchanged envelope before any helper executes. No memfd mount can
     * bypass the measured helper's ordinary-file guard. */
    if (reserve >= request.max_generation_bytes || input.pages > (request.max_generation_bytes - reserve) / 2 ||
        !source_scratch_limit(request.max_generation_bytes - reserve - input.pages) || mkdir("/scratch/input", 0700) != 0 ||
        mkdir("/scratch/tmp", 0700) != 0 || mkdir("/scratch/home", 0700) != 0 || !preparation_materialize_files(&input)) goto failed;
    uint64_t metadata_pages = 0;
    if (!cliq_source_page_add(&metadata_pages, input.bytes[0], request.max_generation_bytes) || reserve >= request.max_generation_bytes - metadata_pages ||
        !source_scratch_limit(request.max_generation_bytes - reserve - metadata_pages)) goto failed;
    intent = fixed_git_intent(&request, config, true);
    if (intent < 0) goto failed;
    valid = fixed_git_run_helper(input.files[0], intent, -1, config, true);
    input.files[0] = intent = -1;
    struct cliq_worker_packet result = sealed; result.command = CLIQ_SOURCE_RESULT;
    /* Actual fixed-helper close/join releases its metadata pages before the
     * original bounded output copy phase, never before an assumed JS close. */
    if (!valid || !source_output_files(&request, reserve, outputs, &result)) goto failed;
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) if (result.source_output_bytes[i] != input.bytes[i] ||
        strcmp(result.source_output_digests[i], input.digests[i]) != 0) goto failed;
    valid = cliq_send(3, &result, outputs, CLIQ_SOURCE_OUTPUTS);
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) if (!source_close_fd(&outputs[i])) valid = false;
    if (!preparation_capture_close(&input)) valid = false;
    free(config); return valid ? 0 : 70;
failed:
    if (diagnostic_stage) source_ready_diagnostic_write(2, &request, diagnostic_stage);
    for (size_t i = 0; i < 2; i++) source_close_fd(&files[i]);
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS; i++) source_close_fd(&outputs[i]);
    source_close_fd(&intent); preparation_capture_close(&input); free(config); return 70;
}
#endif
