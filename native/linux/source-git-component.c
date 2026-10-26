/* Real Linux FD/memfd/data components. No cgroup, SourceInspectionAttempt,
 * StateOwner, launch permission or installed/native qualification is minted. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "source-git-materialize.h"
#include "source-git-history.h"
#include "preparation-git-capture.h"
#include <sys/resource.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/inotify.h>
#include <sys/wait.h>

static unsigned int checks;
static void check(bool accepted, const char *name) {
    checks++;
    if (!accepted) { fprintf(stderr, "source component failed: %s\n", name); exit(1); }
}
static void fixed_digest(char output[65], char value) { memset(output, value, 64); output[64] = '\0'; }
static struct cliq_worker_packet request_data(void) {
    struct cliq_worker_packet request = cliq_packet(CLIQ_SOURCE_RESERVE); request.scope = 1;
    memset(request.source_inspection_id, 'i', 43); request.source_inspection_id[43] = '\0';
    fixed_digest(request.nonce, 'a'); fixed_digest(request.activation_nonce, 'b');
    fixed_digest(request.source_target_ref, 'c'); fixed_digest(request.source_input_intent_ref, 'd');
    request.max_processes = 32; request.memory_bytes = UINT64_C(268435456); request.cpu_quota = 1000000;
    request.max_open_files = 64; request.max_file_bytes = 1048576; request.max_generation_bytes = 268435456; request.max_output_bytes = 65536;
    return request;
}
static int directory_at(int root, const char *name) {
    check(mkdirat(root, name, 0700) == 0, "private directory create");
    int result = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    check(result >= 0, "private directory open"); return result;
}
static void file_at(int root, const char *name, const void *bytes, size_t count) {
    int file = openat(root, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    check(file >= 0 && source_write_all(file, bytes, count), "private fixture full write");
    check(source_close_fd(&file), "private fixture close");
}
static size_t descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd"); check(directory != NULL, "actual descriptor observation");
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    check(closedir(directory) == 0, "actual descriptor observation close"); return count;
}
static void expect_content(int root, const char *name, const void *bytes, size_t length) {
    int fd = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    check(fd >= 0, "materialized file open"); unsigned char buffer[65536]; size_t read_bytes = 0;
    while (read_bytes < length) {
        size_t wanted = length - read_bytes < sizeof(buffer) ? length - read_bytes : sizeof(buffer);
        ssize_t count = read(fd, buffer, wanted);
        check(count > 0 && memcmp(buffer, (const unsigned char *)bytes + read_bytes, (size_t)count) == 0, "materialized immutable full bytes");
        read_bytes += (size_t)count;
    }
    check(read(fd, buffer, 1) == 0 && source_close_fd(&fd), "materialized full EOF and close");
}
static void unlink_fixture(int root, const char *name, bool directory) {
    check(unlinkat(root, name, directory ? AT_REMOVEDIR : 0) == 0, "explicit fixture cleanup");
}
static void append_data_birth(int fd, struct cliq_source_birth_record *record, const unsigned char previous[32]) {
    memcpy(record->previous, previous, 32); struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)record, offsetof(struct cliq_source_birth_record, digest)); sha256_final(&hash, record->digest);
    check(lseek(fd, 0, SEEK_END) >= 0 && source_write_all(fd, record, sizeof(*record)) && fsync(fd) == 0, "ordinary data birth append and sync");
}
static bool child_can_read_parent_fd(int descriptor) {
    pid_t parent = getpid(), child = fork();
    check(child >= 0, "actual fixed proc-isolation child birth");
    if (child == 0) {
        if (close(descriptor) != 0) _exit(3);
        char name[96]; snprintf(name, sizeof(name), "/proc/%ld/fd/%d", (long)parent, descriptor);
        int found = open(name, O_RDONLY | O_CLOEXEC);
        if (found >= 0) { if (close(found) != 0) _exit(3); _exit(0); }
        _exit(errno == EACCES || errno == EPERM ? 1 : 3);
    }
    int status; pid_t joined; do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
    check(joined == child && WIFEXITED(status) && WEXITSTATUS(status) <= 1, "actual fixed proc-isolation child close and join");
    return WEXITSTATUS(status) == 0;
}
static const char *const preparation_payloads[] = { "{}", "index", "pack", "packIndex" };
static const char *const preparation_digests[] = {
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "1bc04b5291c26a46d918139138b992d2de976d6851d0893b0476b85bfbdfc6e6",
    "4862f447f2c7f272fa2f4aaf89dadb3b1ac09105bd5864f8d1a0c9452bb0a226",
    "9bc2576e7b05a07618c41cff57b3bc5e3d9478dc90edeb36bee68197d08c8698"
};
static bool send_preparation_data(int socket, const struct cliq_preparation_input_message_data *data, const void *payload, int extra_fd) {
    unsigned char header[CLIQ_PREPARATION_INPUT_HEADER]; preparation_stream_encode(header, data);
    struct iovec values[2] = { { .iov_base = header, .iov_len = sizeof(header) }, { .iov_base = (void *)payload, .iov_len = data->length } };
    char rights[CMSG_SPACE(sizeof(int))]; memset(rights, 0, sizeof(rights));
    struct msghdr message = { .msg_iov = values, .msg_iovlen = data->length ? 2 : 1 };
    if (extra_fd >= 0) { message.msg_control = rights; message.msg_controllen = sizeof(rights); struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
        entry->cmsg_level = SOL_SOCKET; entry->cmsg_type = SCM_RIGHTS; entry->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(entry), &extra_fd, sizeof(extra_fd)); }
    ssize_t sent; do { sent = sendmsg(socket, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)(CLIQ_PREPARATION_INPUT_HEADER + data->length);
}
static void preparation_stream_component(const struct cliq_worker_packet *request) {
    for (unsigned int mutation = 0; mutation < 8; mutation++) {
        size_t baseline = descriptor_count(); int channel[2];
        check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) == 0, "actual owned preparation data channel");
        pid_t child = fork(); check(child >= 0, "actual fixed input-writer child component birth");
        if (child == 0) {
            if (!source_close_fd(&channel[0])) _exit(2);
            size_t before = descriptor_count(); struct cliq_preparation_capture input;
            bool accepted = preparation_capture_input(channel[1], request, preparation_digests[0], 0, &input);
            bool valid = accepted == (mutation == 0);
            if (accepted) {
                valid = valid && input.total == 20 && input.pages == 4 * 4096;
                for (size_t role = 0; role < 4; role++) {
                    struct stat file; unsigned char bytes[32]; size_t count = strlen(preparation_payloads[role]);
                    valid = valid && fstat(input.files[role], &file) == 0 && file.st_nlink == 0 && file.st_size == (off_t)count &&
                        (fcntl(input.files[role], F_GETFL) & O_ACCMODE) == O_RDONLY &&
                        fcntl(input.files[role], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
                        pread(input.files[role], bytes, count, 0) == (ssize_t)count && memcmp(bytes, preparation_payloads[role], count) == 0 &&
                        pwrite(input.files[role], "x", 1, 0) < 0 && ftruncate(input.files[role], 0) < 0;
                }
            }
            if (!preparation_capture_close(&input) || descriptor_count() != before || !source_close_fd(&channel[1])) valid = false;
            _exit(valid ? 0 : 2);
        }
        check(source_close_fd(&channel[1]), "parent drops original input-reader alias before writing");
        bool writing = true;
        for (uint32_t role = 0; writing && role < 4; role++) {
            struct cliq_preparation_input_message_data data = { .kind = CLIQ_PREPARATION_DECLARE, .role = role, .byte_count = strlen(preparation_payloads[role]) };
            strcpy(data.digest, preparation_digests[role]);
            if (mutation == 1 && role == 2) data.digest[0] = '0';
            if (mutation == 2 && role == 1) data.byte_count++;
            if (mutation == 3 && role == 1) data.role = 2;
            if (mutation == 4 && role == 0) data.digest[0] = '0';
            if (mutation == 7 && role == 2) data.byte_count = request->max_file_bytes + 1;
            int extra = mutation == 6 && role == 0 ? memfd_create("cliq-component-rejected-extra", MFD_CLOEXEC) : -1;
            writing = send_preparation_data(channel[0], &data, NULL, extra);
            if (!source_close_fd(&extra)) writing = false;
            data = (struct cliq_preparation_input_message_data){ .kind = CLIQ_PREPARATION_CHUNK, .role = role, .length = (uint32_t)strlen(preparation_payloads[role]) };
            if (writing) writing = send_preparation_data(channel[0], &data, preparation_payloads[role], -1);
            data = (struct cliq_preparation_input_message_data){ .kind = CLIQ_PREPARATION_END, .role = role };
            if (writing) writing = send_preparation_data(channel[0], &data, NULL, -1);
        }
        struct cliq_preparation_input_message_data complete = { .kind = CLIQ_PREPARATION_INPUT_COMPLETE, .role = 4 };
        if (writing) writing = send_preparation_data(channel[0], &complete, NULL, -1);
        if (writing && mutation == 5) (void)send_preparation_data(channel[0], &complete, NULL, -1);
        check(source_close_fd(&channel[0]), "original data producer writer joins and supplies actual EOF");
        int status; pid_t joined; do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
        check(joined == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "actual CAS-only capture child joins with exact acceptance or closed refusal");
        check(descriptor_count() == baseline, "all failed/successful input scopes close every actual descriptor");
    }
}
/* Ordinary bounded raw datasets exercise the exact historical parser;
 * these changed copies are never written back as original birth evidence. */
static void history_wire_versions(const unsigned char *snapshot, size_t length, const struct cliq_source_birth *header) {
    const size_t prefix = sizeof(struct cliq_source_birth) + sizeof(struct cliq_source_controller_birth);
    check(length > prefix && (length - prefix) % sizeof(struct cliq_source_birth_record) == 0,
        "original complete data chain before wire-version regressions");
    unsigned char *changed = malloc(length); check(changed != NULL, "bounded historical data copy");
    unsigned char original_digest[32], unchanged_digest[32]; struct sha256_context hash;
    sha256_init(&hash); sha256_update(&hash, snapshot, length); sha256_final(&hash, original_digest);
    for (unsigned int variant = 0; variant < 5; variant++) {
        memcpy(changed, snapshot, length);
        struct cliq_source_controller_birth creator; memcpy(&creator, changed + sizeof(*header), sizeof(creator));
        unsigned char previous[32]; memcpy(previous, creator.digest, sizeof(previous));
        for (size_t offset = prefix, index = 0; offset < length; offset += sizeof(struct cliq_source_birth_record), index++) {
            struct cliq_source_birth_record record; memcpy(&record, changed + offset, sizeof(record));
            record.packet.version = variant == 0 ? 6 : variant == 1 ? 7 : variant == 2 ? (index == 0 ? 6 : 7) : variant == 3 ? 5 : 7;
            if (variant == 4 && index == 0) record.packet.command = CLIQ_ACK_BUILTIN_RESULT;
            memcpy(record.previous, previous, sizeof(previous));
            sha256_init(&hash); sha256_update(&hash, (const unsigned char *)&record, offsetof(struct cliq_source_birth_record, digest));
            sha256_final(&hash, record.digest); memcpy(previous, record.digest, sizeof(previous)); memcpy(changed + offset, &record, sizeof(record));
        }
        struct cliq_source_history decoded;
        bool accepted = cliq_source_history_decode(changed, length, header, &decoded);
        check(accepted == (variant < 2), "original wire6 and wire7 data pass; fully rehashed mixed/unknown/builtin chains refuse");
        if (accepted) check(decoded.first.version == (variant == 0 ? 6U : 7U) && decoded.last.version == decoded.first.version && decoded.kind == 12,
            "accepted history preserves original raw version and complete original closure");
        sha256_init(&hash); sha256_update(&hash, snapshot, length); sha256_final(&hash, unchanged_digest);
        check(memcmp(original_digest, unchanged_digest, sizeof(original_digest)) == 0, "historical source bytes remain unchanged for every parse");
    }
    free(changed);
}
int main(void) {
    struct cliq_worker_packet request = request_data(), changed = request;
    check(cliq_source_request_valid(&request) && strcmp(request.nonce, request.activation_nonce) != 0, "distinct staging and launch nonces");
    check(cliq_source_same_attempt(&request, &changed), "same exact source attempt");
    changed.activation_nonce[0] = 'e'; check(!cliq_source_same_attempt(&request, &changed), "changed launch nonce rejected");
    changed = request; changed.nonce[0] = 'f'; check(!cliq_source_same_attempt(&request, &changed), "changed staging nonce rejected");
    preparation_stream_component(&request);
    /* Ordinary closed frame data, not a cgroup/Owner/native launch proof. */
    struct cliq_source_birth header = { .owner_uid = geteuid() };
    struct cliq_source_controller_birth creator = { .magic = CLIQ_SOURCE_CONTROLLER_MAGIC, .version = 1, .pid = getpid() };
    creator.root = creator.parent = creator.leaf = (struct cliq_source_directory_identity){ .device = 1, .inode = 1,
        .uid = geteuid(), .gid = getegid(), .mode = S_IFDIR | 0700 };
    strcpy(creator.leaf_name, "controller-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    check(cliq_process_token(getpid(), creator.process_start_token), "actual component process token sample");
    struct sha256_context creator_hash; sha256_init(&creator_hash);
    sha256_update(&creator_hash, (const unsigned char *)&creator, offsetof(struct cliq_source_controller_birth, digest)); sha256_final(&creator_hash, creator.digest);
    check(cliq_source_controller_frame_valid(&creator, &header), "closed exact controller birth frame data");
    struct cliq_source_controller_birth wrong_creator = creator; wrong_creator.leaf_name[11] = 'z';
    check(!cliq_source_controller_frame_valid(&wrong_creator, &header), "changed controller identity data rejected");
    wrong_creator = creator; wrong_creator.source_header_digest[0] = 1;
    check(!cliq_source_controller_frame_valid(&wrong_creator, &header), "foreign source birth chain rejected");
    struct cliq_source_config config = { .magic = CLIQ_SOURCE_CONFIG_MAGIC, .version = 1, .file_count = 2, .init_bytes = 4096, .inspector_bytes = 1024 };
    fixed_digest(config.inspector_digest, 'a'); fixed_digest(config.repository_identity_digest, 'b');
    char intent_json[4096];
    const char expected_intent[] = "{\"recipe\":\"cliq-source-git-inspection-v1\",\"repositoryIdentityDigest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"resources\":{\"cpuQuotaMicrosPerSecond\":1000000,\"maxGenerationBytes\":268435456,\"maxInvocationOutputBytes\":65536,\"maxIpcFrameBytes\":16777216,\"maxOpenFiles\":64,\"maxProcesses\":32,\"maxQueuedIpcBytes\":67108864,\"maxSingleFileBytes\":1048576,\"memoryBytes\":268435456},\"schemaVersion\":1}";
    check(cliq_fixed_git_intent_json(intent_json, sizeof(intent_json), &request, &config, false) == (int)strlen(expected_intent) &&
        strcmp(intent_json, expected_intent) == 0, "actual native fixed intent must equal independently worked canonical JSON bytes");
    strcpy(config.files[0].path, "/usr/bin/node"); strcpy(config.files[1].path, "/usr/bin/git");
    for (size_t i = 0; i < 2; i++) { config.files[i].byte_count = 8192; fixed_digest(config.files[i].digest, 'c'); }
    uint64_t root_budget = 0, reserve = 0;
    check(cliq_source_storage_reserve(&config, &request, &root_budget, &reserve) && reserve > root_budget + 2 * request.max_output_bytes,
        "combined runtime logs raw-config and intent original capacity");
    check(root_budget == UINT64_C(1048576) + 4 * 4096 + 4096 + 4096 + 2 * 8192,
        "the original four signed-profile directory inodes are reserved inside the existing quota");
    check(!cliq_source_page_add(&reserve, UINT64_MAX, UINT64_MAX), "page overflow rejected");
    struct cliq_worker_packet small = request; small.max_generation_bytes = root_budget;
    check(!cliq_source_storage_reserve(&config, &small, &root_budget, &reserve), "no capacity expansion on insufficient original budget");

#ifndef CLIQ_SOURCE_COMPONENT_DIRECTORY
#define CLIQ_SOURCE_COMPONENT_DIRECTORY "/output"
#endif
    char locator[] = CLIQ_SOURCE_COMPONENT_DIRECTORY "/source-git-component.XXXXXX";
    check(mkdtemp(locator) != NULL, "owned component root");
    int root = open(locator, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); check(root >= 0, "owned component root held");
    /* A real bounded file exercises the production history decoder. These
     * ordinary metadata values do not represent a real cgroup or authority. */
    int birth = openat(root, "data-birth", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    check(birth >= 0, "ordinary birth data file open");
    struct stat original_birth;
    check(fstat(birth, &original_birth) == 0, "actual original data birth descriptor identity");
    header.magic = CLIQ_SOURCE_BIRTH_MAGIC; header.version = CLIQ_SOURCE_BIRTH_VERSION;
    header.staging_device = header.staging_inode = header.workspace_device = header.workspace_inode = header.git_device = header.git_inode = 1;
    header.staging_gid = getegid();
    header.state_root = header.runtime = header.source_parent = creator.root;
    header.birth_device = header.staging_device = header.state_root.device = header.runtime.device = header.source_parent.device = original_birth.st_dev;
    header.birth_inode = original_birth.st_ino;
    header.supervisor_pid = getpid();
    memcpy(header.supervisor_start_token, creator.process_start_token, strlen(creator.process_start_token) + 1);
    memcpy(header.inspection_id, request.source_inspection_id, sizeof(header.inspection_id));
    memcpy(header.staging_nonce, request.nonce, sizeof(header.staging_nonce));
    memcpy(header.target_ref, request.source_target_ref, sizeof(header.target_ref));
    memcpy(header.input_intent_ref, request.source_input_intent_ref, sizeof(header.input_intent_ref));
    sha256_init(&creator_hash); sha256_update(&creator_hash, (const unsigned char *)&header, offsetof(struct cliq_source_birth, digest)); sha256_final(&creator_hash, header.digest);
    memcpy(creator.source_header_digest, header.digest, 32); sha256_init(&creator_hash);
    sha256_update(&creator_hash, (const unsigned char *)&creator, offsetof(struct cliq_source_controller_birth, digest)); sha256_final(&creator_hash, creator.digest);
    check(source_write_all(birth, &header, sizeof(header)) && source_write_all(birth, &creator, sizeof(creator)) && fsync(birth) == 0,
        "complete immutable header and creator data write");
    struct cliq_source_history history;
    check(cliq_source_history_read(birth, &header, &history) && history.kind == 0, "complete controller frame with no reserve records is distinguishable data");
    check(cliq_source_recovery_prefix_complete(&history), "complete no-reserve data is not a no-spawn authority by itself");
    struct cliq_source_birth_record record = { .step = 1, .kind = 1, .packet = request };
    snprintf(record.packet.cgroup_name, sizeof(record.packet.cgroup_name), "cliq-source-%s", request.nonce);
    record.packet.subreaper_pid = creator.pid; memcpy(record.packet.subreaper_start_token, creator.process_start_token, sizeof(creator.process_start_token));
    append_data_birth(birth, &record, creator.digest);
    check(cliq_source_history_read(birth, &header, &history) && history.kind == 1, "actual reserve-intent prefix has no invented cgroup birth");
    check(!cliq_source_recovery_prefix_complete(&history), "missing original cgroup inode remains waiting");
    record.step = 2; record.kind = 2; record.packet.cgroup_device = 1; record.packet.cgroup_inode = 2;
    append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history) && history.kind == 2 && history.born.cgroup_inode == 2, "complete original cgroup birth data preserved");
    unsigned char second_digest[32]; memcpy(second_digest, history.digest, 32);
    check(cliq_source_recovery_prefix_complete(&history), "original cgroup birth is available for independent kernel checks");
    off_t complete_birth = lseek(birth, 0, SEEK_END);
    check(write(birth, "x", 1) == 1 && !cliq_source_history_read(birth, &header, &history), "trailing partial birth data rejected");
    check(ftruncate(birth, complete_birth) == 0, "explicit ordinary fixture restore");
    record.step = 3; record.kind = 4;
    append_data_birth(birth, &record, second_digest);
    check(!cliq_source_history_read(birth, &header, &history), "missing prepared birth may not be reconstructed from a later prefix");
    check(ftruncate(birth, complete_birth) == 0, "explicit invalid-prefix data fixture restore");
    record.step = 3; record.kind = 3; fixed_digest(record.packet.plan_ref, 'a');
    fixed_digest(record.packet.sandbox_launch_ref, 'b'); fixed_digest(record.packet.sandbox_launch_digest, 'c');
    append_data_birth(birth, &record, second_digest);
    check(cliq_source_history_read(birth, &header, &history) && history.kind == 3 && !cliq_source_recovery_prefix_complete(&history),
        "fork-intent without an original monitor token remains waiting");
    record.step = 4; record.kind = 4; record.packet.monitor_pid = getpid() + 1;
    memcpy(record.packet.monitor_start_token, creator.process_start_token, sizeof(record.packet.monitor_start_token));
    append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history) && cliq_source_recovery_prefix_complete(&history), "complete original monitor data has no fabricated READY");
    off_t monitor_end = lseek(birth, 0, SEEK_END);
    record.step = 5; record.kind = 11;
    append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history) && history.kind == 11 && !history.released && !history.continued && !history.ready.pid,
        "cleanup after blocked fork never invents release, continuation or READY");
    record.step = 6; record.kind = 12;
    append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history), "complete ordinary original-resource removal prefix");
    struct cliq_source_retirement_data retirement;
    check(cliq_source_retirement_project(&history, &retirement) && retirement.last_kind == 12 && retirement.reserved &&
        !retirement.blocked && !retirement.released && !retirement.continued && retirement.controller_pid == getpid() &&
        retirement.cgroup_device == 1 && retirement.cgroup_inode == 2 && strcmp(retirement.launch_nonce, request.activation_nonce) == 0 &&
        strcmp(retirement.plan_ref, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
        "original birth recovers exact closure data even without reserved or READY reply observations");
    check(retirement.monitor_pid == getpid() + 1 && retirement.worker_pid == 0 && !retirement.sealed,
        "partial blocked construction retains monitor provenance without inventing worker or snapshot authority");
    unsigned char *snapshot = NULL; size_t snapshot_bytes = 0;
    struct cliq_source_history decoded;
    check(cliq_source_history_read_snapshot(birth, &header, &decoded, &snapshot, &snapshot_bytes) && snapshot &&
        snapshot_bytes == (size_t)lseek(birth, 0, SEEK_END), "complete original snapshot bytes are actually reread with stable file identity");
    check(cliq_source_history_decode(snapshot, snapshot_bytes, &header, &decoded) && decoded.kind == 12 &&
        decoded.header.supervisor_pid == getpid(), "pure complete snapshot decoding preserves original owner provenance");
#ifdef CLIQ_SOURCE_LIFECYCLE_DATA_OUTPUT
    /* Ordinary inert dataset for the independently compiled pure decoder.
     * This test-only component cannot mint a StateOwner or native receipt. */
    char dataset[] = "/output/source-lifecycle-data.XXXXXX";
    int dataset_fd = mkstemp(dataset);
    check(dataset_fd >= 0 && source_write_all(dataset_fd, snapshot, snapshot_bytes) && fsync(dataset_fd) == 0 &&
        source_close_fd(&dataset_fd), "complete inert lifecycle fixture publication and join");
    printf("source lifecycle data=%s; bytes=%zu\n", dataset, snapshot_bytes);
    printf("source birth identity=%llu:%llu\n", (unsigned long long)original_birth.st_dev, (unsigned long long)original_birth.st_ino);
#endif
    history_wire_versions(snapshot, snapshot_bytes, &header);
    check(!cliq_source_history_decode(snapshot, snapshot_bytes - 1, &header, &decoded), "truncated snapshot never becomes original lifecycle");
    snapshot[offsetof(struct cliq_source_birth, supervisor_pid)] ^= 1;
    check(!cliq_source_history_decode(snapshot, snapshot_bytes, &header, &decoded), "changed original Supervisor bytes rejected");
    snapshot[offsetof(struct cliq_source_birth, supervisor_pid)] ^= 1;
    snapshot[snapshot_bytes - 1] ^= 1;
    check(!cliq_source_history_decode(snapshot, snapshot_bytes, &header, &decoded), "changed final progress checksum rejected");
    free(snapshot);
    /* A second ordinary data chain includes the original READY namespace.
     * These inert process/inode values establish no native authority. */
    check(monitor_end > 0 && ftruncate(birth, monitor_end) == 0 && cliq_source_history_read(birth, &header, &history),
        "restore exact original complete monitor data prefix");
    record.step = 5; record.kind = 5; record.packet.pid = getpid() + 2; record.packet.namespace_init_pid = getpid() + 3;
    record.packet.pid_namespace_inode = 314159;
    memcpy(record.packet.start_token, creator.process_start_token, sizeof(record.packet.start_token));
    memcpy(record.packet.init_native_start_token, creator.process_start_token, sizeof(record.packet.init_native_start_token));
    int init_token_bytes = snprintf(record.packet.init_start_token, sizeof(record.packet.init_start_token), "linux-namespace-init:%ld:%.20s:monitor:%ld:%.20s",
        (long)record.packet.namespace_init_pid, creator.process_start_token + strlen("linux-proc-start-ticks:"),
        (long)record.packet.monitor_pid, record.packet.monitor_start_token + strlen("linux-proc-start-ticks:"));
    check(init_token_bytes > 0 && (size_t)init_token_bytes < sizeof(record.packet.init_start_token), "complete inert original namespace token data");
    append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history) && history.ready.pid_namespace_inode == 314159,
        "original READY namespace identity retained in complete data chain");
    record.step = 6; record.kind = 11; append_data_birth(birth, &record, history.digest);
    check(cliq_source_history_read(birth, &header, &history), "complete READY cleanup prefix data");
    record.step = 7; record.kind = 12; append_data_birth(birth, &record, history.digest);
    snapshot = NULL; snapshot_bytes = 0;
    check(cliq_source_history_read_snapshot(birth, &header, &decoded, &snapshot, &snapshot_bytes) && snapshot &&
        cliq_source_retirement_project(&decoded, &retirement) && retirement.blocked &&
        retirement.containment && retirement.containment->pid_namespace_inode == 314159,
        "pure snapshot preserves exact original READY namespace for historical comparison");
#ifdef CLIQ_SOURCE_LIFECYCLE_DATA_OUTPUT
    char ready_dataset[] = "/output/source-lifecycle-data.XXXXXX";
    int ready_dataset_fd = mkstemp(ready_dataset);
    check(ready_dataset_fd >= 0 && source_write_all(ready_dataset_fd, snapshot, snapshot_bytes) && fsync(ready_dataset_fd) == 0 &&
        source_close_fd(&ready_dataset_fd), "complete inert READY lifecycle fixture publication and join");
    printf("source ready lifecycle data=%s; bytes=%zu\n", ready_dataset, snapshot_bytes);
#endif
    history_wire_versions(snapshot, snapshot_bytes, &header);
    free(snapshot);
    check(source_close_fd(&birth), "ordinary history file close"); unlink_fixture(root, "data-birth", false);
    int git = directory_at(root, "git"), input = directory_at(root, "input"), objects = directory_at(git, "objects");
    int pack = directory_at(objects, "pack"), info = directory_at(objects, "info"), git_info = directory_at(git, "info");
    const char head[] = "ref: refs/heads/main\n", raw[] = "fixed raw fixture not a secret or authorization";
    file_at(git, "HEAD", head, sizeof(head) - 1); file_at(git, "config", raw, sizeof(raw) - 1);
    size_t payload_bytes = 1048576; unsigned char *payload = malloc(payload_bytes); check(payload != NULL, "bounded component bytes"); memset(payload, 37, payload_bytes);
    file_at(pack, "fixture.pack", payload, payload_bytes); file_at(pack, "fixture.idx", "index", 5);
    file_at(pack, "fixture.rev", "not captured", 12); file_at(pack, "fixture.bitmap", "not captured", 12);
    file_at(info, "packs", "not captured", 12);
    const char rule[] = "independent-authorized-rule-sentinel";
    file_at(git_info, "exclude", rule, sizeof(rule) - 1);
    int notifications = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); char observed_rule[96];
    snprintf(observed_rule, sizeof(observed_rule), "/proc/self/fd/%d/exclude", git_info);
    check(notifications >= 0 && inotify_add_watch(notifications, observed_rule, IN_OPEN | IN_ACCESS) >= 0,
        "actual owned rule open/read observation");
    struct cliq_source_snapshot ungranted_rule;
    bool ungranted_accepted = source_capture_snapshot(git, &request, &ungranted_rule, 4 * 1048576);
    bool ungranted_joined = source_snapshot_close(&ungranted_rule); unsigned char events[4096]; errno = 0;
    ssize_t observed_events = read(notifications, events, sizeof(events)); int observed_error = errno;
    check(source_close_fd(&notifications), "actual owned rule observation descriptor join");
    check(!ungranted_accepted && ungranted_joined, "an existing rule without its independent grant must refuse rather than masquerade as absent");
    check(observed_events < 0 && observed_error == EAGAIN, "ungranted rule payload is never opened or read");
    struct cliq_worker_packet with_rule = request; fixed_digest(with_rule.source_exclude_grant_digest, 'e');
    struct cliq_source_snapshot rule_capture;
    check(source_capture_snapshot(git, &with_rule, &rule_capture, 4 * 1048576), "exact authorized rule uses original bounded capture");
    bool rule_seen = false;
    for (uint32_t i = 0; i < rule_capture.count; i++) {
        unsigned char *bytes = malloc((size_t)rule_capture.shard_bytes[i]); check(bytes != NULL, "bounded ordinary snapshot observation allocation");
        check(pread(rule_capture.shards[i], bytes, (size_t)rule_capture.shard_bytes[i], 0) == (ssize_t)rule_capture.shard_bytes[i], "actual sealed rule bytes observation");
        if (memmem(bytes, (size_t)rule_capture.shard_bytes[i], rule, sizeof(rule) - 1)) rule_seen = true;
        free(bytes);
    }
    if (!rule_seen) check(source_snapshot_close(&rule_capture), "failed authorized-rule observation closes all snapshot FDs");
    check(rule_seen, "only the separately authorized exact rule must be captured in scope");
    int authorized_input = directory_at(root, "authorized-input"), authorized_config = -1, authorized_rule = -1;
    check(source_materialize_snapshot(&rule_capture, authorized_input, &authorized_config, &authorized_rule), "authorized rule has an independent sealed materialization");
    check(authorized_rule >= 0 && fcntl(authorized_rule, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL),
        "independent ignore rule has all four real memfd seals");
    unsigned char rule_bytes[sizeof(rule)];
    check(pread(authorized_rule, rule_bytes, sizeof(rule) - 1, 0) == (ssize_t)sizeof(rule) - 1 && memcmp(rule, rule_bytes, sizeof(rule) - 1) == 0,
        "independent rule reader returns original authorized bytes");
    int original_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    check(original_dumpable >= 0 && prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0 && child_can_read_parent_fd(authorized_rule),
        "actual ordinary dumpable parent FD is readable before the source producer protection");
    check(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && !child_can_read_parent_fd(authorized_rule),
        "non-dumpable trusted producer rule FD is not visible to the helper child through proc");
    check(prctl(PR_SET_DUMPABLE, original_dumpable, 0, 0, 0) == 0, "restore only the component fixture dumpability");
    struct stat absent_rule;
    check(fstatat(authorized_input, "info/exclude", &absent_rule, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(authorized_input, "config", &absent_rule, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT,
        "neither ignore rule nor raw config becomes Git/helper input");
    check(source_close_fd(&authorized_rule) && source_close_fd(&authorized_config) && source_snapshot_close(&rule_capture),
        "independent rule and snapshot readers really join");
    unlink_fixture(authorized_input, "HEAD", false); unlink_fixture(authorized_input, "objects/pack/fixture.pack", false);
    unlink_fixture(authorized_input, "objects/pack/fixture.idx", false); unlink_fixture(authorized_input, "objects/pack", true);
    unlink_fixture(authorized_input, "objects/info", true); unlink_fixture(authorized_input, "objects", true);
    check(source_close_fd(&authorized_input), "authorized private input close"); unlink_fixture(root, "authorized-input", true);
    unlink_fixture(git_info, "exclude", false);
    size_t before = descriptor_count(); struct cliq_source_snapshot captured;
    check(source_capture_snapshot(git, &request, &captured, 4 * 1048576) && captured.count == 2, "real bounded capture into multiple memfds");
    for (uint32_t i = 0; i < captured.count; i++) {
        check(fcntl(captured.shards[i], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
            (fcntl(captured.shards[i], F_GETFL) & O_ACCMODE) == O_RDONLY, "all four seals and readonly aliases");
        check(pwrite(captured.shards[i], "x", 1, 0) < 0 && ftruncate(captured.shards[i], 0) < 0, "sealed bytes cannot be changed");
    }
    int original = openat(pack, "fixture.pack", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    check(original >= 0 && pwrite(original, "x", 1, 0) == 1 && source_close_fd(&original), "source changes do not change frozen input");
    int raw_reader = -1, no_rule = -1;
    check(source_materialize_snapshot(&captured, input, &raw_reader, &no_rule) && no_rule == -1, "actual sealed stream materializes completely with no unauthorized rule reader");
    check(source_snapshot_close(&captured), "all snapshot readers joined");
    expect_content(input, "HEAD", head, sizeof(head) - 1); expect_content(input, "objects/pack/fixture.pack", payload, payload_bytes);
    struct stat absent;
    check(fstatat(input, "config", &absent, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT, "raw config never lands in Git directory");
    check(fstatat(input, "objects/pack/fixture.rev", &absent, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(input, "objects/info/packs", &absent, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
        fstatat(input, "info/exclude", &absent, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT, "unused accelerators and ignore payload never captured");
    unsigned char raw_bytes[sizeof(raw)];
    check(pread(raw_reader, raw_bytes, sizeof(raw) - 1, 0) == (ssize_t)sizeof(raw) - 1 && memcmp(raw_bytes, raw, sizeof(raw) - 1) == 0 &&
        fcntl(raw_reader, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) && source_close_fd(&raw_reader),
        "raw config has its own sealed reader and actual close");
    check(descriptor_count() == before, "capture materialization all FD ownership joined");

    file_at(info, "alternates", "must reject", 11);
    check(!source_capture_snapshot(git, &request, &captured, 0) && source_snapshot_close(&captured), "real alternates payload refused");
    unlink_fixture(info, "alternates", false);
    unlink_fixture(git, "config", false); check(symlinkat("HEAD", git, "config") == 0, "symlink fixture");
    check(!source_capture_snapshot(git, &request, &captured, 0) && source_snapshot_close(&captured), "config symlink refused nofollow");
    unlink_fixture(git, "config", false); check(linkat(git, "HEAD", git, "config", 0) == 0, "hardlink fixture");
    check(!source_capture_snapshot(git, &request, &captured, 0) && source_snapshot_close(&captured), "config hardlink refused");
    unlink_fixture(git, "config", false);
    check(descriptor_count() == before, "failed capture all issued descriptors joined");

    int deep = directory_at(root, "deep"), parent = fcntl(deep, F_DUPFD_CLOEXEC, 3); check(parent >= 0, "deep root clone");
    int refs = directory_at(parent, "refs"); check(source_close_fd(&parent), "deep parent close"); parent = refs;
    for (unsigned int i = 0; i < 20; i++) { int next = directory_at(parent, "r"); check(source_close_fd(&parent), "deep previous close"); parent = next; }
    file_at(parent, "tip", "tip", 3); check(source_close_fd(&parent), "deep leaf close");
    struct rlimit limits; check(getrlimit(RLIMIT_NOFILE, &limits) == 0 && limits.rlim_cur >= 64, "actual fd ceiling observed");
    struct rlimit bounded = limits; bounded.rlim_cur = 64;
    check(setrlimit(RLIMIT_NOFILE, &bounded) == 0, "actual fixed fd ceiling applied");
    check(source_capture_snapshot(deep, &request, &captured, 0) && source_snapshot_close(&captured), "real recursive double-descriptor peak fits 64");
    check(setrlimit(RLIMIT_NOFILE, &limits) == 0, "actual original fd ceiling restored");
    int current = openat(deep, "refs", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); check(current >= 0, "deep cleanup root");
    char depth_path[128] = "refs";
    for (unsigned int i = 0; i < 20; i++) strcat(depth_path, "/r");
    check(unlinkat(deep, strcat(depth_path, "/tip"), 0) == 0, "deep fixed leaf cleanup");
    depth_path[strlen(depth_path) - 4] = '\0';
    for (unsigned int i = 0; i < 20; i++) { unlink_fixture(deep, depth_path, true); *strrchr(depth_path, '/') = '\0'; }
    check(source_close_fd(&current), "deep cleanup read close"); unlink_fixture(deep, "refs", true);
    check(source_close_fd(&deep), "deep root close"); unlink_fixture(root, "deep", true);

    unlink_fixture(input, "objects/pack/fixture.pack", false); unlink_fixture(input, "objects/pack/fixture.idx", false);
    unlink_fixture(input, "objects/pack", true); unlink_fixture(input, "objects/info", true); unlink_fixture(input, "objects", true);
    unlink_fixture(input, "HEAD", false);
    unlink_fixture(pack, "fixture.pack", false); unlink_fixture(pack, "fixture.idx", false); unlink_fixture(pack, "fixture.rev", false); unlink_fixture(pack, "fixture.bitmap", false);
    unlink_fixture(info, "packs", false);
    check(source_close_fd(&pack) && source_close_fd(&info) && source_close_fd(&git_info), "source child directories close");
    unlink_fixture(objects, "pack", true); unlink_fixture(objects, "info", true); check(source_close_fd(&objects), "source objects close");
    unlink_fixture(git, "objects", true); unlink_fixture(git, "info", true); unlink_fixture(git, "HEAD", false);
    check(source_close_fd(&git) && source_close_fd(&input), "source and materialized roots close");
    unlink_fixture(root, "git", true); unlink_fixture(root, "input", true); check(source_close_fd(&root) && rmdir(locator) == 0, "owned fixture root fully removed");
    free(payload); printf("source component checks=%u; no authority or installed qualification\n", checks); return 0;
}
