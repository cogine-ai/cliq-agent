/* Ordinary bounded birth data on a real private file. This is not a native
 * reservation, StateOwner, cgroup, process-death or installed qualification. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "preparation-git-protocol.h"
#include <stdlib.h>

static unsigned int checks;
static void check(bool accepted, const char *label) {
    checks++;
    if (!accepted) { fprintf(stderr, "preparation component failed: %s\n", label); exit(1); }
}
static void fixed(char *output, size_t bytes, char value) { memset(output, value, bytes - 1); output[bytes - 1] = '\0'; }
int main(void) {
    char filename[] = "/output/worker-preparation-component.XXXXXX";
    int fd = mkstemp(filename); check(fd >= 0 && fchmod(fd, 0600) == 0, "private birth data file");
    struct stat file; check(fstat(fd, &file) == 0, "actual data inode");
    struct cliq_preparation_origin origin = { .owner_epoch = 1, .controller_pid = getpid(), .supervisor_pid = (uint64_t)getpid() + 1,
        .reservation_device = file.st_dev, .reservation_inode = file.st_ino, .reservation_uid = file.st_uid,
        .generation_device = 1, .generation_inode = 2,
        .max_processes = 32, .memory_bytes = UINT64_C(268435456), .cpu_quota = 1000000,
        .max_open_files = 64, .max_file_bytes = UINT64_C(268435456), .max_generation_bytes = UINT64_C(1073741824),
        .max_output_bytes = UINT64_C(67108864), .max_ipc_frame_bytes = UINT64_C(16777216), .max_queued_ipc_bytes = UINT64_C(67108864) };
    origin.root = origin.parent = origin.leaf = (struct cliq_preparation_directory){ .device = 1, .inode = 1,
        .uid = geteuid(), .gid = getegid(), .mode = S_IFDIR | 0700 };
    fixed(origin.session_id, sizeof(origin.session_id), 's'); fixed(origin.run_id, sizeof(origin.run_id), 'r');
    fixed(origin.launch_id, sizeof(origin.launch_id), 'l'); fixed(origin.checkpoint_id, sizeof(origin.checkpoint_id), 'c');
    fixed(origin.supervisor_id, sizeof(origin.supervisor_id), 'v');
    fixed(origin.state_owner_digest, sizeof(origin.state_owner_digest), 'a'); fixed(origin.generation_ref, sizeof(origin.generation_ref), 'b');
    fixed(origin.source_workspace_ref, sizeof(origin.source_workspace_ref), 'c'); fixed(origin.repository_digest, sizeof(origin.repository_digest), 'd');
    fixed(origin.input_intent_ref, sizeof(origin.input_intent_ref), 'e'); fixed(origin.creation_nonce, sizeof(origin.creation_nonce), 'f');
    fixed(origin.spawn_nonce, sizeof(origin.spawn_nonce), '1'); fixed(origin.activation_nonce, sizeof(origin.activation_nonce), '2');
    strcpy(origin.controller_leaf, "controller-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    check(cliq_process_token(getpid(), origin.controller_token), "actual component PID/start identity sample");
    memcpy(origin.supervisor_token, origin.controller_token, sizeof(origin.supervisor_token));
    unsigned char encoded[CLIQ_RESERVATION_BODY]; struct cliq_preparation_origin decoded;
    preparation_origin_encode(encoded, &origin);
    check(preparation_origin_decode(encoded, &decoded), "closed versioned preparation origin data");
    check(preparation_origin_same(&origin, &decoded), "all original owner and physical bindings survive encoding");
    struct cliq_preparation_history history;
    check(preparation_history_begin(fd, &origin) && preparation_history_read(fd, &origin, &history) && history.phase == CLIQ_PREPARATION_ORIGIN,
        "durable origin-only prefix stays distinct from the legacy worker binding");
    check(preparation_read_cleanup_history(fd, &origin, &history), "cleanup decoder retains the complete original no-mutation origin data");
    bool attempted = true; struct cliq_worker_packet expected = cliq_packet(CLIQ_BIND_RESERVATION), actual;
    expected.reservation_device = file.st_dev; expected.reservation_inode = file.st_ino; expected.reservation_uid = file.st_uid;
    expected.generation_device = origin.generation_device; expected.generation_inode = origin.generation_inode;
    expected.subreaper_pid = origin.controller_pid; strcpy(expected.subreaper_start_token, origin.controller_token);
    fixed(expected.plan_ref, sizeof(expected.plan_ref), '3'); fixed(expected.sandbox_launch_ref, sizeof(expected.sandbox_launch_ref), '4');
    fixed(expected.sandbox_launch_digest, sizeof(expected.sandbox_launch_digest), '5'); strcpy(expected.generation_ref, origin.generation_ref);
    strcpy(expected.nonce, origin.spawn_nonce); strcpy(expected.activation_nonce, origin.activation_nonce);
    snprintf(expected.cgroup_name, sizeof(expected.cgroup_name), "cliq-%s", origin.spawn_nonce); strcpy(expected.pid_namespace_reservation, "pending:component-data");
    check(reservation_binding_valid(&expected), "legacy comparison uses a genuinely valid closed data binding");
    check(!reservation_read(fd, &expected, &attempted, &actual), "preparing child origin can never become legacy not-attempted evidence");
    struct cliq_preparation_progress progress = {0};
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_CREATE_INTENT, &progress) &&
        preparation_history_read(fd, &origin, &history) && history.phase == CLIQ_PREPARATION_CREATE_INTENT &&
        !preparation_prefix_complete(&history), "create intent without original cgroup birth remains explicit uncertainty");
    check(!preparation_read_cleanup_history(fd, &origin, &history), "cleanup cannot guess an identity in the create-intent gap");
    check(!preparation_history_append(fd, &origin, CLIQ_PREPARATION_BLOCKED, &progress), "missing original cgroup and monitor frames cannot be guessed");
    progress.cgroup_device = 3; progress.cgroup_inode = 4;
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_CGROUP, &progress) &&
        preparation_history_read(fd, &origin, &history) && preparation_prefix_complete(&history), "exact data cgroup birth retained");
    check(preparation_read_cleanup_history(fd, &origin, &history), "cleanup data has the original exact recorded cgroup birth");
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_FORK_INTENT, &progress) &&
        preparation_history_read(fd, &origin, &history) && !preparation_prefix_complete(&history), "fork intent without monitor birth remains uncertain");
    check(!preparation_read_cleanup_history(fd, &origin, &history), "cleanup cannot guess the pre-monitor fork gap");
    progress.monitor_pid = 19; strcpy(progress.monitor_token, "linux-proc-start-ticks:219");
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_MONITOR, &progress), "original monitor PID and start token data");
    progress.worker_pid = 21; progress.init_pid = 20; progress.pid_namespace_inode = 7; progress.populated = 1;
    strcpy(progress.worker_token, "linux-proc-start-ticks:221"); strcpy(progress.init_native_token, "linux-proc-start-ticks:220");
    strcpy(progress.init_token, "linux-namespace-init:20:220:monitor:19:219");
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_BLOCKED, &progress), "original blocked process and namespace data");
    check(!preparation_history_append(fd, &origin, CLIQ_PREPARATION_RESULT, &progress), "fixed child cannot run on unsealed incomplete CAS input");
    progress.input_bytes = 123; progress.input_entries = 3; progress.input_shards = 1; fixed(progress.input_digest, sizeof(progress.input_digest), '6');
    struct cliq_preparation_progress replacement = progress; replacement.worker_pid++;
    check(!preparation_history_append(fd, &origin, CLIQ_PREPARATION_INPUT_SEALED, &replacement), "sealed input cannot replace the original worker identity");
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_INPUT_SEALED, &progress), "original complete bounded sealed CAS input data");
    for (size_t i = 0; i < 4; i++) { progress.outputs[i].byte_count = 100 + i; fixed(progress.outputs[i].digest, sizeof(progress.outputs[i].digest), (char)('7' + i % 3)); }
    progress.populated = 0; progress.init_reaped = 1;
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_RESULT, &progress), "fixed result and original whole-domain death data");
    check(!preparation_history_append(fd, &origin, CLIQ_PREPARATION_RESOURCES_CLOSED, &progress), "real result may not stand in for outstanding consumers and descriptors");
    check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_CONSUMERS_JOINED, &progress) &&
        preparation_history_append(fd, &origin, CLIQ_PREPARATION_RESOURCES_CLOSED, &progress) &&
        preparation_history_append(fd, &origin, CLIQ_PREPARATION_SCOPE_REMOVED, &progress) &&
        preparation_history_read(fd, &origin, &history) && history.phase == CLIQ_PREPARATION_SCOPE_REMOVED && history.frames == 11,
        "original consumers then all resources then exact removal data remain separate ordered boundaries");
    const size_t complete_bytes = CLIQ_PREPARATION_MAX_FRAMES * CLIQ_PREPARATION_FRAME_BYTES;
    unsigned char *complete = malloc(complete_bytes); check(complete != NULL &&
        reservation_pread_all(fd, complete, complete_bytes, 0), "bounded complete fixture byte observation");
    check(!reservation_read_complete(fd, &expected, &attempted, &actual), "closed preparation alone is not a bound worker or no-spawn record");
    struct cliq_reservation suffix = { .fd = fd, .binding = expected, .bytes = complete_bytes, .binding_offset = complete_bytes };
    reservation_encode(encoded, &expected);
    check(lseek(fd, 0, SEEK_END) == (off_t)complete_bytes && reservation_append(&suffix, CLIQ_RESERVATION_BINDING, encoded, sizeof(encoded)) &&
        reservation_read_complete(fd, &expected, &attempted, &actual) && !attempted,
        "same original complete reservation admits the subsequent worker binding without hiding the preparing child");
    check(preparation_read_cleanup_history(fd, &origin, &history), "unexecuted original final BIND remains a cleanup-only preparing prefix");
    struct cliq_worker_packet wrong_binding = expected; wrong_binding.generation_ref[0] = 'a';
    check(!reservation_read_complete(fd, &wrong_binding, &attempted, &actual), "post-preparation binding cannot substitute the original generation");
    wrong_binding = expected; wrong_binding.activation_nonce[0] = '3';
    check(!reservation_read_complete(fd, &wrong_binding, &attempted, &actual), "post-preparation binding cannot substitute the original activation nonce");
    unsigned char intent[32] = {0}; memcpy(intent, "CREATE1", 7);
    check(reservation_append(&suffix, CLIQ_RESERVATION_INTENT, intent, sizeof(intent)) &&
        !reservation_read_complete(fd, &expected, &attempted, &actual), "post-preparation partial worker intent is never no-spawn");
    check(!preparation_read_cleanup_history(fd, &origin, &history), "preparing cleanup never consumes a final worker intent");
    unsigned char group[64] = {0}; unsigned char *cursor = group;
    reservation_u64(&cursor, 31); reservation_u64(&cursor, 32); reservation_u64(&cursor, geteuid()); reservation_u64(&cursor, S_IFDIR | 0700);
    check(reservation_append(&suffix, CLIQ_RESERVATION_CGROUP, group, sizeof(group)) &&
        !reservation_read_complete(fd, &expected, &attempted, &actual), "post-preparation partial worker cgroup birth remains waiting");
    unsigned char monitor[256] = {0}; cursor = monitor; reservation_u64(&cursor, 39);
    char monitor_token[CLIQ_WORKER_TOKEN_BYTES] = "linux-proc-start-ticks:239"; reservation_text(&cursor, monitor_token, sizeof(monitor_token));
    check(reservation_append(&suffix, CLIQ_RESERVATION_MONITOR, monitor, sizeof(monitor)) &&
        !reservation_read_complete(fd, &expected, &attempted, &actual), "post-preparation monitor without READY remains waiting");
    struct cliq_worker_packet worker = expected; worker.cgroup_device = 31; worker.cgroup_inode = 32; worker.monitor_pid = 39;
    worker.pid = 41; worker.namespace_init_pid = 40; worker.pid_namespace_inode = 47;
    strcpy(worker.monitor_start_token, monitor_token); strcpy(worker.start_token, "linux-proc-start-ticks:241");
    strcpy(worker.init_native_start_token, "linux-proc-start-ticks:240"); strcpy(worker.init_start_token, "linux-namespace-init:40:240:monitor:39:239");
    reservation_encode(encoded, &worker);
    check(reservation_append(&suffix, CLIQ_RESERVATION_READY, encoded, sizeof(encoded)) &&
        reservation_read_complete(fd, &expected, &attempted, &actual) && attempted && actual.pid == 41 && actual.monitor_pid == 39,
        "all original worker birth frames follow the same closed preparing lifecycle on the same inode");
    check(!preparation_read_cleanup_history(fd, &origin, &history), "full worker birth belongs exclusively to existing worker recovery");
    check(!reservation_read(fd, &expected, &attempted, &actual), "legacy decoder still refuses the combined family without fallback");
    check(ftruncate(fd, (off_t)complete_bytes) == 0 && fsync(fd) == 0, "restore exact original preparation prefix after worker suffix data checks");
    for (size_t cut = complete_bytes; cut-- > 0;) {
        check(ftruncate(fd, (off_t)cut) == 0, "owned exact byte-cut fixture");
        bool complete_prefix = cut > 0 && cut % CLIQ_PREPARATION_FRAME_BYTES == 0;
        check(preparation_history_read(fd, &origin, &history) == complete_prefix, "every partial body or footer is refused without legacy fallback");
        check(!reservation_read(fd, &expected, &attempted, &actual), "no preparation prefix can become legacy no-spawn authority");
        check(!reservation_read_complete(fd, &expected, &attempted, &actual), "no incomplete or unbound preparing prefix can become worker no-spawn evidence");
        const size_t phase = complete_prefix ? cut / CLIQ_PREPARATION_FRAME_BYTES - 1 : 0;
        check(preparation_read_cleanup_history(fd, &origin, &history) == (complete_prefix && phase != 1 && phase != 3),
            "every cleanup byte cut preserves original physical-prefix gaps instead of accepting absence");
    }
    check(lseek(fd, 0, SEEK_SET) == 0 && reservation_write_all(fd, complete, complete_bytes) && fsync(fd) == 0,
        "restore only this owned ordinary data fixture");
    check(preparation_history_read(fd, &origin, &history) && history.phase == CLIQ_PREPARATION_SCOPE_REMOVED,
        "full complete history remains intact after exhaustive prefix checks");
    const size_t cleanup_prefixes[] = { 3, 5, 6, 7 };
    for (size_t i = 0; i < sizeof(cleanup_prefixes) / sizeof(cleanup_prefixes[0]); i++) {
        check(ftruncate(fd, (off_t)(cleanup_prefixes[i] * CLIQ_PREPARATION_FRAME_BYTES)) == 0 &&
            preparation_history_read(fd, &origin, &history), "exact recorded prefix for an original cancellation data branch");
        struct cliq_preparation_progress canceled = history.progress; canceled.populated = 0; canceled.init_reaped = canceled.worker_pid ? 1 : 0;
        check(preparation_history_append(fd, &origin, CLIQ_PREPARATION_RESOURCES_CLOSED, &canceled) &&
            preparation_history_append(fd, &origin, CLIQ_PREPARATION_SCOPE_REMOVED, &canceled) &&
            preparation_history_read(fd, &origin, &history) && history.phase == CLIQ_PREPARATION_SCOPE_REMOVED,
            "recorded pre-result cancellation never invents input, result or outstanding output-consumer joins");
        check(lseek(fd, 0, SEEK_SET) == 0 && reservation_write_all(fd, complete, complete_bytes) && ftruncate(fd, (off_t)complete_bytes) == 0 && fsync(fd) == 0,
            "restore only the owned complete data fixture after cancellation branch");
    }
    unsigned char corrupt[CLIQ_PREPARATION_FRAME_BYTES]; memcpy(corrupt, complete, sizeof(corrupt)); corrupt[8] = 1;
    reservation_footer(corrupt + CLIQ_RESERVATION_BODY, CLIQ_PREPARATION_FACT_BASE, sizeof(corrupt), corrupt, CLIQ_RESERVATION_BODY);
    check(pwrite(fd, corrupt, sizeof(corrupt), 0) == (ssize_t)sizeof(corrupt) && !preparation_history_read(fd, &origin, &history),
        "nonzero reserved origin padding is refused even with its valid recomputed frame hash");
    check(pwrite(fd, complete, complete_bytes, 0) == (ssize_t)complete_bytes && fsync(fd) == 0, "restore exact owned fixture bytes after corrupt-padding test");
    struct cliq_preparation_origin foreign = origin; foreign.input_intent_ref[0] = '0';
    check(!preparation_history_read(fd, &foreign, &history), "same inode cannot substitute another original input intent");
    foreign = origin; foreign.owner_epoch++;
    check(!preparation_history_read(fd, &foreign, &history), "same file cannot substitute a newer StateOwner");
    foreign = origin; foreign.supervisor_pid++;
    check(!preparation_read_cleanup_history(fd, &foreign, &history), "cleanup cannot substitute the original Supervisor lifetime");
    check(fchmod(fd, 0644) == 0 && !preparation_history_read(fd, &origin, &history) && fchmod(fd, 0600) == 0,
        "world-readable birth data is refused rather than chmod-adopted");
    check(!preparation_history_append(fd, &origin, CLIQ_PREPARATION_SCOPE_REMOVED, &progress), "closed data history cannot be reused as a second child lifecycle");
    free(complete);
    check(close(fd) == 0 && unlink(filename) == 0, "owned data descriptor and fixture join");
    printf("preparation component checks=%u; data only, no authority or installed qualification\n", checks); return 0;
}
