/* Real owned process/pipe observations. No launch, Owner, Run, permission,
 * output or physical-containment qualification is created by this component. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "preparation-git-protocol.h"
#include <dirent.h>
#include <signal.h>
static unsigned int checks;
static void check(bool valid, const char *message) {
    checks++; if (!valid) { fprintf(stderr, "post-READY diagnostic failed: %s\n", message); exit(1); }
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
static size_t descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd"); check(directory != NULL, "actual descriptor observation");
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    check(closedir(directory) == 0, "actual descriptor observation close"); return count;
}
static bool source_close_fd(int *fd) {
    if (*fd < 0) return true;
    int held = *fd; *fd = -1; return close(held) == 0;
}
/* Actual owned exec-diagnostic pipes and child waits. These are diagnostic
 * data/resource checks only; no native execution or death authority is minted. */
static void postready_diagnostic_component(void) {
    const uint32_t refused[] = { 0, 1, 2000, 2017, 2089, 2092, 2100, 2356, 2400, 2465, 2500, 2520, UINT32_MAX };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        check(!cliq_source_postready_failure_valid(refused[i]), "post-READY failure vocabulary rejects gaps and unknown values");
    for (uint32_t code = 2001; code <= 2016; code++) check(cliq_source_postready_failure_valid(code), "fixed producer failure vocabulary");
    check(!cliq_write_exec_diagnostic(-1, ENOENT), "actual failed diagnostic write cannot be accepted");
    struct cliq_worker_packet original = request_data();
    memset(original.source_inspection_id, 0, sizeof(original.source_inspection_id));
    memset(original.source_target_ref, 0, sizeof(original.source_target_ref));
    memset(original.source_input_intent_ref, 0, sizeof(original.source_input_intent_ref));
    original.generation_device = original.generation_inode = original.reservation_device = original.reservation_inode = 1;
    original.reservation_uid = geteuid(); original.subreaper_pid = getpid();
    check(cliq_process_token(getpid(), original.subreaper_start_token), "original component process identity observation");
    fixed_digest(original.generation_ref, 'c'); fixed_digest(original.preparation_input_intent_ref, 'd');
    strcpy(original.cgroup_name, "cliq-preparation-component");
    check(cliq_preparation_request_valid(&original), "closed preparation data is valid before diagnostic mutations");
    struct cliq_worker_packet response = original; response.command = CLIQ_SOURCE_RESULT; response.status = 2502;
    check(cliq_preparation_failure_status(&original, &response, CLIQ_SOURCE_RESULT, 0) == 2502,
        "only the original fixed attempt can project a closed failure diagnosis");
    struct cliq_worker_packet changed = response; changed.nonce[0] = 'f';
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "foreign launch nonce contributes no diagnostic data");
    changed = response; changed.preparation_input_intent_ref[0] = 'e';
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "foreign metadata identity contributes no diagnostic data");
    changed = response; changed.reservation_inode++;
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "foreign original reservation contributes no diagnostic data");
    changed = response; changed.memory_bytes++;
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "changed resource authority contributes no diagnostic data");
    changed = response; changed.status = 2520;
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "unknown code contributes no diagnostic data");
    changed = response; changed.status = 0;
    check(!cliq_preparation_failure_status(&original, &changed, CLIQ_SOURCE_RESULT, 0), "successful response is never a failure diagnosis");
    check(!cliq_preparation_failure_status(&original, &response, CLIQ_SOURCE_POLL_RESULT, 0), "wrong response command contributes no diagnostic data");
    check(!cliq_preparation_failure_status(&original, &response, CLIQ_SOURCE_RESULT, 1), "FD-bearing reply contributes no diagnostic data");
    struct cliq_worker_packet source = request_data();
    check(!cliq_preparation_failure_status(&source, &response, CLIQ_SOURCE_RESULT, 0), "source grant cannot enter preparation failure projection");

    const unsigned int baseline = descriptor_count();
    for (int scenario = 0; scenario < 23; scenario++) {
        int channel[2]; check(pipe2(channel, O_CLOEXEC) == 0, "owned helper diagnosis pipe");
        pid_t child = fork(); check(child >= 0, "owned diagnostic child born");
        if (child == 0) {
            close(channel[0]);
            if (scenario >= 1 && scenario <= 19) {
                if (!cliq_write_exec_diagnostic(channel[1], -scenario)) _exit(71);
            } else if (scenario == 20 && !cliq_write_exec_diagnostic(channel[1], ENOENT)) _exit(71);
            if (close(channel[1]) != 0) _exit(71);
            if (scenario == 22) { raise(SIGTERM); _exit(71); }
            _exit(scenario == 0 ? 0 : scenario == 21 ? 74 : 70);
        }
        check(source_close_fd(&channel[1]), "diagnostic parent writer joins");
        unsigned char buffer[sizeof(int) + 1]; size_t bytes = 0;
        for (;;) {
            ssize_t count = read(channel[0], buffer + bytes, sizeof(buffer) - bytes);
            if (count < 0 && errno == EINTR) continue;
            check(count >= 0, "actual diagnostic bounded read");
            if (count == 0) break;
            bytes += (size_t)count; check(bytes < sizeof(buffer), "diagnostic is one fixed int only");
        }
        check(source_close_fd(&channel[0]), "diagnostic actual EOF and reader join");
        int status = 0; pid_t joined; do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
        check(joined == child, "original diagnostic child is actually joined");
        int diagnostic = 0; if (bytes == sizeof(diagnostic)) memcpy(&diagnostic, buffer, sizeof(diagnostic));
        uint32_t observed = cliq_source_helper_failure(true, status, (ssize_t)bytes, diagnostic);
        uint32_t expected = scenario == 0 ? 0 : scenario <= 19 ? (uint32_t)(2500 + scenario) :
            scenario == 20 ? CLIQ_SOURCE_FAIL_EXEC : scenario == 21 ? 2174 : 2400 + SIGTERM;
        check(observed == expected, "fixed diagnosis comes from exact original actual exit/signal and pipe bytes");
        check(scenario == 0 ? !cliq_source_postready_failure_valid(observed) : cliq_source_postready_failure_valid(observed),
            "only failed helper observations enter the closed diagnostic vocabulary");
        check(cliq_source_helper_failure(false, status, (ssize_t)bytes, diagnostic) == CLIQ_SOURCE_FAIL_HELPER_JOIN,
            "missing actual join never invents a helper exit observation");
        check(descriptor_count() == baseline, "every diagnostic scenario joins its actual process/pipes/descriptors");
    }
    check(cliq_source_helper_failure(true, 70 << 8, sizeof(int) - 1, -2) == CLIQ_SOURCE_FAIL_EXEC,
        "partial diagnostic data never becomes an authenticated confinement stage");
    check(cliq_source_helper_failure(true, 74 << 8, sizeof(int), -2) == CLIQ_SOURCE_FAIL_EXEC,
        "a pre-exec stage must have its exact actual exit70");
}

int main(void) {
    postready_diagnostic_component();
    printf("{\"format\":\"cliq-source-postready-diagnostic-data-v1\",\"checks\":%u,\"actualRunQualified\":false}\n", checks);
    return 0;
}
