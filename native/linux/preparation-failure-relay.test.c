/* Real bounded owned fork/socket/exit observations for diagnostic routing.
 * No Run, StateOwner, namespace, permission, output or death proof is minted. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "preparation-failure-relay.h"
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
static unsigned int checks;
static void check(bool condition, const char *label) {
    checks++; if (!condition) { fprintf(stderr, "failure relay component failed: %s\n", label); exit(1); }
}
static void digest(char out[65], char byte) { memset(out, byte, 64); out[64] = '\0'; }
static size_t descriptors(void) {
    DIR *stream = opendir("/proc/self/fd"); check(stream != NULL, "owned descriptor inventory");
    struct dirent *entry; size_t count = 0;
    while ((entry = readdir(stream))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    check(closedir(stream) == 0, "descriptor inventory actual close"); return count;
}
static void close_slot(int *slot) {
    if (*slot < 0) return;
    int fd = *slot; *slot = -1; check(close(fd) == 0, "owned original descriptor joins");
}
static struct cliq_worker_packet original(void) {
    struct cliq_worker_packet packet = cliq_packet(CLIQ_SOURCE_CREATE_BLOCKED);
    packet.scope = 1; packet.generation_device = packet.generation_inode = packet.reservation_device = packet.reservation_inode = 1;
    packet.reservation_uid = geteuid(); packet.subreaper_pid = getpid();
    check(cliq_process_token(getpid(), packet.subreaper_start_token), "actual original test process identity");
    digest(packet.generation_ref, 'a'); digest(packet.preparation_input_intent_ref, 'b');
    digest(packet.nonce, 'c'); digest(packet.activation_nonce, 'd'); strcpy(packet.cgroup_name, "owned-component-data");
    packet.max_processes = 32; packet.memory_bytes = 268435456; packet.cpu_quota = 1000000;
    packet.max_open_files = 64; packet.max_file_bytes = 1048576; packet.max_generation_bytes = 268435456; packet.max_output_bytes = 65536;
    check(cliq_preparation_request_valid(&packet), "original inert preparation data is closed"); return packet;
}
int main(void) {
    struct cliq_worker_packet expected = original(); const size_t baseline = descriptors();
    uint64_t wrong_origin = expected.reservation_uid + 1;
    for (unsigned int scenario = 0; scenario < 23; scenario++) {
        int producer[2], receiver[2];
        check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, producer) == 0, "real original producer channel");
        check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, receiver) == 0, "real diagnostic parent channel");
        pid_t child = fork(); check(child >= 0, "actual owned producer fork");
        if (child == 0) {
            close(producer[0]); close(receiver[0]); close(receiver[1]);
            struct cliq_worker_packet response = expected; response.command = CLIQ_SOURCE_RESULT; response.status = 2005;
            int fd = -1; size_t count = 0;
            if (scenario == 1) response.nonce[0] = 'e';
            if (scenario == 2) response.preparation_input_intent_ref[0] = 'e';
            if (scenario == 3) { fd = open("/dev/null", O_RDONLY | O_CLOEXEC); if (fd < 0) _exit(71); count = 1; }
            if (scenario == 4) response.source_byte_count = 1;
            if (scenario == 5) response.init_reaped = 1;
            if (scenario == 6) response.observed_at_ms = 1;
            if (scenario == 7) response.status = 0;
            if (scenario == 8) response.status = 2017;
            if (scenario == 13) response.command = CLIQ_SOURCE_POLL_RESULT;
            if (scenario == 14) response.version--;
            if (scenario == 15) response.status = 2502;
            if (scenario == 18) strcpy(response.relative_path, "not-permitted-result-data");
            if (scenario == 19) response.preparation_input_intent_ref[0] = '\0';
            if (scenario == 20) response.status = 2016;
            bool sent = true;
            if (scenario == 21) sent = send(producer[1], &response, sizeof(response) - 1, MSG_NOSIGNAL) == (ssize_t)sizeof(response) - 1;
            else if (scenario != 22) sent = cliq_send(producer[1], &response, count ? &fd : NULL, count);
            if (fd >= 0 && close(fd) != 0) sent = false;
            if (close(producer[1]) != 0) sent = false;
            if (!sent) _exit(71);
            if (scenario == 11) { raise(SIGTERM); _exit(71); }
            _exit(scenario == 9 ? 0 : scenario == 10 ? 74 : 70);
        }
        close_slot(&producer[1]);
        if (scenario == 16) close_slot(&receiver[1]);
        struct cliq_worker_packet response; int files[CLIQ_SOURCE_TRANSFER_OUTPUTS] = {-1, -1, -1, -1, -1}; size_t count = 0;
        bool received = cliq_receive(producer[0], &response, files, CLIQ_SOURCE_TRANSFER_OUTPUTS, &count);
        check(received == (scenario != 14 && scenario != 21 && scenario != 22), "wire parsing preserves full packet/version/EOF guards");
        uint64_t observed_uid = scenario == 12 ? wrong_origin : expected.reservation_uid;
        bool valid = false;
        if (received) {
            if (scenario == 17) close_slot(&producer[0]);
            valid = cliq_preparation_forward_joined_failure(child, &producer[0], receiver[0], &expected, &response, count, observed_uid);
        }
        bool accepts = scenario == 0 || scenario == 15 || scenario == 20;
        check(valid == accepts, "only exact zero-FD failure and actual exit70 forwards");
        struct cliq_worker_packet forwarded; int passed[1] = {-1}; size_t passed_count = 0;
        if (accepts) {
            check(cliq_receive(receiver[1], &forwarded, passed, 1, &passed_count), "actual joined failure packet reaches parent");
            check(passed_count == 0 && memcmp(&forwarded, &response, sizeof(response)) == 0, "only original exact diagnostic bytes pass");
            check(forwarded.status != 0 && forwarded.command == CLIQ_SOURCE_RESULT && !forwarded.init_reaped &&
                !forwarded.source_output_bytes[0] && !forwarded.observed_at_ms, "relay cannot manufacture result or death facts");
        } else if (receiver[1] >= 0) {
            errno = 0;
            check(!cliq_receive_flags(receiver[1], &forwarded, passed, 1, &passed_count, MSG_DONTWAIT) &&
                (errno == EAGAIN || errno == EWOULDBLOCK), "foreign/FD/status/exit/transport refusal cannot reach parent");
        }
        for (size_t i = 0; i < count; i++) close_slot(&files[i]);
        close_slot(&producer[0]); close_slot(&receiver[0]); close_slot(&receiver[1]);
        int status = 0; pid_t joined;
        do { joined = waitpid(child, &status, 0); } while (joined < 0 && errno == EINTR);
        check(joined == child || (joined < 0 && errno == ECHILD), "every original owned producer truly joins once");
        check(descriptors() == baseline, "all real processes/channel/received FD owners are joined");
    }
    for (int outcome = CLIQ_SOURCE_REPLY_GENERIC_REFUSAL; outcome <= 1; outcome++) {
        uint32_t expected_guard = outcome == -2 ? 4005 : outcome == -3 ? 4006 : outcome == -4 ? 4007 : outcome == -5 ? 4008 : 0;
        check(cliq_source_reply_failure_guard(outcome) == expected_guard, "local transport guards never copy peer data");
    }
    struct cliq_worker_packet failure = expected; failure.command = CLIQ_SOURCE_RESULT; failure.status = 2005;
    check(!cliq_preparation_failure_packet_for_uid(&expected, &failure, 0, wrong_origin), "origin cannot come from an unmatched caller UID");
    printf("{\"format\":\"cliq-preparation-failure-relay-component-v1\",\"checks\":%u,\"actualRunQualified\":false}\n", checks);
    return 0;
}
