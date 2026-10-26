/* Inert protocol data and actual owned sealed descriptors only. This test
 * never creates a native scope, Run, result, settlement or death authority. */
#define _GNU_SOURCE
#include "builtin-result-ack.h"
#include "verifier-protocol.h"
#include <dirent.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
static unsigned int checks;
static void check(bool value, const char *message) {
    checks++; if (!value) { fprintf(stderr, "builtin ACK data check failed: %s\n", message); exit(1); }
}
static size_t descriptors(void) {
    DIR *directory = opendir("/proc/self/fd"); check(directory != NULL, "actual descriptor enumeration");
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    check(closedir(directory) == 0, "actual enumeration closed"); return count;
}
static int sealed_output(void) {
    int fd = memfd_create("cliq-owned-ack-data", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    check(fd >= 0 && write(fd, "original bytes", 14) == 14, "owned actual output bytes");
    check(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0, "all original output seals");
    return fd;
}
int main(void) {
    check(CLIQ_WORKER_VERSION == 7 && CLIQ_WORKER_MAX_SCOPES == 16, "honest private wire version and unchanged arena ceiling");
    struct cliq_worker_packet packet = cliq_packet(CLIQ_ACK_BUILTIN_RESULT);
    packet.scope = 2; packet.parent = 1; packet.observed_at_ms = 7; memset(packet.nonce, 'a', 64);
    check(cliq_builtin_result_ack_valid(&packet), "closed ACK inert packet");
    check(cliq_builtin_result_ack_same(&packet, 2, 1, packet.nonce, 7), "exact original inert result identity");
    check(!cliq_builtin_result_ack_same(&packet, 3, 1, packet.nonce, 7), "different original scope rejected");
    check(!cliq_builtin_result_ack_same(&packet, 2, 3, packet.nonce, 7), "different parent rejected");
    check(!cliq_builtin_result_ack_same(&packet, 2, 1, packet.nonce, 8), "different genuine-result observation rejected");
    char other[65]; memset(other, 'b', 64); other[64] = '\0';
    check(!cliq_builtin_result_ack_same(&packet, 2, 1, other, 7), "different original nonce rejected");
    struct cliq_worker_packet changed;
#define REFUSE(mutation) do { changed = packet; mutation; check(!cliq_builtin_result_ack_valid(&changed), "unknown or productive packet field rejected"); } while (0)
    REFUSE(changed.version = 6); REFUSE(changed.magic++); REFUSE(changed.command = CLIQ_RELEASE_BUILTIN);
    REFUSE(changed.status = 1); REFUSE(changed.scope = 0); REFUSE(changed.scope = CLIQ_WORKER_MAX_SCOPES);
    REFUSE(changed.parent = 0); REFUSE(changed.parent = packet.scope); REFUSE(changed.parent = CLIQ_WORKER_MAX_SCOPES);
    REFUSE(changed.observed_at_ms = 0); REFUSE(changed.observed_at_ms = UINT64_C(9007199254740992));
    REFUSE(changed.nonce[0] = 'A'); REFUSE(changed.nonce[0] = '\0'); REFUSE(changed.nonce[64] = 'a');
    REFUSE(changed.max_processes = 1); REFUSE(changed.stdout_bytes = 1); REFUSE(changed.verifier_reason = CLIQ_VERIFIER_EXIT);
    REFUSE(changed.init_reaped = 1); REFUSE(changed.setup.stage = 1); REFUSE(changed.preparation_input_intent_ref[0] = 'a');
#undef REFUSE
    int channel[2]; check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) == 0, "actual fixed protocol channel");
    check(cliq_send(channel[0], &packet, NULL, 0), "current fixed packet full send");
    struct cliq_worker_packet received; size_t count = 0;
    check(cliq_receive(channel[1], &received, NULL, 0, &count) && count == 0 && cliq_builtin_result_ack_valid(&received), "actual current closed packet full receive");
    changed = packet; changed.version = 6; check(cliq_send(channel[0], &changed, NULL, 0), "historical raw packet is not rewritten at send");
    check(!cliq_receive(channel[1], &received, NULL, 0, &count), "live receiver never accepts historical wire6");
    check(close(channel[0]) == 0 && close(channel[1]) == 0, "actual protocol descriptors joined");
    size_t baseline = descriptors(); int first = sealed_output(), second = sealed_output();
    int old_first = first, old_second = second;
    check(cliq_builtin_result_retire_outputs(&first, &second) && first == -1 && second == -1, "both original sealed memfds actually retire");
    check(fcntl(old_first, F_GETFD) < 0 && errno == EBADF && fcntl(old_second, F_GETFD) < 0 && errno == EBADF, "both original descriptor slots are really closed");
    check(!cliq_builtin_result_retire_outputs(&first, &second), "retired slots cannot be closed twice");
    check(descriptors() == baseline, "successful data retirement retains no descriptor");
    first = sealed_output(); old_first = first;
    check(!cliq_builtin_result_retire_outputs(&first, &first) && first == old_first && fcntl(first, F_GETFD) >= 0, "aliased slots reject without touching the owned descriptor");
    second = first; check(!cliq_builtin_result_retire_outputs(&first, &second) && first == old_first && second == old_first, "duplicated slot value cannot pretend to be two outputs");
    check(close(first) == 0, "alias test real descriptor joined");
    first = sealed_output(); second = sealed_output(); old_first = first; old_second = second;
    check(close(first) == 0, "owned failure fixture closes only its first original descriptor");
    check(!cliq_builtin_result_retire_outputs(&first, &second) && first == -1 && second == -1, "uncertain first close still joins second and never acknowledges success");
    check(fcntl(old_second, F_GETFD) < 0 && errno == EBADF, "failed retirement still actually closes other output");
    int replacement = sealed_output(); check(replacement == old_first, "owned kernel descriptor reuse is observed");
    check(!cliq_builtin_result_retire_outputs(&first, &second) && fcntl(replacement, F_GETFD) >= 0, "repeated failed ACK never closes a recycled descriptor");
    check(close(replacement) == 0 && descriptors() == baseline, "all failure fixture descriptors actually joined");
    printf("{\"format\":\"cliq-builtin-result-ack-data-v1\",\"checks\":%u,\"actualRunQualified\":false}\n", checks); return 0;
}
