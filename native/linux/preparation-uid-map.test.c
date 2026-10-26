/* Pure map/request decoding and actual current-process observations only.
 * This component cannot mint a namespace, reservation or preparation proof. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "preparation-git-protocol.h"
#include <assert.h>
static void digest(char text[65], char value) { memset(text, value, 64); text[64] = '\0'; }
int main(void) {
    uint64_t uid = 0; unsigned int checks = 0;
    const char *valid[] = { "0 1001 1\n", "         0       1001          1\n", "0\t1001\t1\n", "0 0 1\n", "0 4294967294 1\n" };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        assert(preparation_single_uid_map((const unsigned char *)valid[i], strlen(valid[i]), &uid)); checks++;
    }
    const char *invalid[] = { "", "0 1001 1", "0 1001 1\n0 1002 1\n", "1 1001 1\n", "0 1001 2\n", "0 4294967295 1\n",
        "0 18446744073709551616 1\n", "0 -1001 1\n", "0 +1001 1\n", "0 1001 1 garbage\n", "0 1001 1\n\n", "0\n1001\n1\n", "0 1001 1 0\n", "0 1001 1\r\n" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(!preparation_single_uid_map((const unsigned char *)invalid[i], strlen(invalid[i]), &uid)); checks++;
    }
    unsigned char too_long[256]; memset(too_long, ' ', sizeof(too_long));
    assert(!preparation_single_uid_map(too_long, sizeof(too_long), &uid)); checks++;
    assert(!preparation_single_uid_map(NULL, 1, &uid)); checks++;
    struct cliq_worker_packet request = cliq_packet(CLIQ_SOURCE_CREATE_BLOCKED);
    request.generation_device = 1; request.generation_inode = 2; request.reservation_device = 3; request.reservation_inode = 4;
    request.reservation_uid = geteuid(); request.subreaper_pid = getpid();
    assert(cliq_process_token(getpid(), request.subreaper_start_token)); checks++;
    digest(request.preparation_input_intent_ref, 'a'); digest(request.generation_ref, 'b'); digest(request.nonce, 'c'); digest(request.activation_nonce, 'd');
    assert(cliq_preparation_request_valid(&request)); checks++;
    assert(cliq_preparation_same_attempt(&request, &request)); checks++;
    uint64_t other_uid = geteuid() == 1001 ? 1002 : 1001; request.reservation_uid = other_uid;
    assert(!cliq_preparation_request_valid(&request)); checks++;
    assert(preparation_request_for_uid(&request, other_uid)); checks++;
    assert(preparation_same_attempt_for_uid(&request, &request, other_uid)); checks++;
    struct cliq_worker_packet changed = request; changed.activation_nonce[0] = 'e';
    assert(!preparation_same_attempt_for_uid(&request, &changed, other_uid)); checks++;
    changed = request; changed.reservation_uid++; assert(!preparation_same_attempt_for_uid(&request, &changed, other_uid)); checks++;
    bool actual_namespace_mapping = preparation_namespace_origin_uid(&uid);
    if (actual_namespace_mapping) { assert(geteuid() == 0 && getegid() == 0); checks++; }
    else { assert(!cliq_preparation_namespace_request_valid(&request)); checks++; }
    printf("{\"format\":\"cliq-preparing-uid-map-data-v1\",\"checks\":%u,\"actualNamespaceMapping\":%s,\"actualRunQualified\":false}\n",
        checks, actual_namespace_mapping ? "true" : "false");
    return 0;
}
