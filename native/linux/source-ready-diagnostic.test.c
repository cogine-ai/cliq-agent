/* Actual owned memfd and pure private marker parsing. No namespace or
 * readiness qualification is created by these diagnostic-only observations. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "source-ready-diagnostic.h"
#include <assert.h>
#include <sys/mman.h>
static void digest(char text[65], char value) { memset(text, value, 64); text[64] = '\0'; }
static size_t frame(char out[512], const char nonce[65], const char *numbers) {
    int used = snprintf(out, 512, CLIQ_SOURCE_READY_DIAGNOSTIC_PREFIX "%s:%s\n", nonce, numbers);
    assert(used > 0 && used < 512); return (size_t)used;
}
int main(void) {
    unsigned int checks = 0; char nonce[65]; digest(nonce, 'a');
    struct cliq_source_ready_diagnostic data; unsigned char bytes[512];
    size_t used = frame((char *)bytes, nonce, "3:0:0:1001:1:0:0:1");
    assert(source_ready_diagnostic_decode(bytes, used, nonce, &data) && data.stage == 3 && data.map_parent == 0 && data.original_uid == 1001); checks++;
    memset(bytes + used, 0, sizeof(bytes) - used);
    assert(source_ready_diagnostic_decode(bytes, sizeof(bytes), nonce, &data)); checks++;
    char other[65]; digest(other, 'b'); assert(!source_ready_diagnostic_decode(bytes, used, other, &data)); checks++;
    assert(!source_ready_diagnostic_decode(bytes, used - 1, nonce, &data)); checks++;
    bytes[used] = 'x'; assert(!source_ready_diagnostic_decode(bytes, used + 1, nonce, &data)); checks++;
    const char *invalid[] = { "0:0:0:1001:1:0:1001:1", "10:0:0:1001:1:0:1001:1", "3:0:0:1001:2:0:1001:1", "3:0:0:1001:0:0:1001:1",
        "3:0:0:1001:1:0:4294967296:1", "3:0:0:1001:1:0:-1:1", "3:0:0:1001:1:0:+1:1", "3:0:0:1001:1:0:1:1:0", "3:0:0:1001:1:0:1", "3:0:0:1001:1:0:1:1\n" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) { used = frame((char *)bytes, nonce, invalid[i]); assert(!source_ready_diagnostic_decode(bytes, used, nonce, &data)); checks++; }
    bytes[0] = 'x'; assert(!source_ready_diagnostic_decode(bytes, used, nonce, &data)); checks++;
    uint32_t map[3]; const char *maps[] = { "0 0 1\n", "         0       1001          1\n", "0\t4294967295\t4294967295\n" };
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) { assert(source_diagnostic_map((const unsigned char *)maps[i], strlen(maps[i]), map)); checks++; }
    const char *badmaps[] = { "", "0 1 1", "0 1 1\n1 2 1\n", "0 4294967296 1\n", "0 -1 1\n", "0 1 1\n\n", "0\n1\n1\n", "0 1 1 0\n" };
    for (size_t i = 0; i < sizeof(badmaps) / sizeof(badmaps[0]); i++) { assert(!source_diagnostic_map((const unsigned char *)badmaps[i], strlen(badmaps[i]), map)); checks++; }
    struct cliq_worker_packet request = cliq_packet(CLIQ_SOURCE_CREATE_BLOCKED); digest(request.nonce, 'a'); request.reservation_uid = geteuid(); request.max_output_bytes = 65536;
    int fd = memfd_create("cliq-owned-source-diagnostic", MFD_CLOEXEC); assert(fd >= 0); checks++;
    source_ready_diagnostic_write(fd, &request, 3);
    assert(source_ready_diagnostic_read(fd, &request, &data) && data.stage == 3 && data.uid == geteuid() && data.gid == getegid() && data.original_uid == geteuid()); checks++;
    assert(ftruncate(fd, (off_t)request.max_output_bytes) == 0 && source_ready_diagnostic_read(fd, &request, &data)); checks++;
    struct cliq_worker_packet changed = request; changed.nonce[0] = 'b'; assert(!source_ready_diagnostic_read(fd, &changed, &data)); checks++;
    changed = request; changed.reservation_uid++; assert(!source_ready_diagnostic_read(fd, &changed, &data)); checks++;
    changed = request; changed.max_output_bytes--; assert(!source_ready_diagnostic_read(fd, &changed, &data)); checks++;
    assert(pwrite(fd, "X", 1, 300) == 1 && !source_ready_diagnostic_read(fd, &request, &data)); checks++;
    assert(close(fd) == 0); checks++;
    printf("{\"format\":\"cliq-source-ready-diagnostic-data-v1\",\"checks\":%u,\"actualRunQualified\":false}\n", checks);
    return 0;
}
