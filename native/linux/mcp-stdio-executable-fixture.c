/* Synthetic parser data only. This fixture never opens a native module,
 * creates a capability, executes an ELF, or claims installation authority. */
#include "mcp-stdio-executable.h"
#include <assert.h>
static void put16(unsigned char *bytes, uint16_t value) {
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
}
static void put64(unsigned char *bytes, uint64_t value) {
    for (unsigned i = 0; i < 8; i++)
        bytes[i] = (unsigned char)(value >> (i * 8));
}
static void fixture(unsigned char bytes[512]) {
    memset(bytes, 0, 512);
    static const unsigned char identity[] = {0x7f, 0x45, 0x4c, 0x46, 2, 1, 1};
    memcpy(bytes, identity, sizeof(identity));
    put16(bytes + 16, 2); put16(bytes + 18, 62); bytes[20] = 1;
    put64(bytes + 24, UINT64_C(0x400080)); put64(bytes + 32, 64);
    put16(bytes + 52, 64); put16(bytes + 54, 56); put16(bytes + 56, 1);
    bytes[64] = 1; bytes[68] = 5; put64(bytes + 80, UINT64_C(0x400000));
    put64(bytes + 96, 512); put64(bytes + 104, 512); put64(bytes + 112, 4096);
}
int main(void) {
    unsigned char bytes[512];
    fixture(bytes); assert(cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    for (unsigned kind = 2; kind <= 3; kind++) {
        fixture(bytes); bytes[64] = (unsigned char)kind;
        assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    }
    fixture(bytes); put16(bytes + 16, 3); assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); put64(bytes + 32, UINT64_MAX); assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); put64(bytes + 96, 513); assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); put64(bytes + 104, 511); assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); bytes[68] = 4; assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); put64(bytes + 112, 3); assert(!cliq_mcp_stdio_static_elf(bytes, sizeof(bytes)));
    fixture(bytes); assert(!cliq_mcp_stdio_static_elf(bytes, 100));
    assert(!cliq_mcp_stdio_static_elf(NULL, 0));
    return 0;
}
