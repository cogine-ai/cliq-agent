#ifndef CLIQ_MCP_STDIO_EXECUTABLE_H
#define CLIQ_MCP_STDIO_EXECUTABLE_H
/* Pure bytes only. Actual callers must own, completely hash and independently
 * retain the original sealed descriptor; this result is no image authority. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define CLIQ_MCP_STDIO_SERVER_PATH "/runtime/mcp-server"
#define CLIQ_MCP_STDIO_EXECUTABLE_CAP UINT64_C(268435456)
static inline uint16_t cliq_mcp_stdio_u16(const unsigned char *bytes) {
    return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8);
}
static inline uint32_t cliq_mcp_stdio_u32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static inline uint64_t cliq_mcp_stdio_u64(const unsigned char *bytes) {
    return (uint64_t)cliq_mcp_stdio_u32(bytes) | (uint64_t)cliq_mcp_stdio_u32(bytes + 4) << 32;
}
static inline bool cliq_mcp_stdio_static_elf(const unsigned char *bytes, size_t size) {
    static const unsigned char identity[] = {0x7f, 0x45, 0x4c, 0x46, 2, 1, 1};
    if (!bytes || size < 64 || (uint64_t)size > CLIQ_MCP_STDIO_EXECUTABLE_CAP || memcmp(bytes, identity, sizeof(identity)) ||
        (bytes[7] != 0 && bytes[7] != 3) || bytes[8] || cliq_mcp_stdio_u16(bytes + 16) != 2 || cliq_mcp_stdio_u16(bytes + 18) != 62 ||
        cliq_mcp_stdio_u32(bytes + 20) != 1 || cliq_mcp_stdio_u32(bytes + 48) || cliq_mcp_stdio_u16(bytes + 52) != 64 || cliq_mcp_stdio_u16(bytes + 54) != 56)
        return false;
    uint64_t entry = cliq_mcp_stdio_u64(bytes + 24), offset = cliq_mcp_stdio_u64(bytes + 32);
    uint16_t count = cliq_mcp_stdio_u16(bytes + 56);
    if (!count || offset < 64 || offset > size || (uint64_t)count * 56 > (uint64_t)size - offset)
        return false;
    bool executable_entry = false;
    for (uint16_t i = 0; i < count; i++) {
        const unsigned char *header = bytes + (size_t)offset + (size_t)i * 56;
        uint32_t kind = cliq_mcp_stdio_u32(header), flags = cliq_mcp_stdio_u32(header + 4);
        if (kind == 2 || kind == 3)
            return false;
        if (kind != 1)
            continue;
        uint64_t file = cliq_mcp_stdio_u64(header + 8), address = cliq_mcp_stdio_u64(header + 16);
        uint64_t file_size = cliq_mcp_stdio_u64(header + 32), memory_size = cliq_mcp_stdio_u64(header + 40), align = cliq_mcp_stdio_u64(header + 48);
        if (file_size > memory_size || file > size || file_size > (uint64_t)size - file || memory_size > UINT64_MAX - address ||
            (align > 1 && ((align & (align - 1)) || file % align != address % align)))
            return false;
        if ((flags & 1) && entry >= address && entry - address < file_size)
            executable_entry = true;
    }
    return executable_entry;
}
#endif
