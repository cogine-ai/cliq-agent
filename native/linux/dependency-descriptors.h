#ifndef CLIQ_DEPENDENCY_DESCRIPTORS_H
#define CLIQ_DEPENDENCY_DESCRIPTORS_H
/* Fixed canonical data ingress. No N-API property access, arbitrary URL or
 * network operation occurs while the original descriptor sequence is frozen. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "worker-sha256.h"
#define CLIQ_DEPENDENCY_DESCRIPTOR_MAX_COUNT 200000u
#define CLIQ_DEPENDENCY_DESCRIPTOR_PAGE_COUNT 32u
#define CLIQ_DEPENDENCY_DESCRIPTOR_PAGE_BYTES 65536u
#define CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES 67108864u
struct cliq_dependency_string { const unsigned char *data; uint32_t size; };
struct cliq_dependency_descriptor {
    struct cliq_dependency_string name, version, endpoint, path, algorithm, integrity;
};
struct cliq_dependency_descriptor_page {
    struct cliq_dependency_descriptor_page *next;
    uint32_t first, count, byte_count;
    struct cliq_dependency_descriptor values[CLIQ_DEPENDENCY_DESCRIPTOR_PAGE_COUNT];
    unsigned char bytes[];
};
struct cliq_dependency_descriptors {
    uint32_t expected_count, count, page_count; uint64_t owned_bytes, sequence_bytes;
    char expected_digest[65]; struct sha256_context hash;
    struct cliq_dependency_descriptor_page *first, *last;
    bool initialized, sealed, failed;
};
struct cliq_dependency_json { const unsigned char *bytes; size_t size, offset; };
static inline bool cliq_dependency_literal(struct cliq_dependency_json *json, const char *text) {
    size_t count = strlen(text);
    if (json->offset > json->size || count > json->size - json->offset || memcmp(json->bytes + json->offset, text, count)) return false;
    json->offset += count; return true;
}
static inline bool cliq_dependency_number(struct cliq_dependency_json *json, uint32_t *value) {
    if (json->offset >= json->size || json->bytes[json->offset] < '0' || json->bytes[json->offset] > '9') return false;
    uint64_t result = 0; size_t first = json->offset;
    while (json->offset < json->size && json->bytes[json->offset] >= '0' && json->bytes[json->offset] <= '9') {
        result = result * 10 + json->bytes[json->offset++] - '0'; if (result > UINT32_MAX) return false;
    }
    if (json->offset - first > 1 && json->bytes[first] == '0') return false;
    *value = (uint32_t)result; return true;
}
static inline bool cliq_dependency_string_read(struct cliq_dependency_json *json, struct cliq_dependency_string *value) {
    if (!cliq_dependency_literal(json, "\"")) return false;
    size_t first = json->offset;
    while (json->offset < json->size && json->bytes[json->offset] != '"') {
        unsigned char byte = json->bytes[json->offset++];
        if (byte < 0x21 || byte > 0x7e || byte == '\\' || json->offset - first > 4096) return false;
    }
    if (json->offset == first || !cliq_dependency_literal(json, "\"")) return false;
    value->data = json->bytes + first; value->size = (uint32_t)(json->offset - first - 1); return true;
}
static inline int cliq_dependency_string_compare(struct cliq_dependency_string left, struct cliq_dependency_string right) {
    size_t size = left.size < right.size ? left.size : right.size;
    int comparison = memcmp(left.data, right.data, size);
    return comparison ? comparison : left.size < right.size ? -1 : left.size > right.size ? 1 : 0;
}
static inline bool cliq_dependency_string_equal(struct cliq_dependency_string value, const char *text) {
    return value.size == strlen(text) && !memcmp(value.data, text, value.size);
}
static inline bool cliq_dependency_characters(struct cliq_dependency_string value, const char *alphabet) {
    for (uint32_t index = 0; index < value.size; index++) if (!strchr(alphabet, value.data[index])) return false;
    return true;
}
static inline bool cliq_dependency_hex_string(struct cliq_dependency_string value) {
    return value.size == 64 && cliq_dependency_characters(value, "0123456789abcdef");
}
static inline bool cliq_dependency_path_string(struct cliq_dependency_string value) {
    if (value.size < 2 || value.data[0] != '/' || !cliq_dependency_characters(value, "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.@+-")) return false;
    for (uint32_t start = 1, index = 1; index <= value.size; index++) {
        if (index != value.size && value.data[index] != '/') continue;
        uint32_t size = index - start;
        if (!size || (size == 1 && value.data[start] == '.') || (size == 2 && value.data[start] == '.' && value.data[start + 1] == '.')) return false;
        start = index + 1;
    }
    return true;
}
static inline bool cliq_dependency_name_string(struct cliq_dependency_string value) {
    if (value.size > 214) return false;
    uint32_t first = value.data[0] == '@' ? 1 : 0; unsigned separators = 0;
    for (uint32_t index = first; index < value.size; index++) {
        unsigned char byte = value.data[index];
        if (byte == '/') { if (first != 1 || separators++ || index == first || index + 1 == value.size) return false; first = index + 1; continue; }
        if (!strchr("abcdefghijklmnopqrstuvwxyz0123456789._-", byte) || (index == first && !strchr("abcdefghijklmnopqrstuvwxyz0123456789", byte))) return false;
    }
    return value.data[0] == '@' ? separators == 1 : separators == 0;
}
static inline bool cliq_dependency_integrity_string(struct cliq_dependency_string algorithm, struct cliq_dependency_string digest) {
    bool sha256 = cliq_dependency_string_equal(algorithm, "sha256"), sha512 = cliq_dependency_string_equal(algorithm, "sha512");
    if ((!sha256 && !sha512) || digest.size != (sha256 ? 44u : 88u)) return false;
    size_t padding = sha256 ? 1 : 2;
    for (size_t index = 0; index < digest.size - padding; index++) if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", digest.data[index])) return false;
    for (size_t index = digest.size - padding; index < digest.size; index++) if (digest.data[index] != '=') return false;
    const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *last = strchr(alphabet, digest.data[digest.size - padding - 1]);
    return last && ((last - alphabet) & (sha256 ? 3 : 15)) == 0;
}
static inline int cliq_dependency_descriptor_compare(const struct cliq_dependency_descriptor *a, const struct cliq_dependency_descriptor *b) {
    const struct cliq_dependency_string aa[] = {a->name,a->version,a->endpoint,a->path,a->algorithm,a->integrity};
    const struct cliq_dependency_string bb[] = {b->name,b->version,b->endpoint,b->path,b->algorithm,b->integrity};
    for (size_t index = 0; index < 6; index++) { int result = cliq_dependency_string_compare(aa[index], bb[index]); if (result) return result; }
    return 0;
}
static inline bool cliq_dependency_descriptor_members_read(struct cliq_dependency_json *json, struct cliq_dependency_descriptor *value) {
    return cliq_dependency_literal(json, "\"canonicalPackagePath\":") && cliq_dependency_string_read(json, &value->path) &&
        cliq_dependency_literal(json, ",\"endpointRegistrationRef\":") && cliq_dependency_string_read(json, &value->endpoint) &&
        cliq_dependency_literal(json, ",\"integrityAlgorithm\":") && cliq_dependency_string_read(json, &value->algorithm) &&
        cliq_dependency_literal(json, ",\"integrityDigest\":") && cliq_dependency_string_read(json, &value->integrity) &&
        cliq_dependency_literal(json, ",\"packageName\":") && cliq_dependency_string_read(json, &value->name) &&
        cliq_dependency_literal(json, ",\"packageVersion\":") && cliq_dependency_string_read(json, &value->version) &&
        cliq_dependency_literal(json, "}") && cliq_dependency_path_string(value->path) && cliq_dependency_hex_string(value->endpoint) &&
        cliq_dependency_name_string(value->name) && cliq_dependency_characters(value->version, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.+-") &&
        cliq_dependency_integrity_string(value->algorithm, value->integrity);
}
static inline bool cliq_dependency_descriptor_read(struct cliq_dependency_json *json, struct cliq_dependency_descriptor *value) {
    return cliq_dependency_literal(json,"{") && cliq_dependency_descriptor_members_read(json,value);
}
static inline bool cliq_dependency_descriptors_initialize(struct cliq_dependency_descriptors *plan, uint32_t count, const char *digest) {
    if (!plan || count > CLIQ_DEPENDENCY_DESCRIPTOR_MAX_COUNT || !digest || strlen(digest) != 64 || strspn(digest, "0123456789abcdef") != 64) return false;
    memset(plan, 0, sizeof(*plan)); plan->expected_count = count; memcpy(plan->expected_digest, digest, 65);
    sha256_init(&plan->hash); static const unsigned char domain[] = "cliq-dependency-package-descriptors-v1\0";
    sha256_update(&plan->hash, domain, sizeof(domain) - 1); plan->initialized = true; return true;
}
static inline bool cliq_dependency_descriptors_page(struct cliq_dependency_descriptors *plan, const unsigned char *bytes, size_t size) {
    if (!plan || !plan->initialized) return false;
    if (plan->sealed || plan->failed || !bytes || !size || size > CLIQ_DEPENDENCY_DESCRIPTOR_PAGE_BYTES || plan->count >= plan->expected_count) { plan->failed = true; return false; }
    size_t allocation = sizeof(struct cliq_dependency_descriptor_page) + size;
    if (allocation > CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES - plan->owned_bytes) { plan->failed = true; return false; }
    struct cliq_dependency_descriptor_page *page = calloc(1, allocation);
    if (!page) { plan->failed = true; return false; }
    memcpy(page->bytes, bytes, size); page->byte_count = (uint32_t)size;
    struct cliq_dependency_json json = {page->bytes,size,0}; struct sha256_context hash = plan->hash;
    bool valid = cliq_dependency_literal(&json, "{\"descriptors\":["); uint64_t sequence_bytes = plan->sequence_bytes;
    const struct cliq_dependency_descriptor *previous = plan->last ? &plan->last->values[plan->last->count - 1] : NULL;
    while (valid) {
        if (page->count >= CLIQ_DEPENDENCY_DESCRIPTOR_PAGE_COUNT || plan->count + page->count >= plan->expected_count) { valid = false; break; }
        size_t start = json.offset; struct cliq_dependency_descriptor *value = &page->values[page->count];
        valid = cliq_dependency_descriptor_read(&json, value) && (!previous || cliq_dependency_descriptor_compare(previous, value) < 0);
        if (!valid) break;
        size_t length = json.offset - start; unsigned char prefix[4] = {(unsigned char)length,(unsigned char)(length >> 8),(unsigned char)(length >> 16),(unsigned char)(length >> 24)};
        sha256_update(&hash, prefix, 4); sha256_update(&hash, page->bytes + start, length); sequence_bytes += 4 + length;
        page->count++; previous = value;
        if (json.offset < json.size && json.bytes[json.offset] == ',') { json.offset++; continue; }
        break;
    }
    uint32_t schema = 0;
    valid = valid && page->count && cliq_dependency_literal(&json, "],\"firstIndex\":") && cliq_dependency_number(&json, &page->first) &&
        page->first == plan->count && cliq_dependency_literal(&json, ",\"schemaVersion\":") && cliq_dependency_number(&json, &schema) && schema == 1 &&
        cliq_dependency_literal(&json, "}") && json.offset == json.size && sequence_bytes <= CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES;
    if (!valid) { free(page); plan->failed = true; return false; }
    if (plan->last) plan->last->next = page; else plan->first = page;
    plan->last = page; plan->count += page->count; plan->page_count++; plan->owned_bytes += allocation; plan->sequence_bytes = sequence_bytes; plan->hash = hash;
    return true;
}
static inline bool cliq_dependency_descriptors_seal(struct cliq_dependency_descriptors *plan) {
    if (!plan || !plan->initialized || plan->failed || plan->sealed || plan->count != plan->expected_count) return false;
    unsigned char digest[32]; char text[65]; struct sha256_context hash = plan->hash; sha256_final(&hash,digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < 32; index++) { text[index * 2] = hex[digest[index] >> 4]; text[index * 2 + 1] = hex[digest[index] & 15]; } text[64] = 0;
    if (memcmp(text, plan->expected_digest, sizeof(text))) { plan->failed = true; return false; }
    plan->sealed = true; return true;
}
static inline const struct cliq_dependency_descriptor *cliq_dependency_descriptors_at(const struct cliq_dependency_descriptors *plan, uint32_t index) {
    if (!plan || !plan->sealed || plan->failed || index >= plan->count) return NULL;
    for (const struct cliq_dependency_descriptor_page *page = plan->first; page; page = page->next)
        if (index >= page->first && index - page->first < page->count) return &page->values[index - page->first];
    return NULL;
}
static inline void cliq_dependency_descriptors_dispose(struct cliq_dependency_descriptors *plan) {
    if (!plan) return;
    struct cliq_dependency_descriptor_page *page = plan->first;
    while (page) { struct cliq_dependency_descriptor_page *next = page->next; free(page); page = next; }
    memset(plan,0,sizeof(*plan));
}
#endif
