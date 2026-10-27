#ifndef CLIQ_DEPENDENCY_BROKER_INPUT_H
#define CLIQ_DEPENDENCY_BROKER_INPUT_H
#include "dependency-descriptors.h"
#include "dependency-owner-bridge.h"
#define CLIQ_DEPENDENCY_MAX_TARGETS 128u
#define CLIQ_DEPENDENCY_MAX_PINS 64u
#define CLIQ_DEPENDENCY_MAX_TRANSFER UINT64_C(21474836480)
struct cliq_dependency_target {
    char ref[65], host[254], server_name[254], base_path[4097], tls_policy_digest[65];
    uint32_t port, pin_count; unsigned char pins[CLIQ_DEPENDENCY_MAX_PINS][32];
};
struct cliq_dependency_configuration {
    uint32_t package_count, target_count; uint64_t package_descriptor_bytes, max_package_bytes, max_transfer_bytes, run_remaining_ms;
    char plan_digest[65], launch_ref[65], descriptor_digest[65], trust_digest[65];
    struct cliq_dependency_target targets[CLIQ_DEPENDENCY_MAX_TARGETS];
};
static inline bool cliq_dependency_u64(struct cliq_dependency_json *json, uint64_t *value) {
    if (json->offset >= json->size || json->bytes[json->offset] < '0' || json->bytes[json->offset] > '9') return false;
    uint64_t result = 0; size_t first = json->offset;
    while (json->offset < json->size && json->bytes[json->offset] >= '0' && json->bytes[json->offset] <= '9') {
        unsigned digit = json->bytes[json->offset++] - '0'; if (result > (UINT64_MAX - digit) / 10) return false;
        result = result * 10 + digit;
    }
    if (json->offset - first > 1 && json->bytes[first] == '0') return false;
    *value = result; return true;
}
static inline bool cliq_dependency_text(struct cliq_dependency_json *json, char *output, size_t capacity, bool digest) {
    struct cliq_dependency_string value;
    if (!cliq_dependency_string_read(json,&value) || value.size >= capacity || (digest && !cliq_dependency_hex_string(value))) return false;
    memcpy(output,value.data,value.size); output[value.size] = 0; return true;
}
static inline bool cliq_dependency_host(const char *value) {
    size_t size = strlen(value); if (!size || size > 253 || value[0] == '.' || value[size - 1] == '.' ||
        strspn(value,"abcdefghijklmnopqrstuvwxyz0123456789.-") != size) return false;
    const char *cursor = value;
    for (;;) {
        const char *end = strchr(cursor,'.'); size_t count = end ? (size_t)(end - cursor) : strlen(cursor);
        if (!count || count > 63 || cursor[0] == '-' || cursor[count - 1] == '-') return false;
        if (!end) return true;
        cursor = end + 1;
    }
}
static inline bool cliq_dependency_target_read(struct cliq_dependency_json *json, struct cliq_dependency_target *target) {
    if (!cliq_dependency_literal(json,"{\"basePath\":") || !cliq_dependency_text(json,target->base_path,sizeof(target->base_path),false) ||
        !cliq_dependency_literal(json,",\"endpointRegistrationRef\":") || !cliq_dependency_text(json,target->ref,sizeof(target->ref),true) ||
        !cliq_dependency_literal(json,",\"hostAscii\":") || !cliq_dependency_text(json,target->host,sizeof(target->host),false) ||
        !cliq_dependency_host(target->host) || !cliq_dependency_literal(json,",\"port\":") || !cliq_dependency_number(json,&target->port) || !target->port || target->port > 65535 ||
        !cliq_dependency_literal(json,",\"serverNameAscii\":") || !cliq_dependency_text(json,target->server_name,sizeof(target->server_name),false) ||
        !cliq_dependency_host(target->server_name) || !cliq_dependency_literal(json,",\"spkiSha256Pins\":[")) return false;
    uint32_t base_size=(uint32_t)strlen(target->base_path);
    if(base_size>1 && target->base_path[base_size-1]=='/')base_size--;
    struct cliq_dependency_string base = {(const unsigned char*)target->base_path,base_size};
    if (strcmp(target->base_path,"/") && !cliq_dependency_path_string(base)) return false;
    char previous[65] = {0};
    for (;;) {
        char text[65]; if (target->pin_count >= CLIQ_DEPENDENCY_MAX_PINS || !cliq_dependency_text(json,text,sizeof(text),true) ||
            (target->pin_count && strcmp(previous,text) >= 0)) return false;
        for (size_t index = 0; index < 32; index++) {
            const char *alphabet="0123456789abcdef";
            target->pins[target->pin_count][index]=(unsigned char)((strchr(alphabet,text[index*2])-alphabet)*16+(strchr(alphabet,text[index*2+1])-alphabet));
        }
        memcpy(previous,text,sizeof(previous)); target->pin_count++;
        if (json->offset < json->size && json->bytes[json->offset] == ',') { json->offset++; continue; } break;
    }
    return target->pin_count && cliq_dependency_literal(json,"],\"tlsPolicyDigest\":") &&
        cliq_dependency_text(json,target->tls_policy_digest,sizeof(target->tls_policy_digest),true) && cliq_dependency_literal(json,"}");
}
static inline bool cliq_dependency_configuration_read(const unsigned char *bytes,size_t size,struct cliq_dependency_configuration *config) {
    if (!bytes || !size || size > 1048576 || !config) return false;
    memset(config,0,sizeof(*config)); struct cliq_dependency_json json={bytes,size,0}; uint32_t schema;
    if (!cliq_dependency_literal(&json,"{\"descriptorSequenceDigest\":") || !cliq_dependency_text(&json,config->descriptor_digest,65,true) ||
        !cliq_dependency_literal(&json,",\"maxPackageBytes\":") || !cliq_dependency_u64(&json,&config->max_package_bytes) ||
        !config->max_package_bytes || config->max_package_bytes > 67108864 ||
        !cliq_dependency_literal(&json,",\"maxTransferBytes\":") || !cliq_dependency_u64(&json,&config->max_transfer_bytes) ||
        !config->max_transfer_bytes || config->max_transfer_bytes > CLIQ_DEPENDENCY_MAX_TRANSFER ||
        !cliq_dependency_literal(&json,",\"packageCount\":") || !cliq_dependency_number(&json,&config->package_count) || config->package_count > CLIQ_DEPENDENCY_DESCRIPTOR_MAX_COUNT ||
        !cliq_dependency_literal(&json,",\"packageDescriptorBytes\":") || !cliq_dependency_u64(&json,&config->package_descriptor_bytes) || config->package_descriptor_bytes > CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES ||
        !cliq_dependency_literal(&json,",\"planDigest\":") || !cliq_dependency_text(&json,config->plan_digest,65,true) ||
        !cliq_dependency_literal(&json,",\"runRemainingMs\":") || !cliq_dependency_u64(&json,&config->run_remaining_ms) ||
        !config->run_remaining_ms || config->run_remaining_ms > UINT64_C(9007199254740991) ||
        !cliq_dependency_literal(&json,",\"sandboxLaunchSpecRef\":") || !cliq_dependency_text(&json,config->launch_ref,65,true) ||
        !cliq_dependency_literal(&json,",\"schemaVersion\":") || !cliq_dependency_number(&json,&schema) || schema != 1 ||
        !cliq_dependency_literal(&json,",\"targets\":[")) return false;
    for (;;) {
        if (config->target_count >= CLIQ_DEPENDENCY_MAX_TARGETS || !cliq_dependency_target_read(&json,&config->targets[config->target_count])) return false;
        for (uint32_t previous=0;previous<config->target_count;previous++) if (!strcmp(config->targets[previous].ref,config->targets[config->target_count].ref)) return false;
        config->target_count++;
        if (json.offset < json.size && json.bytes[json.offset] == ',') { json.offset++; continue; } break;
    }
    if (!cliq_dependency_literal(&json,"],\"transport\":\"public_integrity_get_v1\",\"trustStoreDigest\":") ||
        !cliq_dependency_text(&json,config->trust_digest,65,true) || !cliq_dependency_literal(&json,"}") || json.offset != size) return false;
    return true;
}
static inline bool cliq_dependency_binding_read(const unsigned char *bytes,size_t size,struct cliq_dependency_binding *binding) {
    if (!bytes || !size || size > 8192 || !binding) return false;
    memset(binding,0,sizeof(*binding)); struct cliq_dependency_json json={bytes,size,0};
    if (!cliq_dependency_literal(&json,"{\"attempt\":") || !cliq_dependency_u64(&json,&binding->attempt) ||
        !cliq_dependency_literal(&json,",\"brokerFenceTokenDigest\":") || !cliq_dependency_text(&json,binding->token_digest,65,true) ||
        !cliq_dependency_literal(&json,",\"dispatchId\":") || !cliq_dependency_text(&json,binding->dispatch,sizeof(binding->dispatch),false) ||
        !cliq_dependency_literal(&json,",\"dispatchJournalSeq\":") || !cliq_dependency_u64(&json,&binding->sequence) || !binding->sequence ||
        !cliq_dependency_literal(&json,",\"grantRef\":") || !cliq_dependency_text(&json,binding->grant_ref,65,true) ||
        !cliq_dependency_literal(&json,",\"leaseEpoch\":") || !cliq_dependency_u64(&json,&binding->lease_epoch) || !binding->lease_epoch ||
        !cliq_dependency_literal(&json,",\"opId\":") || !cliq_dependency_text(&json,binding->op,sizeof(binding->op),false) ||
        !cliq_dependency_literal(&json,",\"requestDigest\":") || !cliq_dependency_text(&json,binding->request_digest,65,true) ||
        !cliq_dependency_literal(&json,",\"requestRef\":") || !cliq_dependency_text(&json,binding->request_ref,65,true) ||
        !cliq_dependency_literal(&json,",\"runId\":") || !cliq_dependency_text(&json,binding->run,sizeof(binding->run),false) ||
        !cliq_dependency_literal(&json,",\"stateOwnerEpoch\":") || !cliq_dependency_u64(&json,&binding->owner_epoch) || !binding->owner_epoch ||
        !cliq_dependency_literal(&json,",\"supervisorInstanceId\":") || !cliq_dependency_text(&json,binding->supervisor,sizeof(binding->supervisor),false) ||
        !cliq_dependency_literal(&json,",\"targetDigest\":") || !cliq_dependency_text(&json,binding->target_digest,65,true) ||
        !cliq_dependency_literal(&json,",\"targetRef\":") || !cliq_dependency_text(&json,binding->target_ref,65,true) ||
        !cliq_dependency_literal(&json,"}") || json.offset != size) return false;
    const char *ids[]={binding->run,binding->op,binding->dispatch,binding->supervisor};
    for (size_t index=0;index<4;index++) if (strspn(ids[index],"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-") != strlen(ids[index])) return false;
    return binding->attempt <= UINT64_C(9007199254740991) && binding->sequence <= UINT64_C(9007199254740991) &&
        binding->owner_epoch <= UINT64_C(9007199254740991) && binding->lease_epoch <= UINT64_C(9007199254740991);
}
#endif
