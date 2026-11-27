#ifndef CLIQ_DEPENDENCY_INPUT_RECORD_H
#define CLIQ_DEPENDENCY_INPUT_RECORD_H
#include <stdio.h>
#include <inttypes.h>
#include "dependency-descriptors.h"
/* Exact private FD4 record, rendered only from previously validated fixed
 * ASCII descriptors and the native full-body SHA256/byte count. */
static inline int dependency_input_record(char *bytes,size_t capacity,const struct cliq_dependency_descriptor *descriptor,uint64_t count,const char *digest) {
    return snprintf(bytes,capacity,"{\"blobBytes\":%" PRIu64 ",\"blobSha256\":\"%s\",\"canonicalPackagePath\":\"%.*s\",\"endpointRegistrationRef\":\"%.*s\",\"integrityAlgorithm\":\"%.*s\",\"integrityDigest\":\"%.*s\",\"packageName\":\"%.*s\",\"packageVersion\":\"%.*s\"}",count,digest,
        (int)descriptor->path.size,(const char*)descriptor->path.data,(int)descriptor->endpoint.size,(const char*)descriptor->endpoint.data,
        (int)descriptor->algorithm.size,(const char*)descriptor->algorithm.data,(int)descriptor->integrity.size,(const char*)descriptor->integrity.data,
        (int)descriptor->name.size,(const char*)descriptor->name.data,(int)descriptor->version.size,(const char*)descriptor->version.data);
}
struct cliq_dependency_package_input_record {
    struct cliq_dependency_descriptor descriptor;uint64_t blob_bytes;char blob_sha256[65];
    const unsigned char *descriptor_members;uint32_t descriptor_member_bytes;
};
/* Returned descriptor string spans belong to these exact record bytes. The
 * owning scope retains them until that package's complete stage joins. */
static inline bool cliq_dependency_input_record_read(const unsigned char *bytes,size_t size,struct cliq_dependency_package_input_record *record) {
    if(!bytes || !size || size>12288 || !record)return false;
    struct cliq_dependency_json json={bytes,size,0};struct cliq_dependency_string digest;uint32_t count;
    memset(record,0,sizeof(*record));
    if(!cliq_dependency_literal(&json,"{\"blobBytes\":") || !cliq_dependency_number(&json,&count) || !count || count>67108864 ||
        !cliq_dependency_literal(&json,",\"blobSha256\":") || !cliq_dependency_string_read(&json,&digest) || !cliq_dependency_hex_string(digest) ||
        !cliq_dependency_literal(&json,","))return false;
    size_t first=json.offset;
    if(!cliq_dependency_descriptor_members_read(&json,&record->descriptor) || json.offset!=size)return false;
    record->blob_bytes=count;memcpy(record->blob_sha256,digest.data,64);record->blob_sha256[64]=0;
    record->descriptor_members=bytes+first;record->descriptor_member_bytes=(uint32_t)(size-first);return true;
}
static inline void cliq_dependency_input_record_hash(struct sha256_context *hash,const struct cliq_dependency_package_input_record *record) {
    uint32_t length=record->descriptor_member_bytes+1;
    unsigned char prefix[4]={(unsigned char)length,(unsigned char)(length>>8),(unsigned char)(length>>16),(unsigned char)(length>>24)};
    sha256_update(hash,prefix,4);sha256_update(hash,(const unsigned char*)"{",1);sha256_update(hash,record->descriptor_members,record->descriptor_member_bytes);
}
#endif
