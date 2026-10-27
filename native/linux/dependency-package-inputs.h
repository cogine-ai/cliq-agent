#ifndef CLIQ_DEPENDENCY_PACKAGE_INPUTS_H
#define CLIQ_DEPENDENCY_PACKAGE_INPUTS_H
#include <inttypes.h>
/* The original native GET owner writes this stream from its own frozen
 * descriptor and actual verified output. No JavaScript metadata is accepted. */
#include "dependency-input-record.h"
static bool dependency_input_reserve_page(struct dependency_broker *broker,const struct cliq_dependency_descriptor_page *page) {
    static const char maximum_digest[]="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";char bytes[12288];
    uint64_t reserve=broker->inputs_reserved;
    for(uint32_t index=0;index<page->count;index++){
        int size=dependency_input_record(bytes,sizeof(bytes),&page->values[index],broker->config->max_package_bytes,maximum_digest);
        if(size<1 || (size_t)size>=sizeof(bytes))return false;reserve+=4+(uint32_t)size;
    }
    if(sizeof(*broker)+sizeof(*broker->config)+broker->descriptors.owned_bytes+reserve>CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES)return false;
    broker->inputs_reserved=reserve;return true;
}
static bool dependency_input_append(struct dependency_broker *broker,const struct dependency_package *package) {
    char bytes[12288];int length=dependency_input_record(bytes,sizeof(bytes),cliq_dependency_descriptors_at(&broker->descriptors,package->index),package->data.byte_count,package->data.digest);
    if(broker->inputs_failed || broker->inputs_sealed || broker->inputs_fd<0 || package->index!=broker->inputs_count || length<1 || (size_t)length>=sizeof(bytes) ||
        broker->inputs_bytes+4+(uint32_t)length>broker->inputs_reserved){broker->inputs_failed=true;return dependency_fail(broker,"package_metadata_refused");}
    unsigned char prefix[4]={(unsigned char)length,(unsigned char)(length>>8),(unsigned char)(length>>16),(unsigned char)(length>>24)};
    const unsigned char *parts[]={prefix,(const unsigned char*)bytes};size_t sizes[]={4,(size_t)length};
    for(size_t part=0;part<2;part++)for(size_t offset=0;offset<sizes[part];){
        ssize_t count=write(broker->inputs_fd,parts[part]+offset,sizes[part]-offset);
        if(count<0 && errno==EINTR)continue;if(count<=0){broker->inputs_failed=true;return dependency_fail(broker,"package_metadata_storage_unavailable");}offset+=(size_t)count;
    }
    sha256_update(&broker->inputs_hash,prefix,4);sha256_update(&broker->inputs_hash,(const unsigned char*)bytes,(size_t)length);
    broker->inputs_bytes+=4+(uint32_t)length;broker->inputs_count++;return true;
}
static bool dependency_inputs_live(struct dependency_broker *broker) {
    struct timespec now;
    return !atomic_load(&broker->owner.closing) && !atomic_load(&broker->owner.unsafe) && clock_gettime(CLOCK_MONOTONIC,&now)==0 &&
        (now.tv_sec<broker->outer_deadline.tv_sec || (now.tv_sec==broker->outer_deadline.tv_sec && now.tv_nsec<broker->outer_deadline.tv_nsec));
}
static bool dependency_inputs_seal(struct dependency_broker *broker) {
    if(broker->inputs_failed || broker->inputs_sealed || broker->inputs_fd<0 || broker->inputs_count!=broker->owner.package_count || !dependency_inputs_live(broker))return dependency_fail(broker,"package_metadata_refused");
    unsigned char bytes[65536],expected[32],actual[32];uint64_t offset=0;struct sha256_context hash,original=broker->inputs_hash;sha256_init(&hash);sha256_final(&original,expected);
    struct stat before,after;
    if(fstat(broker->inputs_fd,&before) || before.st_size<0 || (uint64_t)before.st_size!=broker->inputs_bytes)return dependency_fail(broker,"package_metadata_refused");
    while(offset<broker->inputs_bytes){if(!dependency_inputs_live(broker))return dependency_fail(broker,"cancelled_or_expired");
        size_t wanted=broker->inputs_bytes-offset>sizeof(bytes)?sizeof(bytes):(size_t)(broker->inputs_bytes-offset);ssize_t count;
        do{count=pread(broker->inputs_fd,bytes,wanted,(off_t)offset);}while(count<0 && errno==EINTR && dependency_inputs_live(broker));
        if(count<=0 || (size_t)count>wanted)return dependency_fail(broker,"package_metadata_refused");sha256_update(&hash,bytes,(size_t)count);offset+=(uint64_t)count;
    }
    ssize_t tail;do{tail=pread(broker->inputs_fd,bytes,1,(off_t)offset);}while(tail<0 && errno==EINTR && dependency_inputs_live(broker));
    sha256_final(&hash,actual);
    if(tail!=0 || memcmp(expected,actual,32) || fstat(broker->inputs_fd,&after) || !cliq_dependency_data_same(&before,&after) ||
        fchmod(broker->inputs_fd,0400) || fcntl(broker->inputs_fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))return dependency_fail(broker,"package_metadata_refused");
    if(fstat(broker->inputs_fd,&before))return dependency_fail(broker,"package_metadata_refused");
    char path[64];int size=snprintf(path,sizeof(path),"/proc/self/fd/%d",broker->inputs_fd);
    if(size<1 || (size_t)size>=sizeof(path))return dependency_fail(broker,"package_metadata_refused");
    broker->inputs_read_fd=open(path,O_RDONLY|O_CLOEXEC);
    if(broker->inputs_read_fd<0 || fstat(broker->inputs_read_fd,&after) || !cliq_dependency_data_same(&before,&after) || !cliq_dependency_data_descriptor(broker->inputs_read_fd,&before))return dependency_fail(broker,"package_metadata_refused");
    if(!dependency_close_fd(broker,&broker->inputs_fd))return false;
    broker->inputs_identity=before;static const char hex[]="0123456789abcdef";
    for(size_t index=0;index<32;index++){broker->inputs_digest[index*2]=hex[actual[index]>>4];broker->inputs_digest[index*2+1]=hex[actual[index]&15];}broker->inputs_digest[64]=0;
    broker->inputs_sealed=true;return true;
}
static int dependency_borrow_inputs(struct cliq_dependency_owner *owner,struct cliq_dependency_package_inputs *output) {
    if(dependency_assert_current(owner)!=1 || !output || !atomic_load(&owner->worker_claimed))return -1;
    struct dependency_broker *broker=(struct dependency_broker*)owner;
    if(broker->working || !broker->inputs_sealed || broker->inputs_failed || broker->inputs_borrowed || !cliq_dependency_data_descriptor(broker->inputs_read_fd,&broker->inputs_identity))return -1;
    int fd=fcntl(broker->inputs_read_fd,F_DUPFD_CLOEXEC,3);if(fd<0)return -1;
    broker->inputs_borrowed=true;output->fd=fd;output->bytes=broker->inputs_bytes;memcpy(output->digest,broker->inputs_digest,65);return 1;
}
#endif
