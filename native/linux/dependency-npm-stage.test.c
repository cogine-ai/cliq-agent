#define _GNU_SOURCE
/* Actual owned Linux descriptors and files; no Run, grant, native owner or
 * process-death receipt is created by this data component. */
#if defined(__linux__)
#include "dependency-npm-stage.h"
#include <linux/memfd.h>
#include <sys/socket.h>
static unsigned checks;
#define CHECK(value) do { checks++;if(!(value)){fprintf(stderr,"dependency stage check %u line %u failed\n",checks,__LINE__);exit(1);} } while(0)
static int sealed(const void *bytes,size_t size) {
    int writer=memfd_create("cliq-owned-dependency-stage",MFD_CLOEXEC|MFD_ALLOW_SEALING);CHECK(writer>=0);
    size_t offset=0;while(offset<size){ssize_t n=write(writer,(const unsigned char*)bytes+offset,size-offset);if(n<0 && errno==EINTR)continue;CHECK(n>0);offset+=(size_t)n;}
    CHECK(!fchmod(writer,0400));CHECK(!fcntl(writer,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL));
    char path[64];CHECK(snprintf(path,sizeof(path),"/proc/self/fd/%d",writer)>0);int reader=open(path,O_RDONLY|O_CLOEXEC);CHECK(reader>=0);CHECK(!close(writer));return reader;
}
static void hash(const void *bytes,size_t size,char digest[65]){struct sha256_context h;sha256_init(&h);sha256_update(&h,bytes,size);cliq_dependency_stage_digest(&h,digest);}
static size_t descriptor_count(void){DIR *d=opendir("/proc/self/fd");CHECK(d);size_t n=0;struct dirent *e;while((e=readdir(d)))if(strcmp(e->d_name,".") && strcmp(e->d_name,".."))n++;CHECK(!closedir(d));return n;}
static int directory(char path[64]){strcpy(path,"/tmp/cliq-dependency-stage-XXXXXX");CHECK(mkdtemp(path));int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(fd>=0);return fd;}
static void sequence(const unsigned char *bytes,size_t size,uint32_t count,char digest[65]){
    struct sha256_context h;sha256_init(&h);static const unsigned char domain[]="cliq-dependency-package-descriptors-v1\0";sha256_update(&h,domain,sizeof(domain)-1);
    size_t offset=0;for(uint32_t i=0;i<count;i++){CHECK(size-offset>=4);uint32_t n=cliq_dependency_stage_u32(bytes+offset);offset+=4;CHECK(n<=size-offset);
        struct cliq_dependency_package_input_record record;CHECK(cliq_dependency_input_record_read(bytes+offset,n,&record));cliq_dependency_input_record_hash(&h,&record);offset+=n;}
    CHECK(offset==size);cliq_dependency_stage_digest(&h,digest);
}
static size_t metadata(unsigned char *output,size_t maximum,const char *blob,size_t bytes,unsigned count) {
    size_t offset=0;for(unsigned i=0;i<count;i++){
        char record[2048];int n=snprintf(record,sizeof(record),"{\"blobBytes\":%zu,\"blobSha256\":\"%s\",\"canonicalPackagePath\":\"/owned-%u.tgz\",\"endpointRegistrationRef\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"integrityAlgorithm\":\"sha256\",\"integrityDigest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"packageName\":\"owned-%u\",\"packageVersion\":\"1.0.0\"}",bytes,blob,i,i);
        CHECK(n>0 && (size_t)n<sizeof(record) && offset+4+(size_t)n<=maximum);uint32_t size=(uint32_t)n;
        for(unsigned j=0;j<4;j++)output[offset++]=(unsigned char)(size>>(j*8));memcpy(output+offset,record,size);offset+=size;
    }return offset;
}
int main(void) {
    size_t baseline=descriptor_count();unsigned char payload[65536];for(size_t i=0;i<sizeof(payload);i++)payload[i]=(unsigned char)(i*37U+11U);
    struct sha256_context complete;sha256_init(&complete);for(unsigned i=0;i<33;i++)sha256_update(&complete,payload,sizeof(payload));
    char digest[65],metadata_digest[65],sequence_digest[65],path[64];cliq_dependency_stage_digest(&complete,digest);
    unsigned char records[4096];size_t bytes=metadata(records,sizeof(records),digest,sizeof(payload)*33,2);hash(records,bytes,metadata_digest);sequence(records,bytes,2,sequence_digest);
    struct cliq_dependency_stage stage;int root=directory(path),input=sealed(records,bytes);CHECK(cliq_dependency_stage_initialize(&stage,input,root,bytes,metadata_digest,2,sequence_digest,67108864,8388608));
    volatile sig_atomic_t cancelled=0;
    for(unsigned package=0;package<2;package++)for(unsigned i=0;i<33;i++){int chunk=sealed(payload,sizeof(payload));CHECK(cliq_dependency_stage_chunk(&stage,chunk,&cancelled));CHECK(fcntl(chunk,F_GETFD)<0 && errno==EBADF);}
    CHECK(stage.complete && stage.index==2 && stage.charged_bytes==sizeof(payload)*33);CHECK(cliq_dependency_stage_close(&stage));
    CHECK(fcntl(input,F_GETFD)<0 && errno==EBADF && fcntl(root,F_GETFD)<0 && errno==EBADF);
    char file[160];CHECK(snprintf(file,sizeof(file),"%s/%s.tgz",path,digest)>0);CHECK(!unlink(file));CHECK(!rmdir(path));CHECK(descriptor_count()==baseline);
    root=directory(path);input=sealed(records,bytes);CHECK(!cliq_dependency_stage_initialize(&stage,input,root,bytes,metadata_digest,2,sequence_digest,67108864,1048576));CHECK(cliq_dependency_stage_close(&stage));CHECK(!rmdir(path));
    root=directory(path);input=sealed(records,bytes);CHECK(cliq_dependency_stage_initialize(&stage,input,root,bytes,metadata_digest,2,sequence_digest,67108864,8388608));
    int chunk=sealed(payload,sizeof(payload));cancelled=1;CHECK(!cliq_dependency_stage_chunk(&stage,chunk,&cancelled));CHECK(stage.failed && fcntl(chunk,F_GETFD)<0 && errno==EBADF);CHECK(cliq_dependency_stage_close(&stage));CHECK(!rmdir(path));cancelled=0;
    root=directory(path);input=sealed(records,bytes);CHECK(cliq_dependency_stage_initialize(&stage,input,root,bytes,metadata_digest,2,sequence_digest,67108864,8388608));
    payload[0]^=1;for(unsigned i=0;i<33;i++){chunk=sealed(payload,sizeof(payload));bool accepted=cliq_dependency_stage_chunk(&stage,chunk,&cancelled);CHECK(accepted==(i<32));}
    CHECK(stage.failed && !stage.complete);CHECK(cliq_dependency_stage_close(&stage));CHECK(snprintf(file,sizeof(file),"%s/%s.tgz",path,digest)>0);CHECK(!unlink(file));CHECK(!rmdir(path));
    root=directory(path);input=sealed(records,bytes);CHECK(!cliq_dependency_stage_initialize(&stage,input,root,bytes,metadata_digest,1,sequence_digest,67108864,8388608));CHECK(cliq_dependency_stage_close(&stage));CHECK(!rmdir(path));
    CHECK(descriptor_count()==baseline);printf("{\"format\":\"cliq-dependency-stage-component-v1\",\"checks\":%u,\"qualified\":false}\n",checks);return 0;
}
#else
#include <stdio.h>
int main(void){fputs("dependency_stage_linux_required\n",stderr);return 77;}
#endif
