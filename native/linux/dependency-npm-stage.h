#ifndef CLIQ_DEPENDENCY_NPM_STAGE_H
#define CLIQ_DEPENDENCY_NPM_STAGE_H
/* Fixed same-invocation CAS input stage. No caller pathname, index-selected
 * output name, FD number or script-release bit is accepted. All partial files
 * remain in this scope's private scratch until its original domain joins. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dependency-input-record.h"
#include "dependency-npm-protocol.h"
struct cliq_dependency_stage {
    int metadata_fd, root_fd, writer;
    unsigned char *metadata;
    uint64_t metadata_bytes, offset, package_offset, charged_bytes, byte_limit, package_limit;
    uint32_t expected_count, index;
    bool initialized, failed, complete, reuse, join_failed;
    struct stat metadata_identity, root_identity, file_identity;
    struct cliq_dependency_package_input_record current;
    struct sha256_context hash;
    char leaf[70];
};
static inline bool cliq_dependency_stage_same(const struct stat *a, const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
        a->st_nlink==b->st_nlink && a->st_size==b->st_size && a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static inline bool cliq_dependency_stage_directory(const struct stat *a,const struct stat *b) {
    return S_ISDIR(b->st_mode) && a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid;
}
static inline uint32_t cliq_dependency_stage_u32(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static inline void cliq_dependency_stage_digest(struct sha256_context *hash,char text[65]) {
    unsigned char digest[32];static const char hex[]="0123456789abcdef";sha256_final(hash,digest);
    for(size_t i=0;i<32;i++){text[i*2]=hex[digest[i]>>4];text[i*2+1]=hex[digest[i]&15];}text[64]=0;
}
static inline bool cliq_dependency_stage_sealed(int fd,uint64_t maximum,struct stat *identity) {
#if defined(__linux__) && defined(F_GET_SEALS)
    int flags=fcntl(fd,F_GETFL),descriptor=fcntl(fd,F_GETFD);
    return flags>=0 && (flags&O_ACCMODE)==O_RDONLY && descriptor>=0 && (descriptor&FD_CLOEXEC) &&
        fstat(fd,identity)==0 && S_ISREG(identity->st_mode) && identity->st_nlink==0 && identity->st_uid==geteuid() &&
        (identity->st_mode&07777)==0400 && identity->st_size>=0 && (uint64_t)identity->st_size<=maximum &&
        fcntl(fd,F_GET_SEALS)==(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL);
#else
    (void)fd;(void)maximum;(void)identity;return false;
#endif
}
static inline bool cliq_dependency_stage_root(struct cliq_dependency_stage *stage) {
    struct stat current;return fstat(stage->root_fd,&current)==0 && cliq_dependency_stage_directory(&stage->root_identity,&current);
}
static inline bool cliq_dependency_stage_file_current(struct cliq_dependency_stage *stage,int fd,bool writing) {
    struct stat held,named;
    return cliq_dependency_stage_root(stage) && fstat(fd,&held)==0 && S_ISREG(held.st_mode) && held.st_nlink==1 && held.st_uid==geteuid() &&
        held.st_dev==stage->root_identity.st_dev && held.st_ino==stage->file_identity.st_ino && held.st_dev==stage->file_identity.st_dev &&
        (held.st_mode&07777)==(writing?0600:0400) && fstatat(stage->root_fd,stage->leaf,&named,AT_SYMLINK_NOFOLLOW)==0 && cliq_dependency_stage_same(&held,&named);
}
static inline bool cliq_dependency_stage_empty_root(struct cliq_dependency_stage *stage) {
    int copy=openat(stage->root_fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(copy<0)return false;
    struct stat held;bool valid=fstat(copy,&held)==0 && cliq_dependency_stage_directory(&stage->root_identity,&held);
    DIR *directory=valid?fdopendir(copy):NULL;
    if(!directory){if(close(copy)!=0)stage->join_failed=true;return false;}
    struct dirent *entry;errno=0;
    while((entry=readdir(directory)))if(strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")){valid=false;break;}
    if(errno)valid=false;
    if(closedir(directory)!=0){valid=false;stage->join_failed=true;}return valid;
}
static inline bool cliq_dependency_stage_read_record(struct cliq_dependency_stage *stage,uint64_t *offset,struct cliq_dependency_package_input_record *item) {
    if(*offset>stage->metadata_bytes || stage->metadata_bytes-*offset<4)return false;
    uint32_t size=cliq_dependency_stage_u32(stage->metadata+*offset);*offset+=4;
    if(!size || size>12288 || size>stage->metadata_bytes-*offset || !cliq_dependency_input_record_read(stage->metadata+*offset,size,item))return false;
    *offset+=size;return true;
}
/* Adopts only original namespace-owned SCM copies. The caller always calls
 * close, including a failed initialization; no partial prefix is unowned. */
static inline bool cliq_dependency_stage_initialize(struct cliq_dependency_stage *stage,int metadata,int root,
    uint64_t bytes,const char *digest,uint32_t count,const char *sequence_digest,uint64_t package_limit,uint64_t byte_limit) {
    memset(stage,0,sizeof(*stage));stage->metadata_fd=metadata;stage->root_fd=root;stage->writer=-1;stage->failed=true;
    if(!cliq_dependency_digest(digest) || !cliq_dependency_digest(sequence_digest) || count>200000 ||
        package_limit<1 || package_limit>CLIQ_DEPENDENCY_PACKAGE_BYTES || byte_limit<4096 ||
        !cliq_dependency_stage_sealed(metadata,CLIQ_DEPENDENCY_METADATA_BYTES,&stage->metadata_identity) ||
        (uint64_t)stage->metadata_identity.st_size!=bytes || ((count==0)!=(bytes==0)) ||
        fstat(root,&stage->root_identity)!=0 || !S_ISDIR(stage->root_identity.st_mode) || stage->root_identity.st_uid!=geteuid() || !cliq_dependency_stage_empty_root(stage))return false;
    stage->metadata_bytes=bytes;stage->expected_count=count;stage->package_limit=package_limit;stage->byte_limit=byte_limit;
    if(bytes){stage->metadata=mmap(NULL,(size_t)bytes,PROT_READ,MAP_PRIVATE,metadata,0);if(stage->metadata==MAP_FAILED){stage->metadata=NULL;return false;}}
    struct sha256_context hash,sequence;sha256_init(&hash);if(bytes)sha256_update(&hash,stage->metadata,(size_t)bytes);
    char observed[65];cliq_dependency_stage_digest(&hash,observed);if(strcmp(observed,digest))return false;
    static const unsigned char domain[]="cliq-dependency-package-descriptors-v1\0";sha256_init(&sequence);sha256_update(&sequence,domain,sizeof(domain)-1);
    uint64_t offset=0,total=0;struct cliq_dependency_descriptor previous={0};bool has_previous=false;
    for(uint32_t i=0;i<count;i++){
        struct cliq_dependency_package_input_record item;
        if(!cliq_dependency_stage_read_record(stage,&offset,&item) || item.blob_bytes>package_limit ||
            (has_previous && cliq_dependency_descriptor_compare(&previous,&item.descriptor)>=0) || item.blob_bytes>UINT64_MAX-total)return false;
        total+=item.blob_bytes;previous=item.descriptor;has_previous=true;cliq_dependency_input_record_hash(&sequence,&item);
    }
    cliq_dependency_stage_digest(&sequence,observed);struct stat after;
    if(total>byte_limit || offset!=bytes || strcmp(observed,sequence_digest) || fstat(metadata,&after)!=0 || !cliq_dependency_stage_same(&stage->metadata_identity,&after) ||
        !cliq_dependency_stage_sealed(metadata,bytes,&after))return false;
    stage->initialized=true;stage->failed=false;stage->complete=count==0;return true;
}
static inline bool cliq_dependency_stage_begin(struct cliq_dependency_stage *stage) {
    if(!cliq_dependency_stage_read_record(stage,&stage->offset,&stage->current) || !cliq_dependency_stage_root(stage))return false;
    int length=snprintf(stage->leaf,sizeof(stage->leaf),"%s.tgz",stage->current.blob_sha256);if(length!=68)return false;
    stage->reuse=false;stage->writer=openat(stage->root_fd,stage->leaf,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(stage->writer<0){
        if(errno!=EEXIST)return false;
        stage->writer=openat(stage->root_fd,stage->leaf,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);stage->reuse=true;
    }
    if(stage->writer>=0 && !stage->reuse && fchmod(stage->writer,0600)!=0)return false;
    if(stage->writer<0 || fstat(stage->writer,&stage->file_identity)!=0 || !cliq_dependency_stage_file_current(stage,stage->writer,!stage->reuse))return false;
    if(stage->reuse){if(stage->file_identity.st_size<0 || (uint64_t)stage->file_identity.st_size!=stage->current.blob_bytes)return false;}
    else {
        uint64_t rounded=(stage->current.blob_bytes+4095)&~UINT64_C(4095);
        if(stage->charged_bytes>stage->byte_limit || rounded>stage->byte_limit-stage->charged_bytes)return false;
        stage->charged_bytes+=rounded;
    }
    stage->package_offset=0;sha256_init(&stage->hash);return true;
}
static inline bool cliq_dependency_stage_finish_package(struct cliq_dependency_stage *stage,const volatile sig_atomic_t *cancelled) {
    char observed[65];cliq_dependency_stage_digest(&stage->hash,observed);
    if(strcmp(observed,stage->current.blob_sha256) || !cliq_dependency_stage_file_current(stage,stage->writer,!stage->reuse))return false;
    if(!stage->reuse && fchmod(stage->writer,0400)!=0)return false;
    int writer=stage->writer;stage->writer=-1;if(close(writer)!=0){stage->join_failed=true;return false;}
    int file=openat(stage->root_fd,stage->leaf,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(file<0)return false;
    bool valid=cliq_dependency_stage_file_current(stage,file,false);struct stat before,after;
    valid=valid && fstat(file,&before)==0 && before.st_size>=0 && (uint64_t)before.st_size==stage->current.blob_bytes;
    struct sha256_context hash;sha256_init(&hash);unsigned char buffer[65536];uint64_t offset=0;
    while(valid && offset<stage->current.blob_bytes){
        if(cancelled && *cancelled){valid=false;break;}
        size_t wanted=stage->current.blob_bytes-offset<sizeof(buffer)?(size_t)(stage->current.blob_bytes-offset):sizeof(buffer);
        ssize_t n=pread(file,buffer,wanted,(off_t)offset);if(n<0 && errno==EINTR)continue;
        if(n<=0 || (size_t)n>wanted){valid=false;break;}sha256_update(&hash,buffer,(size_t)n);offset+=(uint64_t)n;
    }
    ssize_t tail;do{tail=pread(file,buffer,1,(off_t)offset);}while(tail<0 && errno==EINTR);
    cliq_dependency_stage_digest(&hash,observed);
    valid=valid && tail==0 && !strcmp(observed,stage->current.blob_sha256) && fstat(file,&after)==0 && cliq_dependency_stage_same(&before,&after) &&
        cliq_dependency_stage_file_current(stage,file,false);
    if(close(file)!=0){valid=false;stage->join_failed=true;}
    if(valid){stage->index++;stage->complete=stage->index==stage->expected_count;stage->package_offset=0;}
    return valid;
}
/* Owns and consumes one actual sealed <=64KiB channel object. Retrying a
 * failed/uncertain chunk is impossible; the original whole scope must join. */
static inline bool cliq_dependency_stage_chunk(struct cliq_dependency_stage *stage,int chunk,const volatile sig_atomic_t *cancelled) {
    struct stat before,after;bool valid=stage->initialized && !stage->failed && !stage->complete && !(cancelled && *cancelled) &&
        cliq_dependency_stage_sealed(chunk,CLIQ_DEPENDENCY_CHUNK_BYTES,&before) && before.st_size>0;
    if(valid && stage->writer<0)valid=cliq_dependency_stage_begin(stage);
    if(valid)valid=(uint64_t)before.st_size<=stage->current.blob_bytes-stage->package_offset && cliq_dependency_stage_file_current(stage,stage->writer,!stage->reuse);
    unsigned char bytes[65536];size_t read_at=0;
    while(valid && read_at<(size_t)before.st_size){
        ssize_t n=pread(chunk,bytes+read_at,(size_t)before.st_size-read_at,(off_t)read_at);if(n<0 && errno==EINTR)continue;
        if(n<=0){valid=false;break;}read_at+=(size_t)n;
    }
    unsigned char tail;ssize_t extra=-1;if(valid){do{extra=pread(chunk,&tail,1,before.st_size);}while(extra<0 && errno==EINTR);}
    valid=valid && extra==0 && fstat(chunk,&after)==0 && cliq_dependency_stage_same(&before,&after) && cliq_dependency_stage_sealed(chunk,CLIQ_DEPENDENCY_CHUNK_BYTES,&after);
    int original=chunk;if(close(original)!=0){valid=false;stage->join_failed=true;}
    if(valid && !stage->reuse){
        size_t at=0;while(at<read_at){if(cancelled && *cancelled){valid=false;break;}
            ssize_t n=write(stage->writer,bytes+at,read_at-at);if(n<0 && errno==EINTR)continue;if(n<=0){valid=false;break;}at+=(size_t)n;}
    }
    if(valid){sha256_update(&stage->hash,bytes,read_at);stage->package_offset+=read_at;
        if(stage->package_offset==stage->current.blob_bytes)valid=cliq_dependency_stage_finish_package(stage,cancelled);}
    if(!valid)stage->failed=true;return valid;
}
static inline bool cliq_dependency_stage_close(struct cliq_dependency_stage *stage) {
    bool joined=true;int writer=stage->writer,metadata=stage->metadata_fd,root=stage->root_fd;
    stage->writer=stage->metadata_fd=stage->root_fd=-1;
    if(writer>=0 && close(writer)!=0)joined=false;
    if(stage->metadata && munmap(stage->metadata,(size_t)stage->metadata_bytes)!=0)joined=false;
    stage->metadata=NULL;
    if(metadata>=0 && close(metadata)!=0)joined=false;
    if(root>=0 && close(root)!=0)joined=false;
    if(!joined){stage->failed=true;stage->join_failed=true;}return joined && !stage->join_failed;
}
#endif
