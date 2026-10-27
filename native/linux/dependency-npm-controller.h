#ifndef CLIQ_DEPENDENCY_NPM_CONTROLLER_H
#define CLIQ_DEPENDENCY_NPM_CONTROLLER_H
#include "dependency-npm-protocol.h"
#include "dependency-result-ack.h"
static bool dependency_open_modules(int generation,const struct cliq_dependency_config *config,int *output) {
    struct stat root,named,held,after;*output=-1;
    if(fstat(generation,&root) || !S_ISDIR(root.st_mode) || fstatat(generation,"node_modules",&named,AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(named.st_mode) || (named.st_mode&07777)!=0755 || named.st_uid!=geteuid() || named.st_dev!=root.st_dev ||
        (uint64_t)named.st_dev!=config->node_modules_device || (uint64_t)named.st_ino!=config->node_modules_inode)return false;
    *output=openat(generation,"node_modules",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    return *output>=0 && fstat(*output,&held)==0 && cliq_dependency_stage_directory(&named,&held) &&
        fstatat(generation,"node_modules",&after,AT_SYMLINK_NOFOLLOW)==0 && cliq_dependency_stage_directory(&held,&after);
}
static void dependency_bubblewrap(int generation_source,int helper_source,int bwrap_source,const int *files,
    const struct cliq_dependency_config *fixed,int script_source,int data_source,int modules_source,const struct cliq_worker_packet *request) {
    const struct cliq_verifier_config *config=&fixed->capture;int keep[CLIQ_WORKER_MAX_FDS];size_t count=0;
    keep[count++]=generation_source;keep[count++]=helper_source;keep[count++]=bwrap_source;
    for(uint32_t i=0;i<config->file_count;i++)keep[count++]=files[i];
    keep[count++]=script_source;keep[count++]=data_source;keep[count++]=modules_source;if(!retain_descriptors(keep,count))_exit(70);
    count=0;int generation=fcntl(generation_source,F_DUPFD,4);if(generation<0 || close(generation_source)!=0)_exit(70);keep[count++]=generation;
    int helper=independent_image_fd(helper_source,4);if(helper<0 || close(helper_source)!=0)_exit(70);keep[count++]=helper;
    int bwrap=fcntl(bwrap_source,F_DUPFD_CLOEXEC,4);if(bwrap<0 || close(bwrap_source)!=0)_exit(70);keep[count++]=bwrap;
    char descriptors[CLIQ_VERIFIER_MAX_FILES+1][24],source[64];snprintf(source,sizeof(source),"/proc/self/fd/%d",generation);snprintf(descriptors[0],24,"%d",helper);
    for(uint32_t i=0;i<config->file_count;i++){int fd=independent_image_fd(files[i],4);if(fd<0 || close(files[i])!=0)_exit(70);keep[count++]=fd;snprintf(descriptors[i+1],24,"%d",fd);}
    int script=independent_image_fd(script_source,4);if(script<0 || close(script_source)!=0)_exit(70);keep[count++]=script;
    int data=independent_image_fd(data_source,4);if(data<0 || close(data_source)!=0)_exit(70);keep[count++]=data;
    int modules=fcntl(modules_source,F_DUPFD,4);if(modules<0 || close(modules_source)!=0)_exit(70);keep[count++]=modules;
    if(!retain_descriptors(keep,count))_exit(70);
    char script_text[24],data_text[24],modules_path[64],root_quota[32],scratch_quota[32];uint64_t runtime,scratch;
    if(!cliq_dependency_storage(fixed,request,&runtime,&scratch))_exit(70);
    snprintf(script_text,sizeof(script_text),"%d",script);snprintf(data_text,sizeof(data_text),"%d",data);snprintf(modules_path,sizeof(modules_path),"/proc/self/fd/%d",modules);
    snprintf(root_quota,sizeof(root_quota),"%llu",(unsigned long long)runtime);snprintf(scratch_quota,sizeof(scratch_quota),"%llu",(unsigned long long)scratch);
    char *arguments[256];size_t at=0;
#define DEPENDENCY_ARG(value) do{if(at>=sizeof(arguments)/sizeof(arguments[0])-1)_exit(70);arguments[at++]=(char*)(value);}while(0)
    DEPENDENCY_ARG("bwrap");DEPENDENCY_ARG("--unshare-user");DEPENDENCY_ARG("--uid");DEPENDENCY_ARG("0");DEPENDENCY_ARG("--gid");DEPENDENCY_ARG("0");
    DEPENDENCY_ARG("--unshare-pid");DEPENDENCY_ARG("--as-pid-1");DEPENDENCY_ARG("--unshare-net");DEPENDENCY_ARG("--unshare-ipc");DEPENDENCY_ARG("--unshare-uts");DEPENDENCY_ARG("--unshare-cgroup");
    DEPENDENCY_ARG("--new-session");DEPENDENCY_ARG("--die-with-parent");DEPENDENCY_ARG("--cap-drop");DEPENDENCY_ARG("ALL");DEPENDENCY_ARG("--cap-add");DEPENDENCY_ARG("CAP_SYS_ADMIN");DEPENDENCY_ARG("--cap-add");DEPENDENCY_ARG("CAP_SETPCAP");
    DEPENDENCY_ARG("--clearenv");DEPENDENCY_ARG("--size");DEPENDENCY_ARG(root_quota);DEPENDENCY_ARG("--tmpfs");DEPENDENCY_ARG("/");DEPENDENCY_ARG("--dir");DEPENDENCY_ARG("/runtime");
    DEPENDENCY_ARG("--perms");DEPENDENCY_ARG("0555");DEPENDENCY_ARG("--ro-bind-data");DEPENDENCY_ARG(descriptors[0]);DEPENDENCY_ARG("/runtime/cliq-linux-worker-init");
    const char *directories[]={"/usr","/usr/bin","/usr/lib","/usr/lib/x86_64-linux-gnu","/lib","/lib/x86_64-linux-gnu","/lib64"};
    for(size_t i=0;i<sizeof(directories)/sizeof(directories[0]);i++){DEPENDENCY_ARG("--dir");DEPENDENCY_ARG(directories[i]);}
    if(fixed->allow_scripts){DEPENDENCY_ARG("--dir");DEPENDENCY_ARG("/bin");}
    for(uint32_t i=0;i<config->file_count;i++){
        const char *path=config->files[i].path;bool named=!strcmp(path,"/usr/bin/node") || (fixed->allow_scripts && (!strcmp(path,"/usr/bin/git") || !strcmp(path,"/bin/bash")));
        DEPENDENCY_ARG("--perms");DEPENDENCY_ARG("0555");DEPENDENCY_ARG(named?"--file":"--ro-bind-data");DEPENDENCY_ARG(descriptors[i+1]);DEPENDENCY_ARG(path);
    }
    DEPENDENCY_ARG("--perms");DEPENDENCY_ARG("0444");DEPENDENCY_ARG("--ro-bind-data");DEPENDENCY_ARG(script_text);DEPENDENCY_ARG(CLIQ_DEPENDENCY_SCRIPT_PATH);
    DEPENDENCY_ARG("--perms");DEPENDENCY_ARG("0400");DEPENDENCY_ARG("--file");DEPENDENCY_ARG(data_text);DEPENDENCY_ARG("/runtime/npm.image");
    DEPENDENCY_ARG("--ro-bind");DEPENDENCY_ARG(source);DEPENDENCY_ARG("/work");DEPENDENCY_ARG("--bind");DEPENDENCY_ARG(modules_path);DEPENDENCY_ARG("/work/node_modules");
    DEPENDENCY_ARG("--proc");DEPENDENCY_ARG("/proc");DEPENDENCY_ARG("--dev");DEPENDENCY_ARG("/dev");
    DEPENDENCY_ARG("--size");DEPENDENCY_ARG(scratch_quota);DEPENDENCY_ARG("--tmpfs");DEPENDENCY_ARG("/scratch");
    const char *scratch_directories[]={"/scratch/package-cache","/scratch/npm-cache","/scratch/tmp","/scratch/home","/tmp","/home","/home/cliq"};
    for(size_t i=0;i<sizeof(scratch_directories)/sizeof(scratch_directories[0]);i++){DEPENDENCY_ARG("--dir");DEPENDENCY_ARG(scratch_directories[i]);}
    DEPENDENCY_ARG("--chdir");DEPENDENCY_ARG("/work");DEPENDENCY_ARG("--");DEPENDENCY_ARG("/runtime/cliq-linux-worker-init");arguments[at]=NULL;
#undef DEPENDENCY_ARG
    char *const environment[]={"LANG=C","LC_ALL=C",NULL};fexecve(bwrap,arguments,environment);_exit(70);
}
static bool dependency_forward_inputs(const struct cliq_worker_packet *request,int passed[CLIQ_WORKER_MAX_FDS],size_t count,struct cliq_worker_packet *response) {
    if(request->scope==0 || request->scope>=CLIQ_WORKER_MAX_SCOPES)return false;struct scope *scope=&scopes[request->scope];
    if(!scope->created || !scope->dependency || scope->stopped || scope->released || scope->dependency_inputs_sealed || !scope_process_current(scope) ||
        !scope_process_current(&scopes[scope->parent]) || !cliq_dependency_input_command_same(request,&scope->identity,request->command) ||
        ((request->command==CLIQ_STAGE_DEPENDENCY_CHUNK)?count!=1:request->command!=CLIQ_SEAL_DEPENDENCY_INPUTS || count!=0))return false;
    size_t extras;struct cliq_worker_packet acknowledgement;
    if(!cliq_send(scope->channel,request,count?passed:NULL,count) || !readable(scope->channel,OBSERVATION_TIMEOUT_MS) ||
        !cliq_receive(scope->channel,&acknowledgement,NULL,0,&extras) || memcmp(&acknowledgement,request,sizeof(acknowledgement)))return false;
    if(request->command==CLIQ_SEAL_DEPENDENCY_INPUTS)scope->dependency_inputs_sealed=true;*response=acknowledgement;return true;
}
#endif
