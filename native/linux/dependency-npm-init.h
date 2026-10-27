#ifndef CLIQ_DEPENDENCY_NPM_INIT_H
#define CLIQ_DEPENDENCY_NPM_INIT_H
#include "dependency-npm-protocol.h"
#include "dependency-npm-image.h"
#include "dependency-npm-stage.h"
#include "source-storage.h"
static bool dependency_read_config(int fd,struct cliq_dependency_config *config) {
    struct stat identity;int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    if(fstat(fd,&identity) || !S_ISREG(identity.st_mode) || identity.st_size!=(off_t)sizeof(*config) || fcntl(fd,F_GET_SEALS)!=seals)return false;
    size_t offset=0;while(offset<sizeof(*config)){ssize_t n=pread(fd,(char*)config+offset,sizeof(*config)-offset,(off_t)offset);if(n<0 && errno==EINTR)continue;if(n<=0)return false;offset+=(size_t)n;}
    return cliq_dependency_config_valid(config);
}
static bool dependency_modules_current(const struct cliq_dependency_config *config) {
    int work=open("/work",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),modules=-1;struct stat root,named,held,after;
    bool valid=work>=0 && fstat(work,&root)==0 && fstatat(work,"node_modules",&named,AT_SYMLINK_NOFOLLOW)==0 && S_ISDIR(named.st_mode) &&
        named.st_uid==geteuid() && named.st_dev==root.st_dev && (uint64_t)named.st_dev==config->node_modules_device && (uint64_t)named.st_ino==config->node_modules_inode;
    if(valid)modules=openat(work,"node_modules",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    valid=valid && modules>=0 && fstat(modules,&held)==0 && cliq_dependency_stage_directory(&named,&held) &&
        fstatat(work,"node_modules",&after,AT_SYMLINK_NOFOLLOW)==0 && cliq_dependency_stage_directory(&held,&after);
    struct stat rule;if(valid){errno=0;valid=fstatat(work,".npmrc",&rule,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;}
    if(modules>=0 && close(modules)!=0)valid=false;if(work>=0 && close(work)!=0)valid=false;return valid;
}
/* The parent keeps only an already-open original RW-mount capability while
 * both PIDs see a genuinely RO bind at the package-cache path. That FD is
 * never inherited by Node and is consumed before the sole RELEASE. */
static bool dependency_confinement(const struct cliq_dependency_config *fixed,uint32_t scope) {
    const struct cliq_verifier_config *config=&fixed->capture;
    int script=open(CLIQ_DEPENDENCY_SCRIPT_PATH,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    bool valid=script>=0 && builtin_full_data(script,fixed->script_bytes,fixed->script_digest,false);
    if(script>=0 && close(script)!=0)valid=false;
    if(!valid || !dependency_modules_current(fixed) || !verifier_node_mount(config,scope) ||
        (fixed->allow_scripts && (!builtin_bind_runtime(config,"/usr/bin/git") || !builtin_bind_runtime(config,"/bin/bash"))) ||
        !verifier_setup_stage(scope,CLIQ_VERIFIER_SETUP_CONFINEMENT) ||
        !verifier_mount_attributes("/",AT_RECURSIVE,MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NOSUID,0) ||
        !verifier_mount_attributes("/",0,MOUNT_ATTR_RDONLY|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/work",AT_RECURSIVE,MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/work/node_modules",AT_RECURSIVE,MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,MOUNT_ATTR_RDONLY) ||
        !verifier_mount_attributes("/scratch",AT_RECURSIVE,MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/scratch/package-cache",AT_RECURSIVE,MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/tmp",AT_RECURSIVE,MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/home/cliq",AT_RECURSIVE,MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0) ||
        !verifier_mount_attributes("/proc",AT_RECURSIVE,MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,0))return false;
    for(uint32_t i=0;i<config->file_count;i++)if(!verifier_mount_attributes(config->files[i].path,0,MOUNT_ATTR_RDONLY|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV,MOUNT_ATTR_NOEXEC))return false;
    if(!verifier_mount_observed("/",true,false,false) || !verifier_mount_observed("/work",true,false,false) ||
        !verifier_mount_observed("/work/node_modules",false,false,false) || !verifier_mount_observed("/scratch",false,false,false) ||
        !verifier_mount_observed("/scratch/package-cache",true,false,false) || !verifier_mount_observed("/tmp",false,false,false) ||
        !verifier_mount_observed("/home/cliq",false,false,false) || !verifier_mount_observed("/proc",true,false,false) ||
        !verifier_mount_observed("/dev",false,false,true) || !verifier_mount_observed(CLIQ_DEPENDENCY_SCRIPT_PATH,true,false,false))return false;
    for(uint32_t i=0;i<config->file_count;i++)if(!verifier_mount_observed(config->files[i].path,true,true,false))return false;
    return dependency_modules_current(fixed) && verifier_drop_capabilities() && verifier_filter() && builtin_filter();
}
static int dependency_namespace(struct cliq_worker_packet initial,int passed[CLIQ_WORKER_MAX_FDS]) {
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)!=0 || !verifier_setup_stage(initial.scope,CLIQ_VERIFIER_SETUP_ENTRY))return 70;
    struct cliq_dependency_config *fixed=calloc(1,sizeof(*fixed));if(!fixed)return 70;
    struct cliq_verifier_config *config=&fixed->capture;bool valid=dependency_read_config(passed[0],fixed) &&
        builtin_sealed_data(passed[1],fixed->input_bytes,fixed->input_digest) && builtin_sealed_data(passed[2],fixed->metadata_bytes,fixed->metadata_digest);
    if(close(passed[0])!=0)valid=false;
    uint64_t root_budget=0,scratch_budget=0;valid=valid && cliq_dependency_storage(fixed,&initial,&root_budget,&scratch_budget);
    int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),scratch=open("/scratch",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat root_identity,scratch_identity;
    valid=valid && root>=0 && scratch>=0 && fstat(root,&root_identity)==0 && fstat(scratch,&scratch_identity)==0 &&
        root_identity.st_dev!=scratch_identity.st_dev && source_tmpfs_within(root,root_budget) && source_tmpfs_within(scratch,scratch_budget);
    if(root>=0 && close(root)!=0)valid=false;if(scratch>=0 && close(scratch)!=0)valid=false;
    int runtime=open("/runtime",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),image=-1,npm=-1;
    if(valid && runtime>=0)image=openat(runtime,"npm.image",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    struct stat named,held,after;
    valid=valid && runtime>=0 && image>=0 && fstat(image,&held)==0 && fstatat(runtime,"npm.image",&named,AT_SYMLINK_NOFOLLOW)==0 && cliq_npm_stat_same(&held,&named) &&
        mkdirat(runtime,"npm",0755)==0;
    if(valid)npm=openat(runtime,"npm",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    valid=valid && npm>=0 && cliq_npm_materialize(image,npm,&shutdown_requested)==CLIQ_NPM_IMAGE_OK &&
        fstat(image,&after)==0 && cliq_npm_stat_same(&held,&after) && fstatat(runtime,"npm.image",&after,AT_SYMLINK_NOFOLLOW)==0 && cliq_npm_stat_same(&held,&after);
    if(image>=0 && close(image)!=0)valid=false;if(npm>=0 && close(npm)!=0)valid=false;
    if(valid)valid=unlinkat(runtime,"npm.image",0)==0 && mkdirat(runtime,"npm-config",0755)==0;
    int configuration=valid?openat(runtime,"npm-config",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW):-1;
    const char *names[]={"user","global"};for(size_t i=0;valid && i<2;i++){
        int fd=openat(configuration,names[i],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0400);valid=fd>=0 && fchmod(fd,0400)==0;
        if(fd>=0 && close(fd)!=0)valid=false;
    }
    if(configuration>=0 && close(configuration)!=0)valid=false;if(runtime>=0 && close(runtime)!=0)valid=false;
    if(valid)valid=mount("/scratch/tmp","/tmp",NULL,MS_BIND,NULL)==0 && mount("/scratch/home","/home/cliq",NULL,MS_BIND,NULL)==0;
    int cache=valid?open("/scratch/package-cache",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW):-1;
    struct cliq_dependency_stage stage;memset(&stage,0,sizeof(stage));stage.metadata_fd=stage.root_fd=stage.writer=-1;
    if(valid)valid=cache>=0 && cliq_dependency_stage_initialize(&stage,passed[2],cache,fixed->metadata_bytes,fixed->metadata_digest,
        fixed->package_count,fixed->descriptor_sequence_digest,initial.max_output_bytes<initial.max_file_bytes?initial.max_output_bytes:initial.max_file_bytes,scratch_budget) &&
        mount("/scratch/package-cache","/scratch/package-cache",NULL,MS_BIND,NULL)==0 && dependency_confinement(fixed,initial.scope);
    if(!valid){if(stage.metadata_fd<0 && passed[2]>=0)close(passed[2]);if(stage.root_fd<0 && cache>=0)close(cache);cliq_dependency_stage_close(&stage);close(passed[1]);free(config);return 70;}
    int barrier[2],execution[2];
    if(pipe2(barrier,O_CLOEXEC)!=0){cliq_dependency_stage_close(&stage);close(passed[1]);free(config);return 70;}
    if(pipe2(execution,O_CLOEXEC|O_NONBLOCK)!=0){close(barrier[0]);close(barrier[1]);cliq_dependency_stage_close(&stage);close(passed[1]);free(config);return 70;}
    pid_t child=fork();if(child<0){close(barrier[0]);close(barrier[1]);close(execution[0]);close(execution[1]);cliq_dependency_stage_close(&stage);close(passed[1]);free(config);return 70;}
    if(!child){
        close(barrier[1]);close(execution[0]);close(3);
        int blocked=fcntl(barrier[0],F_DUPFD_CLOEXEC,10),failure=fcntl(execution[1],F_DUPFD_CLOEXEC,10),
            input=independent_image_fd(passed[1],10),metadata=independent_image_fd(stage.metadata_fd,10);
        if(blocked<0 || failure<0 || input<0 || metadata<0 || dup2(input,3)<0 || dup2(metadata,4)<0 || dup3(failure,5,O_CLOEXEC)<0 ||
            dup3(blocked,6,O_CLOEXEC)<0 || !cliq_close_range(7,UINT_MAX))_exit(70);
        umask(0022);
        char go;ssize_t n;do{n=read(6,&go,1);}while(n<0 && errno==EINTR);if(close(6)!=0 || n!=1 || go!='1')_exit(70);
        char *arguments[4],*environment[11];for(uint32_t i=0;i<3;i++)arguments[i]=config->strings+config->arguments[i];arguments[3]=NULL;
        for(uint32_t i=0;i<10;i++)environment[i]=config->strings+config->environment[i];environment[10]=NULL;
        if(chdir("/work")==0)execve(config->executable,arguments,environment);int error=errno;if(!cliq_write_exec_diagnostic(5,error))_exit(70);_exit(70);
    }
    close(barrier[0]);close(execution[1]);if(close(passed[1])!=0){cliq_dependency_stage_close(&stage);free(config);return 70;}
    struct cliq_worker_packet ready=initial;ready.command=CLIQ_WORKER_READY;ready.pid=child;ready.namespace_init_pid=1;struct stat namespace;
    if(!cliq_process_token(child,ready.start_token) || !cliq_process_token(1,ready.init_start_token) || stat("/proc/self/ns/pid",&namespace)!=0){cliq_dependency_stage_close(&stage);free(config);return 70;}
    ready.pid_namespace_inode=(uint64_t)namespace.st_ino;
    if(!verifier_setup_stage(initial.scope,CLIQ_VERIFIER_SETUP_BEFORE_READY) || !cliq_send(3,&ready,NULL,0)){cliq_dependency_stage_close(&stage);free(config);return 70;}
    bool sealed=false;struct cliq_worker_packet request;size_t count;
    for(;;){int files[1]={-1};if(!cliq_receive(3,&request,files,1,&count)){cliq_dependency_stage_close(&stage);free(config);return 70;}
        if(!sealed && request.command==CLIQ_STAGE_DEPENDENCY_CHUNK && count==1 && cliq_dependency_input_command_same(&request,&initial,CLIQ_STAGE_DEPENDENCY_CHUNK)){
            bool accepted=cliq_dependency_stage_chunk(&stage,files[0],&shutdown_requested);files[0]=-1;
            if(!accepted || !cliq_send(3,&request,NULL,0)){cliq_dependency_stage_close(&stage);free(config);return 70;}
        }else if(!sealed && request.command==CLIQ_SEAL_DEPENDENCY_INPUTS && count==0 && cliq_dependency_input_command_same(&request,&initial,CLIQ_SEAL_DEPENDENCY_INPUTS)){
            if(!stage.complete || stage.failed || !cliq_dependency_stage_close(&stage) || !dependency_modules_current(fixed) ||
                !verifier_mount_observed("/scratch/package-cache",true,false,false) || !cliq_send(3,&request,NULL,0)){free(config);return 70;}sealed=true;
        }else if(sealed && count==0 && request.command==CLIQ_RELEASE_DEPENDENCY_NPM && cliq_dependency_input_command_same(&request,&initial,CLIQ_RELEASE_DEPENDENCY_NPM))break;
        else{if(count && files[0]>=0)close(files[0]);cliq_dependency_stage_close(&stage);free(config);return 70;}
    }
    if(write(barrier[1],"1",1)!=1 || close(barrier[1])!=0){free(config);return 70;}
    int status;pid_t joined;do{joined=waitpid(child,&status,0);}while(joined<0 && errno==EINTR);if(joined!=child){free(config);return 70;}
    struct cliq_worker_packet result=request;result.command=CLIQ_VERIFIER_RESULT;int error=0;ssize_t n;
    do{n=read(execution[0],&error,sizeof(error));}while(n<0 && errno==EINTR);if(close(execution[0])!=0){free(config);return 70;}
    if(n==(ssize_t)sizeof(error) && error>0){result.verifier_reason=CLIQ_VERIFIER_SPAWN_ERROR;result.verifier_errno=(uint32_t)error;}
    else if(n==0 && WIFEXITED(status)){result.verifier_reason=CLIQ_VERIFIER_EXIT;result.exit_status=(uint32_t)WEXITSTATUS(status);}
    else if(n==0 && WIFSIGNALED(status)){result.verifier_reason=CLIQ_VERIFIER_SIGNAL;result.verifier_signal=(uint32_t)WTERMSIG(status);}else{free(config);return 70;}
    free(config);if(!cliq_send(3,&result,NULL,0))return 70;while(read(3,&status,sizeof(status))<0 && errno==EINTR){}return 0;
}
#endif
