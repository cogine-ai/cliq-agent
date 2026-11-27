#ifndef CLIQ_DEPENDENCY_NPM_NATIVE_H
#define CLIQ_DEPENDENCY_NPM_NATIVE_H
#include "dependency-broker-input.h"
#include "dependency-npm-protocol.h"
#include "dependency-package-data.h"
#include "dependency-result-ack.h"
/* Included after the original controller/scope lifecycle. Its only peer
 * callbacks act on the same actual controller; no JS callback or FD is read. */
static bool dependency_owner_value(napi_env env,napi_value value,struct cliq_dependency_owner **owner) {
    bool accepted=false;
    return napi_check_object_type_tag(env,value,&CLIQ_DEPENDENCY_OWNER_TAG,&accepted)==napi_ok && accepted &&
        napi_unwrap(env,value,(void**)owner)==napi_ok && *owner && (*owner)->abi_version==CLIQ_DEPENDENCY_OWNER_ABI &&
        (*owner)->creator_pid==getpid() && (*owner)->assert_current && (*owner)->acquire_worker && (*owner)->borrow_package_inputs &&
        (*owner)->assert_current(*owner)==1;
}
static bool dependency_native_drop_result(struct native_scope *scope,uint32_t origin) {
    if(scope->dependency_custody_origin)return scope->dependency_custody_origin==origin;
    if(scope->verifier_value && napi_delete_reference(scope->controller->env,scope->verifier_value)!=napi_ok)return false;
    scope->verifier_value=NULL;scope->result_acknowledged=true;scope->result_ack_outputs_joined=true;scope->dependency_custody_origin=origin;return true;
}
static int dependency_peer_cancel(void *context) {
    struct native_scope *scope=context;scope->stop_requested=true;
    return close_controller(scope->controller)?1:-1;
}
static int dependency_peer_poll_joined(void *context,struct cliq_dependency_process_observation *output) {
    struct native_scope *scope=context;struct controller *controller=scope->controller;
    if(controller->retirement_failed || atomic_load(&native_retirement_failed))return -1;
    bool joined=scope->result_received || scope_ack_controller_joined(scope);if(!joined)return 0;
    memset(output,0,sizeof(*output));output->result_available=scope->result_received;output->death_joined=true;
    output->result_custody_retired=scope->dependency_custody_origin!=0;output->result_custody_origin=scope->dependency_custody_origin;
    output->result_acknowledged=scope->dependency_custody_origin==1;
    memcpy(&output->packet,scope->result_received?&scope->result:&scope->identity,sizeof(output->packet));return 1;
}
static int dependency_peer_release_execution(void *context,const struct cliq_dependency_binding *binding) {
    struct native_scope *scope=context;struct controller *controller=scope->controller;
    if(!scope->dependency || !scope->dependency_owner || scope->dependency_peer_released || !scope->dependency_inputs_sealed ||
        memcmp(binding,&scope->dependency_owner->binding,sizeof(*binding)) || scope->dependency_owner->assert_current(scope->dependency_owner)!=1 ||
        !scope->ready || scope->stopped || scope->released || controller->closed || controller->pending ||
        !scope->parent || !scope->parent->activated || scope->parent->stopped)return -1;
    scope->released=true; /* Before identity reads/send: never retransmit. */
    if(!scope_image_current(scope->parent) || !scope_image_current(scope))return -1;
    struct cliq_worker_packet request=cliq_packet(CLIQ_RELEASE_DEPENDENCY_NPM);request.scope=scope->id;
    memcpy(request.nonce,scope->identity.nonce,sizeof(request.nonce));return begin_request(controller,scope,&request,NULL,0)?1:-1;
}
static int dependency_peer_begin_ack(void *context) {
    struct native_scope *scope=context;struct controller *controller=scope->controller;
    if(!scope->dependency || !scope->result_received || !scope->released || controller->retirement_failed)return -1;
    if(scope->dependency_custody_origin)return 1;
    if(scope_ack_controller_joined(scope))return dependency_native_drop_result(scope,2)?1:-1;
    if(scope->result_ack_started)return 1;
    scope->result_ack_started=true;
    if(controller->closed)return 0;
    if(controller->pending || !scope->parent)return -1;
    struct cliq_worker_packet request=cliq_packet(CLIQ_ACK_DEPENDENCY_RESULT);request.scope=scope->id;request.parent=scope->parent->id;
    memcpy(request.nonce,scope->identity.nonce,sizeof(request.nonce));request.observed_at_ms=scope->result.observed_at_ms;
    if(!cliq_dependency_result_ack_valid(&request) || !begin_request(controller,scope,&request,NULL,0)){(void)close_controller(controller);return -1;}return 1;
}
static int dependency_peer_poll_ack(void *context) {
    struct native_scope *scope=context;struct controller *controller=scope->controller;
    if(controller->retirement_failed || atomic_load(&native_retirement_failed))return -1;
    if(scope->dependency_custody_origin)return 1;
    if(scope_ack_controller_joined(scope))return dependency_native_drop_result(scope,2)?1:-1;
    if(controller->closed || !scope->result_ack_started)return 0;
    if(controller->pending!=CLIQ_ACK_DEPENDENCY_RESULT || controller->pending_scope!=scope)return -1;
    struct cliq_worker_packet response;int observed=poll_response(controller,scope,CLIQ_ACK_DEPENDENCY_RESULT,&response);
    if(observed<0)return -1;
    if(!observed)return 0;
    if(!scope->parent || !cliq_dependency_result_ack_same(&response,scope->id,scope->parent->id,scope->identity.nonce,scope->result.observed_at_ms) ||
        !dependency_native_drop_result(scope,1)){(void)close_controller(controller);return -1;}return 1;
}
static void dependency_peer_release(void *context) {
    struct native_scope *scope=context;
    if(scope->dependency_peer_released || !scope->dependency_custody_origin || (!scope->result_received && !scope_ack_controller_joined(scope))){
        scope->controller->retirement_failed=true;atomic_store(&native_retirement_failed,true);return;}
    scope->dependency_peer_released=true;scope->dependency_owner=NULL;
    if(scope->dependency_owner_ref){if(napi_delete_reference(scope->controller->env,scope->dependency_owner_ref)!=napi_ok){
        scope->controller->retirement_failed=true;atomic_store(&native_retirement_failed,true);return;}scope->dependency_owner_ref=NULL;}
    scope_release_memory(scope);
}
static napi_value dependency_stage_chunk_call(napi_env env,napi_callback_info info) {
    size_t argc=1;napi_value args[1],self;struct native_scope *scope;void *data=NULL;size_t bytes=0;bool buffer=false;
    if(napi_get_cb_info(env,info,&argc,args,&self,NULL)!=napi_ok || argc!=1 || !tagged(env,self,&SCOPE_TAG,(void**)&scope) || !scope->dependency ||
        !scope->ready || scope->released || scope->stopped || scope->dependency_inputs_sealed || scope->controller->closed || scope->controller->pending ||
        !scope->dependency_owner || scope->dependency_owner->assert_current(scope->dependency_owner)!=1 ||
        napi_is_buffer(env,args[0],&buffer)!=napi_ok || !buffer || napi_get_buffer_info(env,args[0],&data,&bytes)!=napi_ok || !bytes || bytes>CLIQ_DEPENDENCY_CHUNK_BYTES)
        return failure(env,"dependency input chunk is outside its original fixed scope");
    int write_fd=memfd_create("cliq-dependency-input-chunk",MFD_CLOEXEC|MFD_ALLOW_SEALING),fd=-1;bool valid=write_fd>=0;
    size_t offset=0;while(valid && offset<bytes){ssize_t n=write(write_fd,(char*)data+offset,bytes-offset);if(n<0 && errno==EINTR)continue;if(n<=0){valid=false;break;}offset+=(size_t)n;}
    valid=valid && fchmod(write_fd,0400)==0 && fcntl(write_fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)==0;
    char path[64];if(valid){int length=snprintf(path,sizeof(path),"/proc/self/fd/%d",write_fd);valid=length>0 && (size_t)length<sizeof(path);if(valid)fd=open(path,O_RDONLY|O_CLOEXEC);valid=fd>=0;}
    if(!retire_descriptor(&write_fd))valid=false;
    struct cliq_worker_packet request=cliq_packet(CLIQ_STAGE_DEPENDENCY_CHUNK);request.scope=scope->id;memcpy(request.nonce,scope->identity.nonce,sizeof(request.nonce));
    valid=valid && begin_request(scope->controller,scope,&request,&fd,1);
    if(!retire_descriptor(&fd))valid=false;
    if(!valid){(void)close_controller(scope->controller);return failure(env,"dependency input chunk requires original recovery");}return undefined(env);
}
static napi_value dependency_seal_inputs_call(napi_env env,napi_callback_info info) {
    size_t argc=0;napi_value self;struct native_scope *scope;
    if(napi_get_cb_info(env,info,&argc,NULL,&self,NULL)!=napi_ok || !tagged(env,self,&SCOPE_TAG,(void**)&scope) || !scope->dependency ||
        !scope->ready || scope->released || scope->stopped || scope->dependency_inputs_sealed || scope->controller->closed || scope->controller->pending ||
        !scope->dependency_owner || scope->dependency_owner->assert_current(scope->dependency_owner)!=1)return failure(env,"dependency input seal is outside its original scope");
    struct cliq_worker_packet request=cliq_packet(CLIQ_SEAL_DEPENDENCY_INPUTS);request.scope=scope->id;memcpy(request.nonce,scope->identity.nonce,sizeof(request.nonce));
    if(!begin_request(scope->controller,scope,&request,NULL,0)){(void)close_controller(scope->controller);return failure(env,"dependency input seal requires original recovery");}return undefined(env);
}
static napi_value dependency_poll_inputs_call(napi_env env,napi_callback_info info) {
    size_t argc=0;napi_value self,value;struct native_scope *scope;
    if(napi_get_cb_info(env,info,&argc,NULL,&self,NULL)!=napi_ok || !tagged(env,self,&SCOPE_TAG,(void**)&scope) || !scope->dependency || scope->controller->closed ||
        scope->controller->pending_scope!=scope || (scope->controller->pending!=CLIQ_STAGE_DEPENDENCY_CHUNK && scope->controller->pending!=CLIQ_SEAL_DEPENDENCY_INPUTS))
        return failure(env,"dependency input has no original pending channel");
    unsigned command=scope->controller->pending;struct cliq_worker_packet response;int status=poll_response(scope->controller,scope,command,&response);
    struct cliq_worker_packet expected=cliq_packet(command);expected.scope=scope->id;memcpy(expected.nonce,scope->identity.nonce,sizeof(expected.nonce));
    if(status<0 || (status==1 && memcmp(&expected,&response,sizeof(expected)))){(void)close_controller(scope->controller);return failure(env,"dependency input acknowledgement is indeterminate");}
    if(status==1 && command==CLIQ_SEAL_DEPENDENCY_INPUTS)scope->dependency_inputs_sealed=true;
    napi_get_boolean(env,status==1,&value);return value;
}
static napi_value dependency_seal_asset(napi_env env,napi_callback_info info,bool data_image) {
    size_t argc=1;napi_value args[1];uint64_t source;
    if(napi_get_cb_info(env,info,&argc,args,NULL,NULL)!=napi_ok || argc!=1 || !number(env,args[0],&source) || source>INT32_MAX)return failure(env,"dependency asset requires its original held signed file");
    struct stat before,after;int flags=fcntl((int)source,F_GETFL),descriptor_flags=fcntl((int)source,F_GETFD);
    if(flags<0 || descriptor_flags<0 || (flags&O_ACCMODE)!=O_RDONLY || !(descriptor_flags&FD_CLOEXEC) || fstat((int)source,&before)!=0 ||
        !S_ISREG(before.st_mode) || before.st_nlink!=1 || before.st_size<1 || (before.st_mode&0022) || (before.st_uid!=geteuid() && before.st_uid!=0) ||
        (data_image?(uint64_t)before.st_size!=CLIQ_DEPENDENCY_DATA_BYTES:(uint64_t)before.st_size>CLIQ_DEPENDENCY_INPUT_BYTES))return failure(env,"dependency signed asset is outside its fixed shape");
    int writer=memfd_create("cliq-dependency-signed-data",MFD_CLOEXEC|MFD_ALLOW_SEALING),readonly=-1;bool valid=writer>=0;off_t offset=0;
    unsigned char bytes[65536];struct sha256_context hash;sha256_init(&hash);
    while(valid && offset<before.st_size){size_t wanted=(uint64_t)(before.st_size-offset)<sizeof(bytes)?(size_t)(before.st_size-offset):sizeof(bytes);
        ssize_t n=pread((int)source,bytes,wanted,offset);if(n<0 && errno==EINTR)continue;if(n<=0 || (size_t)n>wanted){valid=false;break;}
        size_t at=0;while(at<(size_t)n){ssize_t written=write(writer,bytes+at,(size_t)n-at);if(written<0 && errno==EINTR)continue;if(written<=0){valid=false;break;}at+=(size_t)written;}
        if(valid){sha256_update(&hash,bytes,(size_t)n);offset+=n;}}
    unsigned char tail;ssize_t extra=-1;if(valid){do{extra=pread((int)source,&tail,1,offset);}while(extra<0 && errno==EINTR);}
    unsigned char digest[32];char text[65];static const char hex[]="0123456789abcdef";sha256_final(&hash,digest);
    for(size_t i=0;i<32;i++){text[i*2]=hex[digest[i]>>4];text[i*2+1]=hex[digest[i]&15];}text[64]=0;
    valid=valid && extra==0 && offset==before.st_size && fstat((int)source,&after)==0 && cliq_dependency_data_same(&before,&after) &&
        (!data_image || !strcmp(text,"535b226efa5fa1c33d82e0634ac22a997c200db5799a787edd980f7de7a56f89")) &&
        fchmod(writer,0400)==0 && fcntl(writer,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)==0;
    if(valid){char path[64];int length=snprintf(path,sizeof(path),"/proc/self/fd/%d",writer);valid=length>0 && (size_t)length<sizeof(path);if(valid)readonly=open(path,O_RDONLY|O_CLOEXEC);valid=readonly>=0;}
    if(!retire_descriptor(&writer))valid=false;
    if(!valid){(void)retire_descriptor(&readonly);return failure(env,"dependency signed asset bytes changed or failed to join");}
    struct image *image=calloc(1,sizeof(*image));if(!image){(void)retire_descriptor(&readonly);return failure(env,"dependency asset allocation unavailable");}
    image->fd=readonly;image->byte_count=(uint64_t)before.st_size;memcpy(image->digest,text,65);
    napi_value result,identity;const napi_property_descriptor methods[]={{"close",NULL,fixed_script_close,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_create_object(env,&result)!=napi_ok || napi_create_object(env,&identity)!=napi_ok){(void)retire_descriptor(&image->fd);free(image);return failure(env,"dependency signed asset receiver unavailable");}
    set_number(env,identity,"byteCount",(double)image->byte_count);set_string(env,identity,"sha256",image->digest);
    if(napi_object_freeze(env,identity)!=napi_ok || napi_set_named_property(env,result,"identity",identity)!=napi_ok ||
        napi_type_tag_object(env,result,data_image?&DEPENDENCY_DATA_IMAGE_TAG:&DEPENDENCY_SCRIPT_IMAGE_TAG)!=napi_ok ||
        napi_define_properties(env,result,1,methods)!=napi_ok || napi_wrap(env,result,image,finalize_image,NULL,NULL)!=napi_ok){
        (void)retire_descriptor(&image->fd);free(image);return failure(env,"dependency signed asset receiver unavailable");}
    napi_object_freeze(env,result);return result;
}
static napi_value seal_dependency_script(napi_env env,napi_callback_info info){return dependency_seal_asset(env,info,false);}
static napi_value seal_dependency_data(napi_env env,napi_callback_info info){return dependency_seal_asset(env,info,true);}
static napi_value create_dependency_npm(napi_env env,napi_callback_info info) {
    size_t argc=11;napi_value args[11],self;struct controller *controller;struct native_scope *parent;
    struct image *helper,*bwrap,*script,*image,*input;struct cliq_guest_toolchain *guest;struct cliq_dependency_owner *owner;uint64_t generation,allow;
    if(napi_get_cb_info(env,info,&argc,args,&self,NULL)!=napi_ok || argc!=11 || atomic_load(&native_retirement_failed) ||
        !tagged(env,self,&CONTROLLER_TAG,(void**)&controller) || controller->closed || controller->inspection_only || !controller->ready || controller->pending ||
        (controller->source_requested && !controller->preparation_finished) || controller->next_scope>=CLIQ_WORKER_MAX_SCOPES ||
        !number(env,args[0],&generation) || generation>INT32_MAX || !tagged(env,args[1],&SCOPE_TAG,(void**)&parent) || parent->controller!=controller ||
        parent->invocation || parent->stopped || !parent->activated || !tagged(env,args[2],&IMAGE_TAG,(void**)&helper) || helper->fd<0 ||
        !tagged(env,args[3],&IMAGE_TAG,(void**)&bwrap) || bwrap->fd<0 || !tagged(env,args[5],&DEPENDENCY_SCRIPT_IMAGE_TAG,(void**)&script) || script->fd<0 ||
        !tagged(env,args[6],&DEPENDENCY_DATA_IMAGE_TAG,(void**)&image) || image->fd<0 || !tagged(env,args[7],&IMAGE_TAG,(void**)&input) || input->fd<0 ||
        !dependency_owner_value(env,args[8],&owner) || !field_number(env,args[10],"allowInstallScripts",&allow) || allow>1)
        return failure(env,"dependency invocation requires its original held native owner and fixed signed assets");
    if(!tagged(env,args[4],allow?&CLIQ_BUILTIN_GUEST_TOOLCHAIN_TAG:&CLIQ_GUEST_TOOLCHAIN_TAG,(void**)&guest) || guest->abi_version!=CLIQ_GUEST_ABI_VERSION ||
        !atomic_load_explicit(&guest->ready,memory_order_acquire) || atomic_load(&guest->revoked) || !guest->file_count || guest->file_count>CLIQ_GUEST_MAX_FILES ||
        (allow && guest->builtin_recipe_version!=1))return failure(env,"dependency invocation has no original exact signed guest");
    bool is_buffer=false;void *binding_bytes=NULL;size_t binding_size=0;struct cliq_dependency_binding binding;
    if(napi_is_buffer(env,args[9],&is_buffer)!=napi_ok || !is_buffer || napi_get_buffer_info(env,args[9],&binding_bytes,&binding_size)!=napi_ok ||
        !cliq_dependency_binding_read(binding_bytes,binding_size,&binding) || memcmp(&binding,&owner->binding,sizeof(binding)))return failure(env,"dependency invocation differs from its original permanent claim");
    struct cliq_dependency_config *fixed=calloc(1,sizeof(*fixed));if(!fixed)return failure(env,"dependency configuration allocation unavailable");
    struct cliq_verifier_config *config=&fixed->capture;config->magic=CLIQ_VERIFIER_CONFIG_MAGIC;config->version=1;config->file_count=guest->file_count;
    strcpy(config->executable,"/usr/bin/node");strcpy(config->cwd,"/work");config->argument_count=3;config->environment_count=10;
    fixed->magic=CLIQ_DEPENDENCY_CONFIG_MAGIC;fixed->version=1;fixed->allow_scripts=(uint32_t)allow;fixed->package_count=owner->package_count;
    fixed->script_bytes=script->byte_count;memcpy(fixed->script_digest,script->digest,65);fixed->data_bytes=image->byte_count;memcpy(fixed->data_digest,image->digest,65);
    memcpy(fixed->dependency_plan_digest,owner->plan_digest,65);memcpy(fixed->descriptor_sequence_digest,owner->descriptor_sequence_digest,65);
    struct stat initial,modules,helper_info;struct cliq_worker_packet request=cliq_packet(CLIQ_CREATE_DEPENDENCY_NPM);request.scope=controller->next_scope;request.parent=parent->id;
    bool valid=scope_projection(env,args[10],&request) && field_number(env,args[10],"timeoutMs",&config->timeout_ms) && field_number(env,args[10],"outputLimitBytes",&config->output_limit) &&
        config->output_limit<=request.max_output_bytes && field_string(env,args[10],"planRef",request.plan_ref,sizeof(request.plan_ref)) &&
        field_string(env,args[10],"sandboxLaunchSpecRef",request.sandbox_launch_ref,sizeof(request.sandbox_launch_ref)) && !strcmp(request.sandbox_launch_ref,owner->sandbox_launch_spec_ref) &&
        field_string(env,args[10],"sandboxLaunchSpecDigest",request.sandbox_launch_digest,sizeof(request.sandbox_launch_digest)) &&
        builtin_data_identity(input->fd,&fixed->input_bytes,fixed->input_digest) && fixed->input_bytes<=CLIQ_DEPENDENCY_INPUT_BYTES &&
        fstat(helper->fd,&helper_info)==0 && helper_info.st_size>0 && (fixed->init_bytes=(uint64_t)helper_info.st_size)>0 &&
        fstat((int)generation,&initial)==0 && S_ISDIR(initial.st_mode) && (uint64_t)initial.st_dev==request.generation_device && (uint64_t)initial.st_ino==request.generation_inode &&
        request.generation_device==parent->identity.generation_device && request.generation_inode==parent->identity.generation_inode;
    memcpy(request.generation_ref,parent->identity.generation_ref,sizeof(request.generation_ref));
    if(valid){struct stat rule;errno=0;valid=fstatat((int)generation,".npmrc",&rule,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;}
    const char *arguments[]={"/usr/bin/node","--no-addons",CLIQ_DEPENDENCY_SCRIPT_PATH};
    const char *environment[]={"PATH=/usr/bin:/bin","HOME=/home/cliq","TMPDIR=/tmp","LANG=C.UTF-8","LC_ALL=C.UTF-8","TZ=UTC","GIT_OPTIONAL_LOCKS=0","NODE_EXTRA_CA_CERTS=","NPM_CONFIG_USERCONFIG=/runtime/npm-config/user","NPM_CONFIG_GLOBALCONFIG=/runtime/npm-config/global"};
    for(uint32_t i=0;valid && i<3;i++)valid=verifier_string(config,arguments[i],&config->arguments[i]);
    for(uint32_t i=0;valid && i<10;i++)valid=verifier_string(config,environment[i],&config->environment[i]);
    int files[CLIQ_WORKER_MAX_FDS]={(int)generation,helper->fd,bwrap->fd,-1,script->fd,input->fd,image->fd,-1};
    for(uint32_t i=0;valid && i<guest->file_count;i++){struct stat actual;int seals=fcntl(guest->files[i].fd,F_GET_SEALS),required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
        valid=fstat(guest->files[i].fd,&actual)==0 && S_ISREG(actual.st_mode) && actual.st_size>0 && (uint64_t)actual.st_size==guest->files[i].byte_count && seals==required;
        if(valid){memcpy(config->files[i].path,guest->files[i].path,sizeof(config->files[i].path));memcpy(config->files[i].digest,guest->files[i].digest,65);config->files[i].byte_count=guest->files[i].byte_count;files[8+i]=guest->files[i].fd;}}
    if(!valid){free(config);return failure(env,"dependency invocation source or fixed assets differ");}
    struct native_scope *scope=calloc(1,sizeof(*scope));if(!scope){free(config);return failure(env,"dependency native lifetime allocation unavailable");}
    scope->controller=controller;scope->id=request.scope;scope->identity=request;scope->image_fd=-1;scope->invocation=true;scope->verifier=true;scope->dependency=true;scope->parent=parent;
    scope->references=2;scope->output_limit=config->output_limit;scope->dependency_owner=owner;
    napi_value result;const napi_property_descriptor methods[]={
        {"observe",NULL,scope_inspect,NULL,NULL,NULL,napi_default,NULL},{"pollReady",NULL,scope_poll_ready,NULL,NULL,NULL,napi_default,NULL},
        {"stagePackageChunk",NULL,dependency_stage_chunk_call,NULL,NULL,NULL,napi_default,NULL},{"sealPackageInputs",NULL,dependency_seal_inputs_call,NULL,NULL,NULL,napi_default,NULL},
        {"pollPackageInputs",NULL,dependency_poll_inputs_call,NULL,NULL,NULL,napi_default,NULL},{"result",NULL,scope_result,NULL,NULL,NULL,napi_default,NULL},
        {"stop",NULL,scope_stop,NULL,NULL,NULL,napi_default,NULL},{"pollStopped",NULL,scope_poll_stopped,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_create_object(env,&result)!=napi_ok || napi_type_tag_object(env,result,&SCOPE_TAG)!=napi_ok || napi_define_properties(env,result,8,methods)!=napi_ok ||
        napi_create_reference(env,args[8],1,&scope->dependency_owner_ref)!=napi_ok || napi_wrap(env,result,scope,finalize_scope,NULL,NULL)!=napi_ok){
        if(scope->dependency_owner_ref)napi_delete_reference(env,scope->dependency_owner_ref);
        free(scope);
        free(config);
        return failure(env,"dependency receiver allocation unavailable");
        }
    scope->next=controller->scopes;controller->scopes=scope;controller->references++;controller->next_scope++;
    const struct cliq_dependency_process_peer peer={scope,dependency_peer_cancel,dependency_peer_poll_joined,dependency_peer_release_execution,dependency_peer_begin_ack,dependency_peer_poll_ack,dependency_peer_release};
    if(owner->acquire_worker(owner,&binding,fixed->dependency_plan_digest,request.sandbox_launch_ref,&peer)!=1){free(config);(void)close_controller(controller);return failure(env,"dependency original native owner refused its single scope");}
    scope->references++;
    if(valid){errno=0;if(fstatat((int)generation,"node_modules",&modules,AT_SYMLINK_NOFOLLOW)<0){
        valid=errno==ENOENT && mkdirat((int)generation,"node_modules",0755)==0;
        if(valid){int directory=openat((int)generation,"node_modules",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);valid=directory>=0 && fchmod(directory,0755)==0 && fstat(directory,&modules)==0;
            if(directory>=0 && !retire_descriptor(&directory))valid=false;}}
        valid=valid && S_ISDIR(modules.st_mode) && (modules.st_mode&07777)==0755 && modules.st_uid==geteuid() && modules.st_dev==initial.st_dev;
        if(valid){fixed->node_modules_device=(uint64_t)modules.st_dev;fixed->node_modules_inode=(uint64_t)modules.st_ino;}}
    struct cliq_dependency_package_inputs metadata={.fd=-1};
    valid=valid && owner->borrow_package_inputs(owner,&metadata)==1;files[7]=metadata.fd;fixed->metadata_bytes=metadata.bytes;memcpy(fixed->metadata_digest,metadata.digest,65);
    uint64_t root_budget,scratch_budget;valid=valid && cliq_dependency_storage(fixed,&request,&root_budget,&scratch_budget);
    int descriptor=valid?memfd_create("cliq-dependency-config",MFD_CLOEXEC|MFD_ALLOW_SEALING):-1;
    if(descriptor<0 || write(descriptor,fixed,sizeof(*fixed))!=(ssize_t)sizeof(*fixed) || fchmod(descriptor,0400)!=0 || fcntl(descriptor,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)!=0)valid=false;
    free(config);files[3]=descriptor;
    if(valid)valid=begin_request(controller,scope,&request,files,8+guest->file_count);
    if(!retire_descriptor(&descriptor))valid=false;
    if(!retire_descriptor(&metadata.fd))valid=false;
    if(!valid){(void)close_controller(controller);return failure(env,"dependency native creation is indeterminate; retain the original claim");}return result;
}
#endif
