#ifndef CLIQ_DEPENDENCY_BROKER_H
#define CLIQ_DEPENDENCY_BROKER_H
/* Distinct compile image. Public fixed-path GET and the original offline
 * scope share this one owner; no credential/model owner is accepted here. */
#include "dependency-broker-input.h"
#include "dependency-package-data.h"
#include "dependency-http.h"
struct dependency_broker;
struct dependency_reader;
struct dependency_package {
    struct cliq_dependency_package_data data; struct dependency_broker *broker;
    struct dependency_package *next; struct dependency_reader *readers;
    napi_ref parent; uint32_t index; unsigned native_borrows; bool closed, published, finalized;
};
struct dependency_reader {
    struct cliq_dependency_package_reader reader; struct dependency_package *package;
    struct dependency_reader *next; napi_ref parent; bool finalized;
};
enum dependency_stage { DEPENDENCY_CONNECT, DEPENDENCY_GET, DEPENDENCY_INPUTS_SEAL, DEPENDENCY_RETIRE };
struct dependency_broker {
    struct cliq_dependency_owner owner; /* genuine friend ABI must be first */
    napi_env env; struct cliq_dependency_configuration *config; struct cliq_dependency_descriptors descriptors;
    unsigned char *trust; size_t trust_size; pthread_mutex_t mutex; bool mutex_ready;
    struct timespec outer_deadline,request_deadline,close_deadline;
    GCancellable *cancel; atomic_bool request_expired;atomic_uint active_releases;
    napi_async_work work,unretired_work[4];size_t unretired_work_count;napi_deferred ready_deferred,phase_deferred,close_deferred;
    napi_ref handle,close_promise; napi_async_cleanup_hook_handle cleanup_hook;
    uv_timer_t timer; bool timer_ready,timer_closing,timer_closed,working,env_closing;
    bool bound,connected,attempt_completed,retry_permitted,request_started,network_started,network_retirement_failed,token_revoked;
    bool process_released,process_ack_started,process_acknowledged,process_custody_retired,process_peer_released;
    bool close_requested,retired,finalized,settlement_locked,settlement_borrowed,close_rejected;
    unsigned native_borrows;bool integrity_matched; uint32_t next_index,current_attempt,connection_count,request_count;
    uint64_t total_transferred; enum dependency_stage stage; _Atomic(const char*) error;
    struct cliq_dependency_process_peer peer; struct cliq_dependency_process_observation process;
    struct dependency_package *packages,*pending_package; const struct cliq_dependency_descriptor *descriptor;
    const struct cliq_dependency_target *target;
    GSocketConnection *connection; GSocket *socket; SSL_CTX *tls_context; SSL *tls; EVP_MD_CTX *integrity_hash;
    int output_fd,inputs_fd,inputs_read_fd;struct stat inputs_identity;struct sha256_context inputs_hash;
    uint64_t inputs_reserved,inputs_bytes;uint32_t inputs_count;char inputs_digest[65];bool inputs_failed,inputs_sealed,inputs_borrowed;
    struct sha256_context content_hash; struct cliq_dependency_http http;
    struct dependency_broker *unretired_next;
};
static const napi_type_tag dependency_failure_tag={UINT64_C(0xb9b116e567ab4a69),UINT64_C(0xacfd92bfb43a60a1)};
static const napi_type_tag dependency_package_tag={UINT64_C(0x1de902aca61a4bba),UINT64_C(0xb78d96cc0714be6c)};
static const napi_type_tag dependency_reader_tag={UINT64_C(0xb20add2c830748cd),UINT64_C(0x82318fc7cc8ab564)};
static const napi_type_tag dependency_settlement_tag={UINT64_C(0x490fb085bdbb493c),UINT64_C(0x972f702660dcf68c)};
struct dependency_settlement {struct dependency_broker *broker;napi_env env;napi_ref parent;pid_t creator;bool active;};
struct dependency_failure {
    struct dependency_broker *broker;napi_env env;napi_ref parent;pid_t creator;
    const char *code;uint32_t index,attempt;uint64_t received;bool eof,network_started,request_started,io_joined;
};
static struct dependency_broker *unretired_dependencies;
static void dependency_begin_close(struct dependency_broker *);
static void dependency_try_free(struct dependency_broker *);
static void dependency_release_borrow(struct dependency_broker *);
static void dependency_maybe_finish(struct dependency_broker *);
static bool dependency_queue(struct dependency_broker *,enum dependency_stage);
static int dependency_assert_current(struct cliq_dependency_owner *);
static bool dependency_fail(struct dependency_broker *broker,const char *code) {
    const char *expected=NULL;atomic_compare_exchange_strong(&broker->error,&expected,code);return false;
}
static void dependency_unsafe(struct dependency_broker *broker) {
    atomic_store(&broker->owner.unsafe,true);atomic_store(&retirement_failed,true);
}
#include "dependency-broker-network.h"
#include "dependency-package-inputs.h"
static void dependency_failure_finalize(napi_env env,void *data,void *hint) {
    (void)hint;struct dependency_failure *failure=data;
    if(failure->parent && !failure->broker->env_closing)napi_delete_reference(env,failure->parent);
    struct dependency_broker *broker=failure->broker;wipe(failure,sizeof(*failure));free(failure);dependency_release_borrow(broker);
}
static napi_value dependency_error_code(struct dependency_broker *broker,const char *forced_code) {
    napi_value text,error;napi_create_string_utf8(broker->env,"Installed dependency broker operation refused",NAPI_AUTO_LENGTH,&text);
    napi_create_error(broker->env,NULL,text,&error);bool unsafe=atomic_load(&broker->owner.unsafe);
    const char *code=unsafe?"resource_retirement":forced_code?forced_code:atomic_load(&broker->error)?atomic_load(&broker->error):"operation_refused";
    set_string(broker->env,error,"code",unsafe?"ERR_CLIQ_RESOURCE_RETIREMENT":"ERR_CLIQ_DEPENDENCY_BROKER");
    set_string(broker->env,error,"brokerCode",code);
    if(broker->working)return error; /* No concurrent reads of worker-owned facts. */
    set_number(broker->env,error,"packageIndex",broker->next_index);set_number(broker->env,error,"attempt",broker->current_attempt);
    set_number(broker->env,error,"receivedBytes",(double)broker->http.received_bytes);set_boolean(broker->env,error,"eof",broker->http.eof);
    set_boolean(broker->env,error,"networkStarted",broker->network_started);set_boolean(broker->env,error,"requestStarted",broker->request_started);
    struct dependency_failure *failure=calloc(1,sizeof(*failure));napi_value parent;
    if(failure && broker->handle && napi_get_reference_value(broker->env,broker->handle,&parent)==napi_ok &&
        napi_create_reference(broker->env,parent,1,&failure->parent)==napi_ok){
        failure->broker=broker;failure->env=broker->env;failure->creator=getpid();failure->code=code;failure->index=broker->next_index;failure->attempt=broker->current_attempt;
        failure->received=broker->http.received_bytes;failure->eof=broker->http.eof;failure->network_started=broker->network_started;failure->request_started=broker->request_started;
        failure->io_joined=!broker->working && !broker->connection && !broker->tls && !broker->tls_context && broker->output_fd<0;
        if(napi_type_tag_object(broker->env,error,&dependency_failure_tag)!=napi_ok || napi_wrap(broker->env,error,failure,dependency_failure_finalize,NULL,NULL)!=napi_ok){
            napi_delete_reference(broker->env,failure->parent);free(failure);}
        else broker->native_borrows++;
    }else free(failure);
    return error;
}
static napi_value dependency_error(struct dependency_broker *broker){return dependency_error_code(broker,NULL);}
static napi_value dependency_throw(struct dependency_broker *broker,const char *code) {napi_throw(broker->env,dependency_error_code(broker,code));return NULL;}
static bool dependency_buffer(napi_env env,napi_value value,size_t max,const unsigned char **bytes,size_t *size) {
    bool buffer=false;void *data=NULL;
    if(napi_is_buffer(env,value,&buffer)!=napi_ok || !buffer || napi_get_buffer_info(env,value,&data,size)!=napi_ok || !*size || *size>max)return false;
    *bytes=data;return true;
}
static bool dependency_u32(napi_env env,napi_value value,uint32_t *output) {
    double number;if(napi_get_value_double(env,value,&number)!=napi_ok || !isfinite(number) || number<0 || number>UINT32_MAX || number!=(uint32_t)number)return false;
    *output=(uint32_t)number;return true;
}
static struct dependency_broker *dependency_receiver(napi_env env,napi_callback_info info,size_t *argc,napi_value *args) {
    napi_value receiver;bool tag=false;struct cliq_dependency_owner *owner=NULL;
    if(napi_get_cb_info(env,info,argc,args,&receiver,NULL)!=napi_ok || napi_check_object_type_tag(env,receiver,&CLIQ_DEPENDENCY_OWNER_TAG,&tag)!=napi_ok || !tag ||
        napi_unwrap(env,receiver,(void**)&owner)!=napi_ok || !owner || owner->abi_version!=CLIQ_DEPENDENCY_OWNER_ABI || owner->creator_pid!=getpid() ||
        owner->environment!=env || syscall(SYS_gettid)!=getpid()) {napi_throw_type_error(env,NULL,"Invalid dependency owner");return NULL;}
    return (struct dependency_broker*)owner;
}
static bool dependency_binding_argument(struct dependency_broker *broker,napi_value value,struct cliq_dependency_binding *binding) {
    const unsigned char *bytes;size_t size;
    if(!dependency_buffer(broker->env,value,8192,&bytes,&size))return false;
    unsigned char original[8192];memcpy(original,bytes,size);
    return cliq_dependency_binding_read(original,size,binding) && !strcmp(binding->token_digest,broker->owner.binding.token_digest);
}
static bool dependency_binding_current(struct dependency_broker *broker,napi_value value) {
    struct cliq_dependency_binding binding;
    return broker->bound && dependency_binding_argument(broker,value,&binding) && !memcmp(&binding,&broker->owner.binding,sizeof(binding));
}
static bool dependency_outer_current(struct dependency_broker *broker) {
    struct timespec now;
    return !atomic_load(&broker->owner.closing) && !atomic_load(&broker->owner.unsafe) && !broker->descriptors.failed && !broker->token_revoked &&
        clock_gettime(CLOCK_MONOTONIC,&now)==0 && (now.tv_sec<broker->outer_deadline.tv_sec ||
        (now.tv_sec==broker->outer_deadline.tv_sec && now.tv_nsec<broker->outer_deadline.tv_nsec));
}
static int dependency_assert_current(struct cliq_dependency_owner *owner) {
    if(!owner || owner->abi_version!=CLIQ_DEPENDENCY_OWNER_ABI || owner->creator_pid!=getpid() || syscall(SYS_gettid)!=getpid())return -1;
    struct dependency_broker *broker=(struct dependency_broker*)owner;
    return dependency_outer_current(broker) && broker->bound && broker->descriptors.sealed && !broker->descriptors.failed && atomic_load(&owner->fence_retained)?1:0;
}
static int dependency_acquire_worker(struct cliq_dependency_owner *owner,const struct cliq_dependency_binding *binding,const char *plan,const char *launch,const struct cliq_dependency_process_peer *peer) {
    if(dependency_assert_current(owner)!=1 || !binding || !plan || !launch || !peer || !peer->context || !peer->cancel || !peer->poll_joined ||
        !peer->release_execution || !peer->begin_output_ack || !peer->poll_output_ack || !peer->release)return -1;
    struct dependency_broker *broker=(struct dependency_broker*)owner;
    if(broker->working || broker->connected || broker->next_index!=owner->package_count || broker->pending_package || !broker->inputs_sealed ||
        memcmp(binding,&owner->binding,sizeof(*binding)) || strcmp(plan,owner->plan_digest) || strcmp(launch,owner->sandbox_launch_spec_ref) ||
        atomic_exchange(&owner->worker_claimed,true))return -1;
    broker->peer=*peer;broker->native_borrows++;return 1;
}
static bool dependency_process_poll(struct dependency_broker *broker) {
    if(!atomic_load(&broker->owner.worker_claimed) || broker->process_peer_released)return true;
    struct cliq_dependency_process_observation observation={0};int status=broker->peer.poll_joined(broker->peer.context,&observation);
    if(status<0){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");return false;}
    if(status==1){if(!observation.death_joined){dependency_unsafe(broker);return dependency_fail(broker,"resource_retirement");}
        if(observation.result_custody_origin>2 || (observation.result_acknowledged && (!observation.result_custody_retired || observation.result_custody_origin!=1)) ||
            (observation.result_custody_retired && observation.result_custody_origin==0) || (!observation.result_custody_retired && observation.result_custody_origin!=0)){
            dependency_unsafe(broker);return dependency_fail(broker,"resource_retirement");}
        broker->process=observation;broker->process_acknowledged=observation.result_acknowledged;broker->process_custody_retired=observation.result_custody_retired;atomic_store(&broker->owner.worker_joined,true);}
    return status==1;
}
static void dependency_package_retire(struct dependency_package *package) {
    if(package->closed)return;
    for(struct dependency_reader *reader=package->readers;reader;reader=reader->next)if(!reader->reader.joined)(void)cliq_dependency_data_join(&reader->reader);
    if(package->data.initialized && cliq_dependency_data_retire(&package->data)!=CLIQ_DEPENDENCY_DATA_OK){dependency_unsafe(package->broker);dependency_fail(package->broker,"resource_retirement");return;}
    package->closed=true;
}
static void dependency_try_free(struct dependency_broker *broker) {
    /* The native count is independent of environment finalizer/ref ordering. */
    if(!broker->finalized || !broker->retired || atomic_load(&broker->owner.unsafe) || broker->working || broker->native_borrows ||
        atomic_load(&broker->owner.fence_retained) || broker->settlement_locked || broker->settlement_borrowed)return;
    if(broker->close_promise && !broker->env_closing)napi_delete_reference(broker->env,broker->close_promise);
    if(broker->handle && !broker->env_closing)napi_delete_reference(broker->env,broker->handle);
    if(broker->mutex_ready && pthread_mutex_destroy(&broker->mutex)){atomic_store(&retirement_failed,true);return;}
    cliq_dependency_descriptors_dispose(&broker->descriptors);free(broker->trust);free(broker->config);wipe(broker,sizeof(*broker));free(broker);
}
static void dependency_release_borrow(struct dependency_broker *broker) {
    if(!broker->native_borrows){dependency_unsafe(broker);atomic_store(&retirement_failed,true);return;}
    broker->native_borrows--;dependency_try_free(broker);
}
static void dependency_finalize(napi_env env,void *data,void *hint) {
    (void)env;(void)hint;struct dependency_broker *broker=data;broker->finalized=true;dependency_try_free(broker);
}
static void dependency_package_try_free(struct dependency_package *package) {
    if(!package->finalized || !package->closed || package->readers || package->native_borrows || package->data.unsafe)return;
    struct dependency_broker *broker=package->broker;wipe(package,sizeof(*package));free(package);dependency_release_borrow(broker);
}
static void dependency_reader_finalize(napi_env env,void *data,void *hint) {
    (void)hint;struct dependency_reader *reader=data;struct dependency_package *package=reader->package;
    if(!reader->reader.joined && cliq_dependency_data_join(&reader->reader)!=CLIQ_DEPENDENCY_DATA_OK)dependency_unsafe(package->broker);
    struct dependency_reader **link=&package->readers;while(*link && *link!=reader)link=&(*link)->next;if(*link)*link=reader->next;
    if(reader->parent && !package->broker->env_closing)napi_delete_reference(env,reader->parent);
    wipe(reader,sizeof(*reader));
    free(reader);
    if(!package->native_borrows){dependency_unsafe(package->broker);return;}package->native_borrows--;dependency_package_try_free(package);
}
static struct dependency_reader *dependency_reader_receiver(napi_env env,napi_callback_info info) {
    napi_value receiver,args[1];size_t argc=1;bool tag=false;struct dependency_reader *reader=NULL;
    if(napi_get_cb_info(env,info,&argc,args,&receiver,NULL)!=napi_ok || argc || napi_check_object_type_tag(env,receiver,&dependency_reader_tag,&tag)!=napi_ok || !tag ||
        napi_unwrap(env,receiver,(void**)&reader)!=napi_ok || !reader || reader->package->broker->env!=env ||
        reader->package->broker->owner.creator_pid!=getpid() || syscall(SYS_gettid)!=getpid()){napi_throw_type_error(env,NULL,"Invalid dependency package reader");return NULL;}return reader;
}
static napi_value dependency_reader_read(napi_env env,napi_callback_info info) {
    struct dependency_reader *reader=dependency_reader_receiver(env,info);if(!reader)return NULL;
    unsigned char bytes[CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES];size_t size=0;
    if(cliq_dependency_data_read(&reader->reader,bytes,&size)!=CLIQ_DEPENDENCY_DATA_OK)return dependency_throw(reader->package->broker,"package_reader_refused");
    napi_value value;if(napi_create_buffer_copy(env,size,bytes,NULL,&value)!=napi_ok)return dependency_throw(reader->package->broker,"package_storage_unavailable");return value;
}
static napi_value dependency_reader_complete(napi_env env,napi_callback_info info) {
    struct dependency_reader *reader=dependency_reader_receiver(env,info);if(!reader)return NULL;
    if(!cliq_dependency_data_complete(&reader->reader))return dependency_throw(reader->package->broker,"package_reader_incomplete");
    return NULL;
}
static napi_value dependency_reader_close(napi_env env,napi_callback_info info) {
    struct dependency_reader *reader=dependency_reader_receiver(env,info);if(!reader)return NULL;
    if(cliq_dependency_data_join(&reader->reader)!=CLIQ_DEPENDENCY_DATA_OK){dependency_unsafe(reader->package->broker);return dependency_throw(reader->package->broker,"resource_retirement");}return NULL;
}
static void dependency_package_finalize(napi_env env,void *data,void *hint) {
    (void)hint;struct dependency_package *package=data;package->finalized=true;dependency_package_retire(package);
    struct dependency_package **link=&package->broker->packages;while(*link && *link!=package)link=&(*link)->next;if(*link)*link=package->next;
    if(package->parent && !package->broker->env_closing)napi_delete_reference(env,package->parent);
    package->parent=NULL;
    dependency_package_try_free(package);
}
static struct dependency_package *dependency_package_receiver(napi_env env,napi_callback_info info,napi_value *receiver) {
    napi_value args[1];size_t argc=1;bool tag=false;struct dependency_package *package=NULL;
    if(napi_get_cb_info(env,info,&argc,args,receiver,NULL)!=napi_ok || argc || napi_check_object_type_tag(env,*receiver,&dependency_package_tag,&tag)!=napi_ok || !tag ||
        napi_unwrap(env,*receiver,(void**)&package)!=napi_ok || !package || package->broker->env!=env || package->broker->owner.creator_pid!=getpid() || syscall(SYS_gettid)!=getpid()){
        napi_throw_type_error(env,NULL,"Invalid dependency package owner");return NULL;}return package;
}
static napi_value dependency_package_open(napi_env env,napi_callback_info info) {
    napi_value receiver;struct dependency_package *package=dependency_package_receiver(env,info,&receiver);if(!package)return NULL;
    if(package->closed || atomic_load(&package->broker->owner.closing))return dependency_throw(package->broker,"package_reader_refused");
    struct dependency_reader *reader=calloc(1,sizeof(*reader));if(!reader)return dependency_throw(package->broker,"package_storage_unavailable");reader->package=package;
    if(cliq_dependency_data_open(&package->data,&reader->reader)!=CLIQ_DEPENDENCY_DATA_OK){free(reader);return dependency_throw(package->broker,"package_reader_refused");}
    napi_value value;napi_create_object(env,&value);const napi_property_descriptor methods[]={
        {"readChunk",NULL,dependency_reader_read,NULL,NULL,NULL,napi_default,NULL},
        {"assertComplete",NULL,dependency_reader_complete,NULL,NULL,NULL,napi_default,NULL},
        {"close",NULL,dependency_reader_close,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_create_reference(env,receiver,1,&reader->parent)!=napi_ok || napi_type_tag_object(env,value,&dependency_reader_tag)!=napi_ok ||
        napi_wrap(env,value,reader,dependency_reader_finalize,NULL,NULL)!=napi_ok){
        (void)cliq_dependency_data_join(&reader->reader);if(reader->parent)napi_delete_reference(env,reader->parent);free(reader);
        dependency_unsafe(package->broker);return dependency_throw(package->broker,"resource_retirement");}
    package->native_borrows++;reader->next=package->readers;package->readers=reader;
    if(napi_define_properties(env,value,3,methods)!=napi_ok){dependency_unsafe(package->broker);return dependency_throw(package->broker,"resource_retirement");}
    napi_object_freeze(env,value);return value;
}
static napi_value dependency_package_close(napi_env env,napi_callback_info info) {
    napi_value receiver;struct dependency_package *package=dependency_package_receiver(env,info,&receiver);if(!package)return NULL;
    if(package->closed)return NULL;
    if(package->data.readers)return dependency_throw(package->broker,"package_readers_not_joined");
    if(cliq_dependency_data_retire(&package->data)!=CLIQ_DEPENDENCY_DATA_OK){dependency_unsafe(package->broker);return dependency_throw(package->broker,"resource_retirement");}
    package->closed=true;
    if(!dependency_input_append(package->broker,package))return dependency_throw(package->broker,"package_metadata_refused");
    /* Closing an actual successful data child advances only its original
     * package index. It cannot recycle an attempt, scope or dispatch. */
    if(package->index==package->broker->next_index){package->broker->next_index++;package->broker->attempt_completed=false;package->broker->retry_permitted=false;package->broker->current_attempt=0;}
    return NULL;
}
static napi_value dependency_package_value(struct dependency_broker *broker,struct dependency_package *package) {
    napi_value value,owner;napi_create_object(broker->env,&value);
    if(napi_get_reference_value(broker->env,broker->handle,&owner)!=napi_ok || napi_create_reference(broker->env,owner,1,&package->parent)!=napi_ok)return NULL;
    const napi_property_descriptor methods[]={{"openReader",NULL,dependency_package_open,NULL,NULL,NULL,napi_default,NULL},{"close",NULL,dependency_package_close,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_type_tag_object(broker->env,value,&dependency_package_tag)!=napi_ok || napi_wrap(broker->env,value,package,dependency_package_finalize,NULL,NULL)!=napi_ok)return NULL;
    package->published=true;broker->native_borrows++;package->next=broker->packages;broker->packages=package;
    if(napi_define_properties(broker->env,value,2,methods)!=napi_ok)return NULL;
    set_number(broker->env,value,"byteCount",(double)package->data.byte_count);set_string(broker->env,value,"sha256",package->data.digest);
    napi_object_freeze(broker->env,value);return value;
}
static void dependency_worker(napi_env env,void *data) {
    (void)env;struct dependency_broker *broker=data;
    if(broker->stage==DEPENDENCY_RETIRE){dependency_network_retire(broker);return;}
    if(broker->stage==DEPENDENCY_INPUTS_SEAL){(void)dependency_inputs_seal(broker);return;}
    if(pthread_mutex_lock(&broker->mutex)){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");return;}
    bool released=!broker->token_revoked && dependency_network_live(broker);
    if(released)atomic_fetch_add(&broker->active_releases,1);
    if(pthread_mutex_unlock(&broker->mutex)){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");return;}
    if(!released){dependency_fail(broker,"cancelled_or_expired");dependency_network_retire(broker);return;}
    if(broker->stage==DEPENDENCY_CONNECT){if(!dependency_network_connect(broker))dependency_network_retire(broker);}
    else{(void)dependency_network_get(broker);dependency_network_retire(broker);}
    if(pthread_mutex_lock(&broker->mutex)){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");return;}
    if(atomic_fetch_sub(&broker->active_releases,1)!=1){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");}
    if(pthread_mutex_unlock(&broker->mutex)){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");}
}
static void dependency_complete(napi_env env,napi_status status,void *data) {
    struct dependency_broker *broker=data;
    if(status!=napi_ok)dependency_fail(broker,"worker_unavailable");
    broker->working=false;
    if(napi_delete_async_work(env,broker->work)!=napi_ok){
        if(broker->unretired_work_count<4)broker->unretired_work[broker->unretired_work_count++]=broker->work;
        dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");
    }
    broker->work=NULL;
    if(broker->stage==DEPENDENCY_CONNECT){broker->connected=!atomic_load(&broker->error) && !atomic_load(&broker->owner.closing);if(!broker->connected){broker->attempt_completed=true;broker->retry_permitted=atomic_load(&broker->error) && !strcmp(atomic_load(&broker->error),"transport_interrupted");}}
    if(broker->stage==DEPENDENCY_GET){broker->connected=false;broker->attempt_completed=true;
        const char *code=atomic_load(&broker->error);broker->retry_permitted=code?!strcmp(code,"transport_interrupted"):(broker->http.status!=200 || !broker->integrity_matched);}
    if(broker->phase_deferred && !broker->env_closing){napi_deferred deferred=broker->phase_deferred;broker->phase_deferred=NULL;
        if(atomic_load(&broker->error) || atomic_load(&broker->owner.closing))napi_reject_deferred(env,deferred,dependency_error(broker));
        else if(broker->stage==DEPENDENCY_GET){
            napi_value value;napi_create_object(env,&value);set_string(env,value,"kind",broker->http.status==200?(broker->integrity_matched?"complete":"integrity_mismatch"):"http_error");
            set_number(env,value,"status",broker->http.status);set_number(env,value,"receivedBytes",(double)broker->http.received_bytes);set_boolean(env,value,"eof",broker->http.eof);
            set_number(env,value,"packageIndex",broker->next_index);set_number(env,value,"attempt",broker->current_attempt);
            if(broker->http.status==200 && broker->integrity_matched){napi_value package=dependency_package_value(broker,broker->pending_package);
                if(!package){if(broker->pending_package->published)broker->pending_package=NULL;dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");napi_reject_deferred(env,deferred,dependency_error(broker));}
                else{napi_set_named_property(env,value,"package",package);broker->pending_package=NULL;napi_object_freeze(env,value);napi_resolve_deferred(env,deferred,value);}}
            else{napi_object_freeze(env,value);napi_resolve_deferred(env,deferred,value);}
        }else{napi_value value;napi_get_undefined(env,&value);napi_resolve_deferred(env,deferred,value);}
    }
    if(broker->pending_package && !broker->pending_package->published){dependency_package_retire(broker->pending_package);
        struct dependency_package *pending=broker->pending_package;broker->pending_package=NULL;
        if(!pending->data.unsafe){free(pending);}}
    if(atomic_load(&broker->owner.closing))dependency_maybe_finish(broker);
}
static bool dependency_queue(struct dependency_broker *broker,enum dependency_stage stage) {
    if(broker->working)return false;
    napi_value name;if(napi_create_string_utf8(broker->env,"cliq dependency native owner",NAPI_AUTO_LENGTH,&name)!=napi_ok)return false;
    if(napi_create_async_work(broker->env,NULL,name,dependency_worker,dependency_complete,broker,&broker->work)!=napi_ok)return false;
    broker->stage=stage;broker->working=true;
    if(napi_queue_async_work(broker->env,broker->work)!=napi_ok){broker->working=false;
        if(napi_delete_async_work(broker->env,broker->work)!=napi_ok){
            if(broker->unretired_work_count<4)broker->unretired_work[broker->unretired_work_count++]=broker->work;
            dependency_unsafe(broker);
        }broker->work=NULL;return false;}
    return true;
}
static void dependency_timer_closed(uv_handle_t *handle) {
    struct dependency_broker *broker=handle->data;
    napi_env env=broker->env;
    napi_handle_scope scope=NULL;
    /* libuv callbacks have no implicit Node-API handle scope. Save env before
     * finishing: the last real close may release the native allocation. */
    if(napi_open_handle_scope(env,&scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency close scope unavailable",NAPI_AUTO_LENGTH);
    broker->timer_closed=true;
    dependency_maybe_finish(broker);
    if(scope && napi_close_handle_scope(env,scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency close scope did not retire",NAPI_AUTO_LENGTH);
}
static napi_value dependency_closed_value(struct dependency_broker *broker) {
    napi_value value;napi_create_object(broker->env,&value);set_string(broker->env,value,"kind","dependency_transport_closed");
    set_string(broker->env,value,"brokerFenceTokenDigest",broker->owner.binding.token_digest);set_boolean(broker->env,value,"tokenRevoked",true);
    set_boolean(broker->env,value,"dispatchFenceRetained",atomic_load(&broker->owner.fence_retained));
    set_boolean(broker->env,value,"settlementFenceBorrowed",broker->settlement_borrowed);
    set_boolean(broker->env,value,"networkStarted",broker->network_started);set_boolean(broker->env,value,"requestStarted",broker->request_started);
    set_number(broker->env,value,"connectionCount",broker->connection_count);set_number(broker->env,value,"requestCount",broker->request_count);
    set_number(broker->env,value,"transferredBytes",(double)broker->total_transferred);
    set_boolean(broker->env,value,"processClaimed",atomic_load(&broker->owner.worker_claimed));
    set_boolean(broker->env,value,"processJoined",atomic_load(&broker->owner.worker_joined));
    set_boolean(broker->env,value,"processResultAcknowledged",broker->process_acknowledged);
    set_boolean(broker->env,value,"processResultCustodyRetired",broker->process_custody_retired);
    set_string(broker->env,value,"processResultCustodyOrigin",broker->process.result_custody_origin==1?"acknowledged":broker->process.result_custody_origin==2?"controller_joined":"none");napi_object_freeze(broker->env,value);return value;
}
static void dependency_release_cleanup(struct dependency_broker *broker) {
    if(broker->retired && !atomic_load(&broker->owner.fence_retained) && !broker->settlement_locked && !broker->settlement_borrowed && broker->cleanup_hook){
        if(napi_remove_async_cleanup_hook(broker->cleanup_hook)!=napi_ok){dependency_unsafe(broker);return;}broker->cleanup_hook=NULL;
    }
}
static void dependency_maybe_finish(struct dependency_broker *broker) {
    if(!atomic_load(&broker->owner.closing) || broker->working)return;
    if(broker->retired){dependency_release_cleanup(broker);dependency_try_free(broker);return;}
    if(!broker->network_retirement_failed && (broker->connection || broker->tls || broker->tls_context || broker->output_fd>=0)){
        if(!dependency_queue(broker,DEPENDENCY_RETIRE)){broker->network_retirement_failed=true;dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");}return;}
    if(broker->pending_package && !broker->pending_package->published){
        dependency_package_retire(broker->pending_package);
        if(!broker->pending_package->data.unsafe){free(broker->pending_package);broker->pending_package=NULL;}
    }
    for(struct dependency_package *package=broker->packages;package;package=package->next)dependency_package_retire(package);
    if(!dependency_process_poll(broker))return;
    if(atomic_load(&broker->owner.worker_claimed) && !broker->process_peer_released){
        /* A known result remains in native custody across SQL/CAS failure.
         * Whole-controller teardown may actually close its original FDs; that
         * local data drop is recorded separately from a post-commit ACK. */
        /* poll_output_ack may report the original controller's actual
         * cleanup/reap local drop. Close never starts ACK45 for an uncommitted
         * result; only beginAcknowledgeProcessResult can send that command. */
        int acknowledged=broker->peer.poll_output_ack(broker->peer.context);
        if(acknowledged<0){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");return;}
        if(!acknowledged)return;
        if(!dependency_process_poll(broker) || !broker->process_custody_retired)return;
        broker->peer.release(broker->peer.context);broker->process_peer_released=true;memset(&broker->peer,0,sizeof(broker->peer));dependency_release_borrow(broker);
    }
    (void)dependency_close_fd(broker,&broker->inputs_fd);(void)dependency_close_fd(broker,&broker->inputs_read_fd);
    if(broker->cancel){g_object_unref(broker->cancel);broker->cancel=NULL;}
    if(broker->timer_ready && !broker->timer_closing){uv_timer_stop(&broker->timer);broker->timer_closing=true;uv_close((uv_handle_t*)&broker->timer,dependency_timer_closed);return;}
    if(broker->timer_ready && !broker->timer_closed)return;
    broker->retired=true;
    dependency_release_cleanup(broker);
    if(broker->close_deferred && !broker->env_closing){if(atomic_load(&broker->owner.unsafe))napi_reject_deferred(broker->env,broker->close_deferred,dependency_error(broker));
        else napi_resolve_deferred(broker->env,broker->close_deferred,dependency_closed_value(broker));
        broker->close_deferred=NULL;
        }
    if(broker->handle && !broker->env_closing){broker->native_borrows++;uint32_t count;if(napi_reference_unref(broker->env,broker->handle,&count)!=napi_ok)dependency_unsafe(broker);dependency_release_borrow(broker);}
    else dependency_try_free(broker);
}
static void dependency_timer(uv_timer_t *timer) {
    struct dependency_broker *broker=timer->data;struct timespec now;
    napi_env env=broker->env;
    napi_handle_scope scope=NULL;
    if(napi_open_handle_scope(env,&scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency timer scope unavailable",NAPI_AUTO_LENGTH);
    if(clock_gettime(CLOCK_MONOTONIC,&now)){dependency_unsafe(broker);dependency_begin_close(broker);goto finished;}
    if(atomic_load(&broker->owner.closing)){
        if((now.tv_sec>broker->close_deadline.tv_sec || (now.tv_sec==broker->close_deadline.tv_sec && now.tv_nsec>=broker->close_deadline.tv_nsec)) && !broker->retired){
            dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");
            if(broker->close_deferred && !broker->env_closing){napi_reject_deferred(broker->env,broker->close_deferred,dependency_error(broker));broker->close_deferred=NULL;}}
        dependency_maybe_finish(broker);goto finished;
    }
    if(now.tv_sec>broker->outer_deadline.tv_sec || (now.tv_sec==broker->outer_deadline.tv_sec && now.tv_nsec>=broker->outer_deadline.tv_nsec)){dependency_begin_close(broker);goto finished;}
    if(broker->working && (now.tv_sec>broker->request_deadline.tv_sec || (now.tv_sec==broker->request_deadline.tv_sec && now.tv_nsec>=broker->request_deadline.tv_nsec))){
        atomic_store(&broker->request_expired,true);if(broker->cancel)g_cancellable_cancel(broker->cancel);}
finished:
    if(scope && napi_close_handle_scope(env,scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency timer scope did not retire",NAPI_AUTO_LENGTH);
}
static void dependency_begin_close(struct dependency_broker *broker) {
    if(atomic_exchange(&broker->owner.closing,true)){dependency_maybe_finish(broker);return;}
    if(!broker->settlement_locked){
        if(pthread_mutex_lock(&broker->mutex))dependency_unsafe(broker);
        else{broker->token_revoked=true;if(pthread_mutex_unlock(&broker->mutex))dependency_unsafe(broker);}
    }
    atomic_store(&broker->request_expired,true);if(broker->cancel)g_cancellable_cancel(broker->cancel);
    if(clock_gettime(CLOCK_MONOTONIC,&broker->close_deadline))dependency_unsafe(broker);else broker->close_deadline.tv_sec+=2;
    if(atomic_load(&broker->owner.worker_claimed) && !broker->process_peer_released && broker->peer.cancel(broker->peer.context)<0){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");}
    if(broker->ready_deferred && !broker->env_closing){napi_reject_deferred(broker->env,broker->ready_deferred,dependency_error(broker));broker->ready_deferred=NULL;}
    if(broker->timer_ready && !broker->timer_closing)uv_timer_start(&broker->timer,dependency_timer,0,5);
    dependency_maybe_finish(broker);
}
static napi_value dependency_close_call(napi_env env,napi_callback_info info) {
    napi_value args[1];size_t argc=1;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc)return dependency_throw(broker,"close_refused");
    napi_value promise;
    if(broker->close_promise){napi_get_reference_value(env,broker->close_promise,&promise);return promise;}
    if(napi_create_promise(env,&broker->close_deferred,&promise)!=napi_ok || napi_create_reference(env,promise,1,&broker->close_promise)!=napi_ok)return dependency_throw(broker,"resource_retirement");
    dependency_begin_close(broker);return promise;
}
static napi_value dependency_page_call(napi_env env,napi_callback_info info) {
    napi_value args[2];size_t argc=2;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    const unsigned char *bytes;size_t size;
    if(argc!=1 || broker->bound || !dependency_outer_current(broker) || !dependency_buffer(env,args[0],65536,&bytes,&size) ||
        sizeof(*broker)+sizeof(*broker->config)+broker->descriptors.owned_bytes+broker->inputs_reserved+sizeof(struct cliq_dependency_descriptor_page)+size>CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES ||
        !cliq_dependency_descriptors_page(&broker->descriptors,bytes,size))return dependency_throw(broker,"descriptor_page_refused");
    if(!dependency_input_reserve_page(broker,broker->descriptors.last)){broker->descriptors.failed=true;return dependency_throw(broker,"descriptor_storage_refused");}
    return NULL;
}
static napi_value dependency_seal_call(napi_env env,napi_callback_info info) {
    napi_value args[1];size_t argc=1;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc || !dependency_outer_current(broker) || !cliq_dependency_descriptors_seal(&broker->descriptors) ||
        broker->descriptors.sequence_bytes!=broker->config->package_descriptor_bytes)return dependency_throw(broker,"descriptor_sequence_refused");
    for(struct cliq_dependency_descriptor_page *page=broker->descriptors.first;page;page=page->next)for(uint32_t index=0;index<page->count;index++){
        unsigned matches=0;for(uint32_t target=0;target<broker->config->target_count;target++)matches+=cliq_dependency_string_equal(page->values[index].endpoint,broker->config->targets[target].ref);
        if(matches!=1){broker->descriptors.failed=true;return dependency_throw(broker,"descriptor_endpoint_refused");}}
    broker->inputs_fd=(int)syscall(SYS_memfd_create,"cliq-dependency-package-inputs",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(broker->inputs_fd<0)return dependency_throw(broker,"package_metadata_storage_unavailable");
    sha256_init(&broker->inputs_hash);
    if(broker->ready_deferred){napi_value value;napi_get_undefined(env,&value);napi_resolve_deferred(env,broker->ready_deferred,value);broker->ready_deferred=NULL;}return NULL;
}
static napi_value dependency_retain_call(napi_env env,napi_callback_info info) {
    napi_value args[1];size_t argc=1;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc || !broker->descriptors.sealed || !dependency_outer_current(broker) || atomic_exchange(&broker->owner.fence_retained,true))return dependency_throw(broker,"dispatch_fence_refused");
    return NULL;
}
static napi_value dependency_bind_call(napi_env env,napi_callback_info info) {
    napi_value args[2];size_t argc=2;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    struct cliq_dependency_binding binding;
    if(argc!=1 || broker->bound || !atomic_load(&broker->owner.fence_retained) || !broker->descriptors.sealed || !dependency_outer_current(broker) ||
        !dependency_binding_argument(broker,args[0],&binding))return dependency_throw(broker,"invocation_binding_refused");
    broker->owner.binding=binding;broker->bound=true;return NULL;
}
static napi_value dependency_network_call(napi_env env,napi_callback_info info,enum dependency_stage stage) {
    napi_value args[4];size_t argc=4;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    uint32_t index,attempt;
    if(argc!=3 || !dependency_binding_current(broker,args[0]) || !dependency_u32(env,args[1],&index) || !dependency_u32(env,args[2],&attempt) ||
        index!=broker->next_index || index>=broker->owner.package_count || (attempt<1 || attempt>3) || broker->working || !dependency_outer_current(broker) ||
        !atomic_load(&broker->owner.fence_retained) || atomic_load(&broker->owner.worker_claimed))return dependency_throw(broker,"package_release_refused");
    if(stage==DEPENDENCY_CONNECT){
        if(broker->connected || broker->pending_package || (broker->attempt_completed?(!broker->retry_permitted || attempt!=broker->current_attempt+1):(attempt!=1)))return dependency_throw(broker,"package_attempt_refused");
        broker->descriptor=cliq_dependency_descriptors_at(&broker->descriptors,index);broker->target=NULL;
        for(uint32_t current=0;broker->descriptor && current<broker->config->target_count;current++)if(cliq_dependency_string_equal(broker->descriptor->endpoint,broker->config->targets[current].ref))broker->target=&broker->config->targets[current];
        if(!broker->target || broker->total_transferred>=broker->config->max_transfer_bytes)return dependency_throw(broker,"package_budget_refused");
        broker->current_attempt=attempt;broker->attempt_completed=false;broker->retry_permitted=false;memset(&broker->http,0,sizeof(broker->http));atomic_store(&broker->error,NULL);atomic_store(&broker->request_expired,false);
        if(broker->cancel){g_object_unref(broker->cancel);broker->cancel=NULL;}broker->cancel=g_cancellable_new();
        if(clock_gettime(CLOCK_MONOTONIC,&broker->request_deadline))return dependency_throw(broker,"clock_unavailable");
        broker->request_deadline.tv_sec+=30;
        if(broker->request_deadline.tv_sec>broker->outer_deadline.tv_sec || (broker->request_deadline.tv_sec==broker->outer_deadline.tv_sec && broker->request_deadline.tv_nsec>broker->outer_deadline.tv_nsec))broker->request_deadline=broker->outer_deadline;
    }else{
        if(!broker->connected || attempt!=broker->current_attempt || broker->pending_package)return dependency_throw(broker,"package_attempt_refused");
        broker->pending_package=calloc(1,sizeof(*broker->pending_package));if(!broker->pending_package)return dependency_throw(broker,"package_storage_unavailable");
        broker->pending_package->data.fd=-1;broker->pending_package->broker=broker;broker->pending_package->index=index;broker->integrity_matched=false;
    }
    napi_value promise;
    if(napi_create_promise(env,&broker->phase_deferred,&promise)!=napi_ok)return dependency_throw(broker,"worker_unavailable");
    if(!dependency_queue(broker,stage)){
        dependency_fail(broker,"worker_unavailable");napi_reject_deferred(env,broker->phase_deferred,dependency_error(broker));broker->phase_deferred=NULL;
        dependency_begin_close(broker);
    }
    return promise;
}
static napi_value dependency_seal_inputs_call(napi_env env,napi_callback_info info) {
    size_t argc=2;napi_value args[2],promise;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc!=1 || !dependency_binding_current(broker,args[0]) || !dependency_outer_current(broker) || broker->working || broker->connected || broker->pending_package ||
        broker->next_index!=broker->owner.package_count || broker->inputs_sealed || broker->inputs_failed)return dependency_throw(broker,"package_metadata_refused");
    if(napi_create_promise(env,&broker->phase_deferred,&promise)!=napi_ok)return dependency_throw(broker,"worker_unavailable");
    if(!dependency_queue(broker,DEPENDENCY_INPUTS_SEAL)){dependency_fail(broker,"worker_unavailable");napi_reject_deferred(env,broker->phase_deferred,dependency_error(broker));broker->phase_deferred=NULL;dependency_begin_close(broker);}
    return promise;
}
static napi_value dependency_connect_call(napi_env env,napi_callback_info info){return dependency_network_call(env,info,DEPENDENCY_CONNECT);}
static napi_value dependency_get_call(napi_env env,napi_callback_info info){return dependency_network_call(env,info,DEPENDENCY_GET);}
static bool dependency_data_joined(struct dependency_broker *broker) {
    if(broker->pending_package)return false;
    for(struct dependency_package *package=broker->packages;package;package=package->next)if(!package->closed || package->data.readers || package->data.unsafe)return false;
    return true;
}
static bool dependency_settlement_drop(struct dependency_settlement *fence) {
    if(!fence->active)return true;
    struct dependency_broker *broker=fence->broker;
    if(!broker || (!(broker->env_closing && !broker->settlement_locked) &&
        (!broker->settlement_locked || !broker->settlement_borrowed || pthread_mutex_unlock(&broker->mutex)))){
        if(broker){dependency_unsafe(broker);dependency_fail(broker,"resource_retirement");}return false;}
    broker->settlement_locked=false;broker->settlement_borrowed=false;fence->active=false;
    if(fence->parent && !broker->env_closing)napi_delete_reference(fence->env,fence->parent);
    fence->parent=NULL;
    dependency_maybe_finish(broker);return true;
}
static void dependency_settlement_finalize(napi_env env,void *data,void *hint) {
    (void)env;(void)hint;struct dependency_settlement *fence=data;if(!dependency_settlement_drop(fence))return;
    struct dependency_broker *broker=fence->broker;wipe(fence,sizeof(*fence));free(fence);dependency_release_borrow(broker);
}
static struct dependency_settlement *dependency_settlement_receiver(napi_env env,napi_callback_info info) {
    size_t argc=1;napi_value args[1],receiver;bool tagged=false;struct dependency_settlement *fence=NULL;
    if(napi_get_cb_info(env,info,&argc,args,&receiver,NULL)!=napi_ok || argc || napi_check_object_type_tag(env,receiver,&dependency_settlement_tag,&tagged)!=napi_ok || !tagged ||
        napi_unwrap(env,receiver,(void**)&fence)!=napi_ok || !fence || fence->env!=env || fence->creator!=getpid() || syscall(SYS_gettid)!=getpid()){
        napi_throw_type_error(env,NULL,"Invalid dependency settlement fence");return NULL;}return fence;
}
static napi_value dependency_settlement_assert(napi_env env,napi_callback_info info) {
    struct dependency_settlement *fence=dependency_settlement_receiver(env,info);if(!fence)return NULL;struct dependency_broker *broker=fence->broker;
    if(!fence->active || !broker || broker->env_closing || !broker->settlement_locked || !broker->token_revoked || !broker->bound || broker->working || broker->connected ||
        atomic_load(&broker->owner.unsafe) || atomic_load(&broker->active_releases)!=0 || !dependency_data_joined(broker) ||
        (atomic_load(&broker->owner.worker_claimed) && !atomic_load(&broker->owner.worker_joined)))return dependency_throw(broker,"settlement_fence_refused");
    return NULL;
}
static napi_value dependency_settlement_close(napi_env env,napi_callback_info info) {
    struct dependency_settlement *fence=dependency_settlement_receiver(env,info);if(!fence)return NULL;
    if(!dependency_settlement_drop(fence))return dependency_throw(fence->broker,"resource_retirement");
    return NULL;
}
static napi_value dependency_acquire_settlement(napi_env env,napi_callback_info info) {
    size_t argc=2;napi_value args[2],value,parent;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc!=1 || !dependency_binding_current(broker,args[0]) || broker->working || broker->connected || broker->connection || broker->tls || broker->settlement_borrowed ||
        !atomic_load(&broker->owner.fence_retained) || atomic_load(&broker->owner.unsafe) || atomic_load(&broker->active_releases)!=0 || !dependency_data_joined(broker) || !dependency_process_poll(broker))return dependency_throw(broker,"settlement_fence_refused");
    struct dependency_settlement *fence=calloc(1,sizeof(*fence));if(!fence)return dependency_throw(broker,"worker_unavailable");
    if(pthread_mutex_lock(&broker->mutex)){free(fence);return dependency_throw(broker,"resource_retirement");}
    if(atomic_load(&broker->active_releases)!=0){pthread_mutex_unlock(&broker->mutex);free(fence);return dependency_throw(broker,"settlement_fence_refused");}
    broker->settlement_locked=true;broker->settlement_borrowed=true;broker->token_revoked=true;
    fence->env=env;fence->broker=broker;fence->creator=getpid();fence->active=true;napi_create_object(env,&value);
    const napi_property_descriptor methods[]={{"assertCurrent",NULL,dependency_settlement_assert,NULL,NULL,NULL,napi_default,NULL},{"close",NULL,dependency_settlement_close,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_get_reference_value(env,broker->handle,&parent)!=napi_ok || napi_create_reference(env,parent,1,&fence->parent)!=napi_ok ||
        napi_type_tag_object(env,value,&dependency_settlement_tag)!=napi_ok || napi_wrap(env,value,fence,dependency_settlement_finalize,NULL,NULL)!=napi_ok){
        (void)dependency_settlement_drop(fence);free(fence);dependency_unsafe(broker);return dependency_throw(broker,"resource_retirement");}
    broker->native_borrows++;
    if(napi_define_properties(env,value,2,methods)!=napi_ok){(void)dependency_settlement_drop(fence);dependency_unsafe(broker);return dependency_throw(broker,"resource_retirement");}
    set_string(env,value,"kind","dependency_settlement_fence");set_string(env,value,"brokerFenceTokenDigest",broker->owner.binding.token_digest);
    set_boolean(env,value,"networkStarted",broker->network_started);set_boolean(env,value,"requestStarted",broker->request_started);
    set_boolean(env,value,"processClaimed",atomic_load(&broker->owner.worker_claimed));set_boolean(env,value,"processJoined",atomic_load(&broker->owner.worker_joined));
    set_boolean(env,value,"processResultAvailable",broker->process.result_available);napi_object_freeze(env,value);return value;
}
static napi_value dependency_release_process(napi_env env,napi_callback_info info) {
    size_t argc=2;napi_value args[2];struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc!=1 || !dependency_binding_current(broker,args[0]) || dependency_assert_current(&broker->owner)!=1 || broker->working || broker->connected || broker->process_released ||
        !atomic_load(&broker->owner.worker_claimed) || !broker->inputs_borrowed || !dependency_data_joined(broker))return dependency_throw(broker,"process_release_refused");
    if(pthread_mutex_lock(&broker->mutex))return dependency_throw(broker,"resource_retirement");
    /* Irreversible before the original native channel send. A failed send is
     * never interpreted as permission to send or construct another scope. */
    broker->process_released=true;atomic_fetch_add(&broker->active_releases,1);int status=broker->peer.release_execution(broker->peer.context,&broker->owner.binding);
    if(atomic_fetch_sub(&broker->active_releases,1)!=1)dependency_unsafe(broker);
    if(pthread_mutex_unlock(&broker->mutex)){dependency_unsafe(broker);return dependency_throw(broker,"resource_retirement");}
    if(status<0)return dependency_throw(broker,"process_release_refused");
    return NULL;
}
static napi_value dependency_begin_ack(napi_env env,napi_callback_info info) {
    size_t argc=2;napi_value args[2];struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc!=1 || !dependency_binding_current(broker,args[0]) || !broker->token_revoked || broker->settlement_locked || broker->working || !dependency_data_joined(broker) ||
        !atomic_load(&broker->owner.worker_claimed) || !dependency_process_poll(broker) || !broker->process.result_available || broker->process_peer_released)return dependency_throw(broker,"process_ack_refused");
    if(broker->process_ack_started)return NULL;
    broker->process_ack_started=true;
    if(broker->peer.begin_output_ack(broker->peer.context)<0)return dependency_throw(broker,"process_ack_refused");
    return NULL;
}
static napi_value dependency_poll_ack(napi_env env,napi_callback_info info) {
    size_t argc=1;napi_value args[1],value;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc || !broker->process_ack_started || atomic_load(&broker->owner.unsafe))return dependency_throw(broker,"process_ack_refused");
    if(!broker->process_custody_retired){int status=broker->peer.poll_output_ack(broker->peer.context);
        if(status<0)return dependency_throw(broker,"process_ack_refused");
        if(status==1){if(!dependency_process_poll(broker) || !broker->process_custody_retired)return dependency_throw(broker,"process_ack_refused");
        broker->peer.release(broker->peer.context);
            broker->process_peer_released=true;memset(&broker->peer,0,sizeof(broker->peer));dependency_release_borrow(broker);}}
    napi_get_boolean(env,broker->process_custody_retired,&value);return value;
}
static napi_value dependency_release_fence(napi_env env,napi_callback_info info) {
    size_t argc=1;napi_value args[1];struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    if(argc || !broker->token_revoked || broker->settlement_borrowed || broker->working || broker->connected || !dependency_data_joined(broker) ||
        (atomic_load(&broker->owner.worker_claimed) && (!atomic_load(&broker->owner.worker_joined) || !broker->process_peer_released)))return dependency_throw(broker,"dispatch_fence_refused");
    atomic_store(&broker->owner.fence_retained,false);dependency_maybe_finish(broker);return NULL;
}
static napi_value dependency_observe_failure(napi_env env,napi_callback_info info) {
    size_t argc=2;napi_value args[2],value;struct dependency_broker *broker=dependency_receiver(env,info,&argc,args);if(!broker)return NULL;
    bool tagged=false;struct dependency_failure *failure=NULL;
    if(argc!=1 || napi_check_object_type_tag(env,args[0],&dependency_failure_tag,&tagged)!=napi_ok || !tagged ||
        napi_unwrap(env,args[0],(void**)&failure)!=napi_ok || !failure || failure->broker!=broker || failure->env!=env || failure->creator!=getpid()){
        napi_throw_type_error(env,NULL,"Invalid dependency failure observation");return NULL;}
    napi_create_object(env,&value);set_string(env,value,"brokerCode",failure->code);set_number(env,value,"packageIndex",failure->index);set_number(env,value,"attempt",failure->attempt);
    set_number(env,value,"receivedBytes",(double)failure->received);set_boolean(env,value,"eof",failure->eof);set_boolean(env,value,"networkStarted",failure->network_started);
    set_boolean(env,value,"requestStarted",failure->request_started);set_boolean(env,value,"ioJoined",failure->io_joined);
    /* Only an actual original network operation, after its real I/O join,
     * may use the RFC's at-most-three integrity GET attempts. */
    set_boolean(env,value,"retryableTransport",failure->io_joined && failure->attempt>=1 && failure->attempt<3 && !strcmp(failure->code,"transport_interrupted"));
    napi_object_freeze(env,value);return value;
}
static void dependency_cleanup(napi_async_cleanup_hook_handle handle,void *data) {
    (void)handle;struct dependency_broker *broker=data;
    napi_env env=broker->env;
    napi_handle_scope scope=NULL;
    /* Closing suppresses public replies, not the temporary JS values needed
     * to queue real native retirement. The async hook owns an env reference;
     * Node releases that reference asynchronously after hook removal, so this
     * callback closes its handle scope before that final env release. */
    if(napi_open_handle_scope(env,&scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency cleanup scope unavailable",NAPI_AUTO_LENGTH);
    broker->env_closing=true;
    if(broker->settlement_locked){if(pthread_mutex_unlock(&broker->mutex))dependency_unsafe(broker);else broker->settlement_locked=false;}
    broker->settlement_borrowed=false;atomic_store(&broker->owner.fence_retained,false);dependency_begin_close(broker);
    if(napi_close_handle_scope(env,scope)!=napi_ok)
        napi_fatal_error("cliq-dependency-broker",NAPI_AUTO_LENGTH,"dependency cleanup scope did not retire",NAPI_AUTO_LENGTH);
}
static napi_value dependency_prepare(napi_env env,napi_callback_info info) {
    struct timespec started;size_t argc=3;napi_value args[3];const unsigned char *configuration,*trust;size_t configuration_size,trust_size;
    if(clock_gettime(CLOCK_MONOTONIC,&started) || atomic_load(&retirement_failed) || syscall(SYS_gettid)!=getpid() || napi_get_cb_info(env,info,&argc,args,NULL,NULL)!=napi_ok || argc!=2 ||
        !dependency_buffer(env,args[0],1048576,&configuration,&configuration_size) || !dependency_buffer(env,args[1],16*1048576,&trust,&trust_size)){
        napi_throw_type_error(env,NULL,"Invalid dependency preparation");return NULL;}
    struct dependency_broker *broker=calloc(1,sizeof(*broker));
    if(!broker){napi_throw_error(env,NULL,"Dependency owner unavailable");return NULL;}
    broker->env=env;broker->outer_deadline=started;broker->owner.abi_version=CLIQ_DEPENDENCY_OWNER_ABI;broker->owner.creator_pid=getpid();broker->owner.environment=env;
    broker->owner.assert_current=dependency_assert_current;broker->owner.acquire_worker=dependency_acquire_worker;broker->owner.borrow_package_inputs=dependency_borrow_inputs;
    broker->output_fd=-1;broker->inputs_fd=-1;broker->inputs_read_fd=-1;
    atomic_init(&broker->owner.closing,false);atomic_init(&broker->owner.unsafe,false);atomic_init(&broker->owner.fence_retained,false);
    atomic_init(&broker->active_releases,0);atomic_init(&broker->owner.worker_claimed,false);atomic_init(&broker->owner.worker_joined,false);atomic_init(&broker->request_expired,false);atomic_init(&broker->error,NULL);
    broker->config=calloc(1,sizeof(*broker->config));broker->trust=malloc(trust_size);unsigned char *original_configuration=malloc(configuration_size);
    if(original_configuration)memcpy(original_configuration,configuration,configuration_size);
    if(broker->trust)memcpy(broker->trust,trust,trust_size);
    unsigned char token[32],digest[32];char trust_digest[65];uid_t uid;gid_t gid;char home[PATH_MAX];
    bool valid=broker->config && broker->trust && original_configuration && current_user(&uid,&gid,home) && cliq_dependency_configuration_read(original_configuration,configuration_size,broker->config) &&
        SHA256(broker->trust,trust_size,digest) && RAND_bytes(token,sizeof(token))==1;
    free(original_configuration);
    if(valid){static const char hex[]="0123456789abcdef";for(size_t index=0;index<32;index++){trust_digest[index*2]=hex[digest[index]>>4];trust_digest[index*2+1]=hex[digest[index]&15];}trust_digest[64]=0;
        valid=!strcmp(trust_digest,broker->config->trust_digest) && cliq_dependency_descriptors_initialize(&broker->descriptors,broker->config->package_count,broker->config->descriptor_digest) &&
            pthread_mutex_init(&broker->mutex,NULL)==0;broker->mutex_ready=valid;
    }
    if(!valid){free(broker->config);free(broker->trust);free(broker);wipe(token,sizeof(token));napi_throw_type_error(env,NULL,"Invalid dependency preparation");return NULL;}
    broker->trust_size=trust_size;SHA256(token,sizeof(token),digest);wipe(token,sizeof(token));
    static const char hex[]="0123456789abcdef";for(size_t index=0;index<32;index++){broker->owner.binding.token_digest[index*2]=hex[digest[index]>>4];broker->owner.binding.token_digest[index*2+1]=hex[digest[index]&15];}
    broker->owner.binding.token_digest[64]=0;wipe(digest,sizeof(digest));memcpy(broker->owner.plan_digest,broker->config->plan_digest,65);
    memcpy(broker->owner.sandbox_launch_spec_ref,broker->config->launch_ref,65);memcpy(broker->owner.descriptor_sequence_digest,broker->config->descriptor_digest,65);broker->owner.package_count=broker->config->package_count;
    broker->outer_deadline.tv_sec+=(time_t)(broker->config->run_remaining_ms/1000);broker->outer_deadline.tv_nsec+=(long)(broker->config->run_remaining_ms%1000)*1000000;
    if(broker->outer_deadline.tv_nsec>=1000000000){broker->outer_deadline.tv_sec++;broker->outer_deadline.tv_nsec-=1000000000;}
    napi_value handle,ready;napi_create_object(env,&handle);
    const napi_property_descriptor methods[]={
        {"registerPackagePage",NULL,dependency_page_call,NULL,NULL,NULL,napi_default,NULL},{"sealPackagePlan",NULL,dependency_seal_call,NULL,NULL,NULL,napi_default,NULL},
        {"retainDispatchFence",NULL,dependency_retain_call,NULL,NULL,NULL,napi_default,NULL},{"bindInvocation",NULL,dependency_bind_call,NULL,NULL,NULL,napi_default,NULL},
        {"connect",NULL,dependency_connect_call,NULL,NULL,NULL,napi_default,NULL},{"releaseGet",NULL,dependency_get_call,NULL,NULL,NULL,napi_default,NULL},
        {"observeFailure",NULL,dependency_observe_failure,NULL,NULL,NULL,napi_default,NULL},
        {"sealPackageInputs",NULL,dependency_seal_inputs_call,NULL,NULL,NULL,napi_default,NULL},
        {"releaseProcess",NULL,dependency_release_process,NULL,NULL,NULL,napi_default,NULL},{"acquireSettlementFence",NULL,dependency_acquire_settlement,NULL,NULL,NULL,napi_default,NULL},
        {"beginAcknowledgeProcessResult",NULL,dependency_begin_ack,NULL,NULL,NULL,napi_default,NULL},{"pollProcessResultAcknowledged",NULL,dependency_poll_ack,NULL,NULL,NULL,napi_default,NULL},
        {"releaseDispatchFence",NULL,dependency_release_fence,NULL,NULL,NULL,napi_default,NULL},{"close",NULL,dependency_close_call,NULL,NULL,NULL,napi_default,NULL}};
    uv_loop_t *loop;
    if(napi_create_promise(env,&broker->ready_deferred,&ready)!=napi_ok || napi_type_tag_object(env,handle,&CLIQ_DEPENDENCY_OWNER_TAG)!=napi_ok ||
        napi_wrap(env,handle,&broker->owner,dependency_finalize,NULL,NULL)!=napi_ok || napi_define_properties(env,handle,sizeof(methods)/sizeof(*methods),methods)!=napi_ok ||
        napi_create_reference(env,handle,1,&broker->handle)!=napi_ok || napi_add_async_cleanup_hook(env,dependency_cleanup,broker,&broker->cleanup_hook)!=napi_ok ||
        napi_get_uv_event_loop(env,&loop)!=napi_ok || uv_timer_init(loop,&broker->timer)){
        dependency_unsafe(broker);atomic_store(&retirement_failed,true);broker->unretired_next=unretired_dependencies;unretired_dependencies=broker;
        return dependency_throw(broker,"resource_retirement");}
    broker->timer_ready=true;broker->timer.data=broker;uv_update_time(loop);
    if(uv_timer_start(&broker->timer,dependency_timer,20,20)){dependency_unsafe(broker);dependency_begin_close(broker);return dependency_throw(broker,"resource_retirement");}
    napi_set_named_property(env,handle,"ready",ready);set_string(env,handle,"brokerFenceTokenDigest",broker->owner.binding.token_digest);napi_object_freeze(env,handle);return handle;
}
static napi_value initialize_dependency_broker(napi_env env,napi_value exports) {
    if(!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)){napi_throw_error(env,NULL,"Dependency TLS unavailable");return NULL;}
    const napi_property_descriptor methods[]={{"prepareDependencyTransport",NULL,dependency_prepare,NULL,NULL,NULL,napi_default,NULL}};
    if(napi_define_properties(env,exports,1,methods)!=napi_ok)return NULL;
    set_number(env,exports,"interfaceVersion",1);
    set_number(env,exports,"maximumOwnerDataBytes",CLIQ_DEPENDENCY_DESCRIPTOR_TOTAL_BYTES);
    set_number(env,exports,"descriptorPageStorageBytes",sizeof(struct cliq_dependency_descriptor_page));
    set_number(env,exports,"fixedOwnerStorageBytes",sizeof(struct dependency_broker)+sizeof(struct cliq_dependency_configuration));
    napi_object_freeze(env,exports);return exports;
}
NAPI_MODULE(cliq_linux_dependency_broker,initialize_dependency_broker)
#endif
