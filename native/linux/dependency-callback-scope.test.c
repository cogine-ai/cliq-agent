/* Actual Node/libuv callback component. The callbacks are extracted verbatim
 * from the same production source. Its inert broker shim owns no network,
 * Journal, process, claim, permission or result custody. */
#define _GNU_SOURCE
#include <node_api.h>
#include <uv.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/resource.h>
struct dependency_broker {
    napi_env env;
    uv_timer_t timer;
    struct { atomic_bool closing,fence_retained; } owner;
    struct timespec close_deadline,outer_deadline,request_deadline,started_at;
    bool timer_closed,timer_closing,retired,working,env_closing;
    atomic_bool request_expired;
    void *cancel;
    napi_deferred close_deferred,joined;
    napi_ref callback_resource;
    napi_async_context callback_context;
    napi_async_cleanup_hook_handle cleanup_hook;
    napi_async_work work;
    pthread_mutex_t mutex;
    bool settlement_locked,settlement_borrowed,retire_queued,retire_joined,callbacks_retiring,finalized;
    unsigned native_borrows,callback_depth;
    int marker;
};
struct dependency_callback_scope { napi_env env; napi_handle_scope handles; napi_callback_scope callback; };
static atomic_bool retirement_failed;
static struct dependency_broker *live_broker;
static void dependency_timer_closed(uv_handle_t *handle);
static void dependency_cleanup(napi_async_cleanup_hook_handle handle,void *data);
static bool dependency_callbacks_init(struct dependency_broker *broker);
static void dependency_release_cleanup(struct dependency_broker *broker);
static void dependency_release_borrow(struct dependency_broker *broker);
static void dependency_maybe_finish(struct dependency_broker *broker);
static void dependency_try_free(struct dependency_broker *broker) {
    if (!broker->retired || !broker->finalized || broker->native_borrows || broker->callback_depth || broker->callbacks_retiring ||
        broker->callback_context || broker->callback_resource || broker->cleanup_hook) return;
    if (live_broker!=broker) abort();
    live_broker=NULL;free(broker);
}
static void retirement_execute(napi_env env,void *data) {
    (void)env;
    struct dependency_broker *broker=data;
    const char marker[]="retire_work\n";
    if (write(broker->marker,marker,sizeof(marker)-1)!=(ssize_t)sizeof(marker)-1) abort();
}
static void retirement_complete(napi_env env,napi_status status,void *data);

static void dependency_finish(struct dependency_broker *broker) {
    if (broker->env_closing && !broker->retire_joined) {
        if (!broker->retire_queued) {
            napi_value name;
            if (napi_create_string_utf8(broker->env,"actual inert retirement",NAPI_AUTO_LENGTH,&name)!=napi_ok ||
                napi_create_async_work(broker->env,NULL,name,retirement_execute,retirement_complete,broker,&broker->work)!=napi_ok ||
                napi_queue_async_work(broker->env,broker->work)!=napi_ok) abort();
            broker->retire_queued=true;
        }
        return;
    }
    if (!broker->timer_closed) {
        if (!broker->timer_closing) {
            broker->timer_closing=true;
            uv_timer_stop(&broker->timer);
            uv_close((uv_handle_t*)&broker->timer,dependency_timer_closed);
        }
        return;
    }
    if (broker->env_closing) {
        const char marker[]="timer_closed\n";
        if (write(broker->marker,marker,sizeof(marker)-1)!=(ssize_t)sizeof(marker)-1 || close(broker->marker)) abort();
        broker->retired=true;broker->finalized=true;
        dependency_release_cleanup(broker);
        return;
    }
    napi_value value;
    if (napi_create_object(broker->env,&value)!=napi_ok) abort();
    napi_value yes;
    napi_get_boolean(broker->env,true,&yes);
    napi_set_named_property(broker->env,value,"actualTimerClosed",yes);
    struct timespec ended;
    if (clock_gettime(CLOCK_MONOTONIC,&ended)) abort();
    napi_value elapsed;
    if (napi_create_double(broker->env,(double)(ended.tv_sec-broker->started_at.tv_sec)*1000.0+
        (double)(ended.tv_nsec-broker->started_at.tv_nsec)/1000000.0,&elapsed)!=napi_ok ||
        napi_set_named_property(broker->env,value,"nativeCloseElapsedMs",elapsed)!=napi_ok) abort();
    if (broker->close_deferred) napi_resolve_deferred(broker->env,broker->close_deferred,value);
    napi_resolve_deferred(broker->env,broker->joined,value);
    /* This inert allocation is owned only by its callback, unlike the real
     * JS-wrapped broker. Require the production native borrow to keep it alive
     * through reentrant Promise/GC and actual async-context retirement. */
    broker->retired=true;broker->finalized=true;
    dependency_release_cleanup(broker);
}
static void retirement_complete(napi_env env,napi_status status,void *data) {
    struct dependency_broker *broker=data;
    if (status!=napi_ok || napi_delete_async_work(env,broker->work)!=napi_ok) abort();
    broker->work=NULL;
    broker->retire_joined=true;
    const char marker[]="retire_joined\n";
    if (write(broker->marker,marker,sizeof(marker)-1)!=(ssize_t)sizeof(marker)-1) abort();
    dependency_maybe_finish(broker);
}
static void dependency_unsafe(struct dependency_broker *broker) { (void)broker; }
static void dependency_fail(struct dependency_broker *broker,const char *code) { (void)broker; (void)code; }
static napi_value dependency_error(struct dependency_broker *broker) {
    napi_value text,error;
    napi_create_string_utf8(broker->env,"fixed inert callback failure",NAPI_AUTO_LENGTH,&text);
    napi_create_error(broker->env,NULL,text,&error);
    return error;
}
static void dependency_begin_close(struct dependency_broker *broker) { atomic_store(&broker->owner.closing,true);dependency_maybe_finish(broker); }
static void g_cancellable_cancel(void *cancel) { (void)cancel; }
/* Generated from the live callbacks and their lifetime helpers; no copied
 * callback/context-retirement algorithm. */
#include "dependency-callbacks-under-test.h"
static napi_value exercise(napi_env env,napi_callback_info info) {
    size_t argc=1;
    napi_value args[1],result,completion,joined;
    bool timer=false;
    if (napi_get_cb_info(env,info,&argc,args,NULL,NULL)!=napi_ok || argc!=1 || napi_get_value_bool(env,args[0],&timer)!=napi_ok) return NULL;
    struct dependency_broker *broker=calloc(1,sizeof(*broker));
    if (!broker) return NULL;
    broker->env=env;
    if (clock_gettime(CLOCK_MONOTONIC,&broker->started_at)) abort();
    if (live_broker || !dependency_callbacks_init(broker)) abort();
    live_broker=broker;
    atomic_init(&broker->owner.closing,true);
    atomic_init(&broker->request_expired,false);
    uv_loop_t *loop;
    if (napi_get_uv_event_loop(env,&loop)!=napi_ok || uv_timer_init(loop,&broker->timer)) abort();
    broker->timer.data=broker;
    napi_create_promise(env,&broker->close_deferred,&completion);
    napi_create_promise(env,&broker->joined,&joined);
    napi_create_object(env,&result);
    napi_set_named_property(env,result,"completion",completion);
    napi_set_named_property(env,result,"joined",joined);
    if (timer) { if (uv_timer_start(&broker->timer,dependency_timer,0,0)) abort(); }
    else dependency_maybe_finish(broker);
    return result;
}
static napi_value arm_cleanup(napi_env env,napi_callback_info info) {
    size_t argc=1;
    napi_value args[1],value;
    char filename[4096];size_t length=0;
    if (napi_get_cb_info(env,info,&argc,args,NULL,NULL)!=napi_ok || argc!=1 ||
        napi_get_value_string_utf8(env,args[0],filename,sizeof(filename),&length)!=napi_ok || !length || length>=sizeof(filename)-1) return NULL;
    struct dependency_broker *broker=calloc(1,sizeof(*broker));
    if (!broker) return NULL;
    broker->env=env;
    if (live_broker || !dependency_callbacks_init(broker)) abort();
    live_broker=broker;
    broker->marker=open(filename,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (broker->marker<0) abort();
    atomic_init(&broker->owner.closing,false);
    atomic_init(&broker->owner.fence_retained,false);
    atomic_init(&broker->request_expired,false);
    uv_loop_t *loop;
    if (clock_gettime(CLOCK_MONOTONIC,&broker->outer_deadline)) abort();
    broker->outer_deadline.tv_sec+=60;
    if (napi_get_uv_event_loop(env,&loop)!=napi_ok || uv_timer_init(loop,&broker->timer) ||
        napi_add_async_cleanup_hook(env,dependency_cleanup,broker,&broker->cleanup_hook)!=napi_ok) abort();
    broker->timer.data=broker;
    if (uv_timer_start(&broker->timer,dependency_timer,20,20)) abort();
    napi_get_undefined(env,&value);
    return value;
}
static napi_value assert_callback_alive(napi_env env,napi_callback_info info) {
    (void)info;napi_value resource,value;
    if (!live_broker || !live_broker->callback_depth || !live_broker->native_borrows || !live_broker->callback_context ||
        !live_broker->callback_resource || napi_get_reference_value(env,live_broker->callback_resource,&resource)!=napi_ok || !resource) abort();
    napi_get_undefined(env,&value);return value;
}
static napi_value assert_retired(napi_env env,napi_callback_info info) {
    (void)info;napi_value value;if (live_broker) abort();napi_get_undefined(env,&value);return value;
}
static napi_value initialize(napi_env env,napi_value exports) {
    const struct rlimit core={0,0};
    if (setrlimit(RLIMIT_CORE,&core)) return NULL;
    const napi_property_descriptor methods[]={{"exercise",NULL,exercise,NULL,NULL,NULL,napi_default,NULL},{"armCleanup",NULL,arm_cleanup,NULL,NULL,NULL,napi_default,NULL},
        {"assertCallbackAlive",NULL,assert_callback_alive,NULL,NULL,NULL,napi_default,NULL},{"assertRetired",NULL,assert_retired,NULL,NULL,NULL,napi_default,NULL}};
    if (napi_define_properties(env,exports,4,methods)!=napi_ok) return NULL;
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME,initialize)
