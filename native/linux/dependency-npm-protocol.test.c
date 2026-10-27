#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "dependency-npm-protocol.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"dependency config check %u failed at %u\n",checks,__LINE__);return 1; } } while(0)
static void string(struct cliq_verifier_config *config,const char *text,uint32_t *at) { size_t n=strlen(text)+1;*at=config->string_bytes;memcpy(config->strings+*at,text,n);config->string_bytes+=(uint32_t)n; }
static void file(struct cliq_verifier_config *config,const char *path) { unsigned i=config->file_count++;strcpy(config->files[i].path,path);memset(config->files[i].digest,'a',64);config->files[i].byte_count=1; }
static void valid(struct cliq_dependency_config *fixed) {
    memset(fixed,0,sizeof(*fixed));fixed->magic=CLIQ_DEPENDENCY_CONFIG_MAGIC;fixed->version=1;fixed->init_bytes=1;fixed->script_bytes=1;fixed->input_bytes=1;
    fixed->data_bytes=CLIQ_DEPENDENCY_DATA_BYTES;fixed->node_modules_device=1;fixed->node_modules_inode=2;
    char *digests[]={fixed->script_digest,fixed->input_digest,fixed->metadata_digest,fixed->dependency_plan_digest,fixed->descriptor_sequence_digest};
    for(unsigned i=0;i<5;i++) memset(digests[i],'a',64);
    strcpy(fixed->data_digest,"535b226efa5fa1c33d82e0634ac22a997c200db5799a787edd980f7de7a56f89");
    struct cliq_verifier_config *config=&fixed->capture;config->magic=CLIQ_VERIFIER_CONFIG_MAGIC;config->version=1;config->timeout_ms=60000;config->output_limit=67108864;
    strcpy(config->executable,"/usr/bin/node");strcpy(config->cwd,"/work");config->argument_count=3;config->environment_count=10;
    const char *args[]={"/usr/bin/node","--no-addons",CLIQ_DEPENDENCY_SCRIPT_PATH};
    const char *env[]={"PATH=/usr/bin:/bin","HOME=/home/cliq","TMPDIR=/tmp","LANG=C.UTF-8","LC_ALL=C.UTF-8","TZ=UTC","GIT_OPTIONAL_LOCKS=0","NODE_EXTRA_CA_CERTS=","NPM_CONFIG_USERCONFIG=/runtime/npm-config/user","NPM_CONFIG_GLOBALCONFIG=/runtime/npm-config/global"};
    for(unsigned i=0;i<3;i++)string(config,args[i],&config->arguments[i]);for(unsigned i=0;i<10;i++)string(config,env[i],&config->environment[i]);file(config,"/usr/bin/node");
}
int main(void) { struct cliq_worker_packet initial={0},packet={0},changed;
    initial.scope=2;memset(initial.nonce,'a',64);packet.magic=CLIQ_WORKER_MAGIC;packet.version=CLIQ_WORKER_VERSION;
    packet.scope=2;memcpy(packet.nonce,initial.nonce,sizeof(packet.nonce));
    const unsigned commands[]={CLIQ_STAGE_DEPENDENCY_CHUNK,CLIQ_SEAL_DEPENDENCY_INPUTS,CLIQ_RELEASE_DEPENDENCY_NPM};
    for(unsigned i=0;i<3;i++){
        packet.command=commands[i];CHECK(cliq_dependency_input_command_same(&packet,&initial,commands[i]));
#define REFUSE(field,value) do { changed=packet;changed.field=(value);CHECK(!cliq_dependency_input_command_same(&changed,&initial,commands[i])); } while(0)
        REFUSE(version,6);REFUSE(command,CLIQ_RELEASE_BUILTIN);REFUSE(status,1);REFUSE(scope,1);REFUSE(parent,1);
        REFUSE(observed_at_ms,1);REFUSE(stdout_bytes,1);REFUSE(max_output_bytes,1);REFUSE(init_reaped,1);REFUSE(nonce[0],'b');
#undef REFUSE
    }
    CHECK(!cliq_dependency_input_command_same(&packet,&initial,CLIQ_RELEASE_VERIFIER));initial.nonce[0]='A';
    CHECK(!cliq_dependency_input_command_same(&packet,&initial,CLIQ_RELEASE_DEPENDENCY_NPM));
    struct cliq_dependency_config *fixed=calloc(1,sizeof(*fixed));CHECK(fixed);valid(fixed);CHECK(cliq_dependency_config_valid(fixed));
    fixed->allow_scripts=1;CHECK(!cliq_dependency_config_valid(fixed));file(&fixed->capture,"/usr/bin/git");file(&fixed->capture,"/bin/bash");CHECK(cliq_dependency_config_valid(fixed));
    fixed->allow_scripts=0;CHECK(!cliq_dependency_config_valid(fixed));valid(fixed);fixed->capture.timeout_ms=60001;CHECK(!cliq_dependency_config_valid(fixed));
    valid(fixed);fixed->input_bytes=1048577;CHECK(!cliq_dependency_config_valid(fixed));valid(fixed);fixed->package_count=1;CHECK(!cliq_dependency_config_valid(fixed));
    fixed->metadata_bytes=1;CHECK(cliq_dependency_config_valid(fixed));fixed->package_count=200001;CHECK(!cliq_dependency_config_valid(fixed));
    valid(fixed);fixed->data_digest[0]='b';CHECK(!cliq_dependency_config_valid(fixed));valid(fixed);fixed->capture.environment[0]++;CHECK(!cliq_dependency_config_valid(fixed));
    valid(fixed);fixed->node_modules_inode=0;CHECK(!cliq_dependency_config_valid(fixed));free(fixed);printf("{\"checks\":%u,\"qualified\":false}\n",checks);return 0; }
