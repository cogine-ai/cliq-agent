#ifndef CLIQ_DEPENDENCY_NPM_PROTOCOL_H
#define CLIQ_DEPENDENCY_NPM_PROTOCOL_H
/* New fixed dependency family in the same unpublished private wire7. The
 * packet layout and every source/verifier/builtin acceptance rule stay intact.
 * This configuration is sealed data, never an execution grant. */
#include "verifier-protocol.h"
#include "worker-protocol.h"
#define CLIQ_DEPENDENCY_CONFIG_MAGIC UINT32_C(0x43444e31)
#define CLIQ_DEPENDENCY_SCRIPT_PATH "/runtime/cliq-npm-dependency.mjs"
#define CLIQ_DEPENDENCY_DATA_BYTES UINT64_C(11950276)
#define CLIQ_DEPENDENCY_PACKAGE_BYTES UINT64_C(67108864)
#define CLIQ_DEPENDENCY_INPUT_BYTES UINT64_C(1048576)
#define CLIQ_DEPENDENCY_METADATA_BYTES UINT64_C(67108864)
#define CLIQ_DEPENDENCY_CHUNK_BYTES UINT64_C(65536)
/* One fixed original channel only; status and every unrelated packet field
 * remain zero. This data test never supplies native origin or a release. */
static inline bool cliq_dependency_input_command_same(const struct cliq_worker_packet *packet,
    const struct cliq_worker_packet *initial,unsigned command) {
    if(command!=CLIQ_STAGE_DEPENDENCY_CHUNK && command!=CLIQ_SEAL_DEPENDENCY_INPUTS && command!=CLIQ_RELEASE_DEPENDENCY_NPM)return false;
    if(initial->scope==0 || initial->scope>=CLIQ_WORKER_MAX_SCOPES || strnlen(initial->nonce,sizeof(initial->nonce))!=64)return false;
    for(size_t i=0;i<64;i++)if(!((initial->nonce[i]>='0' && initial->nonce[i]<='9') || (initial->nonce[i]>='a' && initial->nonce[i]<='f')))return false;
    struct cliq_worker_packet expected;memset(&expected,0,sizeof(expected));expected.magic=CLIQ_WORKER_MAGIC;expected.version=CLIQ_WORKER_VERSION;
    expected.command=command;expected.scope=initial->scope;memcpy(expected.nonce,initial->nonce,sizeof(expected.nonce));
    return !memcmp(packet,&expected,sizeof(expected));
}
struct cliq_dependency_config {
    struct cliq_verifier_config capture;
    uint32_t magic, version, allow_scripts, package_count;
    uint64_t init_bytes, script_bytes, input_bytes, metadata_bytes, data_bytes;
    uint64_t node_modules_device, node_modules_inode;
    char script_digest[65], input_digest[65], metadata_digest[65], data_digest[65];
    char dependency_plan_digest[65], descriptor_sequence_digest[65];
};
_Static_assert(offsetof(struct cliq_dependency_config, capture) == 0, "original captured result allocation prefix");
static inline bool cliq_dependency_digest(const char *text) {
    if (strnlen(text, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
static inline bool cliq_dependency_config_valid(const struct cliq_dependency_config *fixed) {
    const struct cliq_verifier_config *config = &fixed->capture;
    if (fixed->magic != CLIQ_DEPENDENCY_CONFIG_MAGIC || fixed->version != 1 || fixed->allow_scripts > 1 || fixed->package_count > 200000 ||
        fixed->init_bytes < 1 || fixed->init_bytes > UINT64_C(268435456) || fixed->script_bytes < 1 || fixed->script_bytes > CLIQ_DEPENDENCY_INPUT_BYTES ||
        fixed->input_bytes < 1 || fixed->input_bytes > CLIQ_DEPENDENCY_INPUT_BYTES || fixed->metadata_bytes > CLIQ_DEPENDENCY_METADATA_BYTES ||
        ((fixed->package_count == 0) != (fixed->metadata_bytes == 0)) || fixed->data_bytes != CLIQ_DEPENDENCY_DATA_BYTES ||
        !fixed->node_modules_device || !fixed->node_modules_inode ||
        !cliq_dependency_digest(fixed->script_digest) || !cliq_dependency_digest(fixed->input_digest) ||
        !cliq_dependency_digest(fixed->metadata_digest) || !cliq_dependency_digest(fixed->dependency_plan_digest) ||
        !cliq_dependency_digest(fixed->descriptor_sequence_digest) ||
        strcmp(fixed->data_digest, "535b226efa5fa1c33d82e0634ac22a997c200db5799a787edd980f7de7a56f89") ||
        config->magic != CLIQ_VERIFIER_CONFIG_MAGIC || config->version != 1 || config->file_count < 1 ||
        config->file_count > CLIQ_VERIFIER_MAX_FILES || config->argument_count != 3 || config->environment_count != 10 ||
        config->string_bytes < 1 || config->string_bytes > CLIQ_VERIFIER_STRING_BYTES || config->strings[config->string_bytes - 1] != '\0' ||
        config->timeout_ms < 1 || config->timeout_ms > UINT64_C(60000) || config->output_limit < UINT64_C(65536) ||
        config->output_limit > UINT64_C(67108864) || strcmp(config->executable, "/usr/bin/node") || strcmp(config->cwd, "/work")) return false;
    const char *arguments[] = { "/usr/bin/node", "--no-addons", CLIQ_DEPENDENCY_SCRIPT_PATH };
    const char *environment[] = { "PATH=/usr/bin:/bin", "HOME=/home/cliq", "TMPDIR=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC",
        "GIT_OPTIONAL_LOCKS=0", "NODE_EXTRA_CA_CERTS=", "NPM_CONFIG_USERCONFIG=/runtime/npm-config/user", "NPM_CONFIG_GLOBALCONFIG=/runtime/npm-config/global" };
    uint32_t offset = 0;
    for (uint32_t i = 0; i < 13; i++) {
        uint32_t at = i < 3 ? config->arguments[i] : config->environment[i - 3];
        const char *literal = i < 3 ? arguments[i] : environment[i - 3]; size_t length = strlen(literal) + 1;
        if (at != offset || at >= config->string_bytes || length > config->string_bytes - at || memcmp(config->strings + at, literal, length)) return false;
        offset += (uint32_t)length;
    }
    if (offset != config->string_bytes) return false;
    bool node = false, git = false, bash = false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        const char *path = config->files[i].path;
        bool extra = !strcmp(path, "/usr/bin/git") || !strcmp(path, "/bin/bash");
        if (!cliq_verifier_path(path) || !(cliq_verifier_mapping_path(path) || (fixed->allow_scripts && extra)) ||
            !cliq_dependency_digest(config->files[i].digest) || config->files[i].byte_count < 1 || config->files[i].byte_count > UINT64_C(268435456)) return false;
        for (uint32_t j = 0; j < i; j++) if (!strcmp(path, config->files[j].path)) return false;
        if (!strcmp(path, "/usr/bin/node")) node = true;
        if (!strcmp(path, "/usr/bin/git")) git = true;
        if (!strcmp(path, "/bin/bash")) bash = true;
    }
    return node && (fixed->allow_scripts ? git && bash : !git && !bash);
}
static inline bool cliq_dependency_page_add(uint64_t *used,uint64_t bytes,uint64_t limit) {
    if(bytes>UINT64_MAX-4095)return false;uint64_t rounded=(bytes+4095)&~UINT64_C(4095);
    if(*used>limit || rounded>limit-*used)return false;*used+=rounded;return true;
}
static inline bool cliq_dependency_storage(const struct cliq_dependency_config *fixed,const struct cliq_worker_packet *request,uint64_t *root,uint64_t *scratch) {
    if(!cliq_dependency_config_valid(fixed))return false;
    uint64_t runtime=UINT64_C(1048576)+UINT64_C(33554432);
    if(!cliq_dependency_page_add(&runtime,fixed->init_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&runtime,fixed->script_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&runtime,fixed->data_bytes,request->max_generation_bytes))return false;
    for(uint32_t i=0;i<fixed->capture.file_count;i++)if(!cliq_dependency_page_add(&runtime,fixed->capture.files[i].byte_count,request->max_generation_bytes))return false;
    uint64_t total=runtime;
    if(!cliq_dependency_page_add(&total,fixed->input_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&total,fixed->metadata_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&total,request->max_output_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&total,request->max_output_bytes,request->max_generation_bytes) ||
        !cliq_dependency_page_add(&total,sizeof(*fixed),request->max_generation_bytes) || total>=request->max_generation_bytes)return false;
    *root=runtime & ~UINT64_C(4095);*scratch=(request->max_generation_bytes-total)&~UINT64_C(4095);return *root && *scratch;
}

#endif
