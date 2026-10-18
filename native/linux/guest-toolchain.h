#ifndef CLIQ_GUEST_TOOLCHAIN_H
#define CLIQ_GUEST_TOOLCHAIN_H

/* Private ABI shared only by the signed extractor and worker addon. No JS
 * object, integer FD array, digest or retained report can impersonate it. */
#include <node_api.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define CLIQ_GUEST_ABI_VERSION 1
#define CLIQ_GUEST_MAX_FILES 32
#define CLIQ_GUEST_MAX_PINNED 32
#define CLIQ_GUEST_PATH_BYTES 4096
#define CLIQ_GUEST_IMAGE_BYTES UINT64_C(268435456)

static const napi_type_tag CLIQ_GUEST_TOOLCHAIN_TAG = {
    UINT64_C(0x4df929b45fc4476c), UINT64_C(0x9a8f3167d867ec21)
};

struct cliq_guest_file {
    int fd;
    uint64_t byte_count;
    char path[CLIQ_GUEST_PATH_BYTES];
    char digest[65];
};

/* This prefix is the napi_unwrap pointer. The extractor alone mutates it,
 * publishing ready with release ordering after every file is sealed. A worker
 * call consumes it synchronously before any close can run on the JS thread. */
struct cliq_guest_toolchain {
    uint32_t abi_version;
    atomic_bool ready;
    atomic_bool revoked;
    uint32_t file_count;
    char image_digest[65];
    char node_path[CLIQ_GUEST_PATH_BYTES];
    char node_digest[65];
    struct cliq_guest_file files[CLIQ_GUEST_MAX_FILES];
};

#endif
