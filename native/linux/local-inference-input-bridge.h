#ifndef CLIQ_LOCAL_INFERENCE_INPUT_BRIDGE_H
#define CLIQ_LOCAL_INFERENCE_INPUT_BRIDGE_H
/* Same-process, same-env private resource-custody ABI. The StateOwner image
 * owns every original source FD and witness. A decoded artifact, callback or
 * JavaScript object cannot construct or replace this peer. */
#include <stdatomic.h>
#include "local-inference-birth.h"
#define CLIQ_LOCAL_INPUT_ABI 1U
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_LOCAL_INPUT_TAG = {UINT64_C(0x937a0b9edda140db), UINT64_C(0xbc8e7f8c36d8a096)};
static const napi_type_tag CLIQ_LOCAL_RETAINED_INPUT_TAG = {UINT64_C(0x47eac65193824c7f), UINT64_C(0xa1f843766056fa34)};
#endif
struct cliq_local_input {
  uint32_t abi;
  pid_t creator_pid;
  void *environment;
  atomic_bool closed, execution_claimed, execution_joined;
  int config_fd, birth_fd, sources[CLIQ_LOCAL_SERVICE_FILES];
  struct stat birth_identity;
  struct cliq_local_service_input config;
  struct cliq_local_birth_frame origin;
  bool bound, retained;
  bool (*assert_current)(struct cliq_local_input *);
  int (*retire)(struct cliq_local_input *);
};
#endif
