#ifndef CLIQ_LOCAL_INFERENCE_OWNER_BRIDGE_H
#define CLIQ_LOCAL_INFERENCE_OWNER_BRIDGE_H
/* Same-process/env C-private friendship to the original service owner.
 * No JS FD, callback, URL, host namespace or structural owner is accepted. */
#include "local-inference-protocol.h"
#define CLIQ_LOCAL_OWNER_ABI 1U
enum cliq_local_peer_purpose { CLIQ_LOCAL_PEER_HEALTH = 1, CLIQ_LOCAL_PEER_MODEL = 2 };
enum cliq_local_peer_result { CLIQ_LOCAL_PEER_NOT_LISTENING = -2 };
#if defined(NAPI_VERSION)
static const napi_type_tag CLIQ_LOCAL_HEALTH_PEER_TAG = {UINT64_C(0x1491e710b4ce43e2), UINT64_C(0x9d09f846caabbd70)};
static const napi_type_tag CLIQ_LOCAL_MODEL_PEER_TAG = {UINT64_C(0x8e087dc90f054a87), UINT64_C(0xa7025e6b8702b97a)};
#endif
struct cliq_local_service_peer {
  uint32_t abi, purpose;
  pid_t creator_pid;
  void *environment;
  struct cliq_local_service_binding binding;
  bool borrowed;
  bool (*assert_current)(struct cliq_local_service_peer *);
  int (*begin_connection)(struct cliq_local_service_peer *);
  /* 0=original pending; 1=one connected FD; -1=refusal; -2=the original
   * fixed private listener refused a connection. None proves no model effect. */
  int (*poll_connection)(struct cliq_local_service_peer *, int *);
  int (*cancel)(struct cliq_local_service_peer *);
  /* Cancellation is not join. Only actual pending reply consumption/FD close,
   * or the original controller's complete physical join, returns 1. */
  int (*poll_joined)(struct cliq_local_service_peer *);
  int (*release)(struct cliq_local_service_peer *);
};
#endif
