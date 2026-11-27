#ifndef CLIQ_DEPENDENCY_RESULT_ACK_H
#define CLIQ_DEPENDENCY_RESULT_ACK_H
#include "worker-common.h"
/* Disjoint fixed ACK purpose. These checks release settled data only and
 * neither prove a completed Journal nor grant productive execution. */
static inline bool cliq_dependency_result_ack_valid(const struct cliq_worker_packet *packet) {
    if(packet->scope==0 || packet->scope>=CLIQ_WORKER_MAX_SCOPES || packet->parent==0 || packet->parent>=CLIQ_WORKER_MAX_SCOPES ||
        packet->parent==packet->scope || !packet->observed_at_ms || packet->observed_at_ms>UINT64_C(9007199254740991) ||
        strnlen(packet->nonce,sizeof(packet->nonce))!=64)return false;
    for(size_t i=0;i<64;i++)if(!((packet->nonce[i]>='0' && packet->nonce[i]<='9') || (packet->nonce[i]>='a' && packet->nonce[i]<='f')))return false;
    struct cliq_worker_packet expected=cliq_packet(CLIQ_ACK_DEPENDENCY_RESULT);expected.scope=packet->scope;expected.parent=packet->parent;
    expected.observed_at_ms=packet->observed_at_ms;memcpy(expected.nonce,packet->nonce,64);return !memcmp(&expected,packet,sizeof(expected));
}
static inline bool cliq_dependency_result_ack_same(const struct cliq_worker_packet *packet,unsigned scope,unsigned parent,const char nonce[65],uint64_t at) {
    return cliq_dependency_result_ack_valid(packet) && packet->scope==scope && packet->parent==parent && packet->observed_at_ms==at && !memcmp(packet->nonce,nonce,65);
}
#endif
