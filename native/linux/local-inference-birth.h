#ifndef CLIQ_LOCAL_INFERENCE_BIRTH_H
#define CLIQ_LOCAL_INFERENCE_BIRTH_H
/* Bounded physical witness for the one already-reserved service launch.
 * This is not an execution ledger or a substitute for current inspection. */
#include "local-inference-protocol.h"
#include "worker-sha256.h"
#define CLIQ_LOCAL_BIRTH_MAGIC UINT32_C(0x434c4231)
#define CLIQ_LOCAL_BIRTH_MAX_FRAMES 128U
enum cliq_local_birth_step {
  CLIQ_LOCAL_BIRTH_RESERVED = 1, CLIQ_LOCAL_BIRTH_CREATE_INTENT = 2, CLIQ_LOCAL_BIRTH_CGROUP_CREATED = 3,
  CLIQ_LOCAL_BIRTH_PREPARE_INTENT = 4, CLIQ_LOCAL_BIRTH_PREPARE_FORKED = 5,
  CLIQ_LOCAL_BIRTH_INPUT_HANDED = 6, CLIQ_LOCAL_BIRTH_PREPARE_JOINED = 7,
  CLIQ_LOCAL_BIRTH_NAMESPACE_INTENT = 8, CLIQ_LOCAL_BIRTH_NAMESPACE_FORKED = 9,
  CLIQ_LOCAL_BIRTH_READY = 10, CLIQ_LOCAL_BIRTH_ENGINE_RELEASED = 11,
  CLIQ_LOCAL_BIRTH_QUIESCENT = 12, CLIQ_LOCAL_BIRTH_FDS_RETIRED = 13
};
struct cliq_local_birth_identity { uint64_t device, inode, uid, gid, mode; };
struct cliq_local_birth_frame {
  uint32_t magic, version, ordinal, step;
  struct cliq_local_service_packet packet;
  int64_t controller_pid;
  char controller_start[192];
  uint64_t controller_device, controller_inode, controller_uid;
  struct cliq_local_birth_identity state_root, runtime, private_parent, birth;
  struct cliq_local_birth_identity controller_anchor, controller_parent, controller_leaf;
  char controller_leaf_name[64];
  unsigned char previous[32], digest[32];
};
#if defined(__x86_64__)
_Static_assert(sizeof(struct cliq_local_birth_frame) == 4144, "local birth v1 layout changed");
_Static_assert(offsetof(struct cliq_local_birth_frame, digest) == 4112, "local birth v1 digest offset changed");
#endif
struct cliq_local_birth_history {
  struct cliq_local_birth_frame first, last, ready;
  uint32_t count;
  bool namespace_intent;
};
static inline bool cliq_local_birth_token(const char *token, size_t capacity) {
  static const char prefix[] = "linux-proc-start-ticks:"; size_t length = strnlen(token, capacity);
  if (length <= sizeof(prefix) - 1 || length >= capacity || memcmp(token, prefix, sizeof(prefix) - 1)) return false;
  const char *number = token + sizeof(prefix) - 1; size_t digits = length - sizeof(prefix) + 1;
  if (!digits || digits > 20 || number[0] < '1' || number[0] > '9' || (digits == 20 && strcmp(number, "18446744073709551615") > 0)) return false;
  for (size_t i = 1; i < digits; ++i) if (number[i] < '0' || number[i] > '9') return false;
  return true;
}
static inline bool cliq_local_birth_controller_name(const char *name) {
  if (strnlen(name, 64) != 43 || memcmp(name, "controller-", 11)) return false;
  for (size_t i = 11; i < 43; ++i) if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
  return true;
}
static inline bool cliq_local_birth_observation_valid(const struct cliq_local_service_observation *value) {
  const int64_t pids[] = {value->preparation_pid, value->monitor_pid, value->namespace_init_pid, value->bootstrap_pid};
  const char *tokens[] = {value->preparation_start, value->monitor_start, value->namespace_init_start, value->bootstrap_start};
  for (size_t i = 0; i < 4; ++i) {
    if (pids[i] < 0 || pids[i] > INT32_MAX || (pids[i] == 0 ? tokens[i][0] != '\0' : !cliq_local_birth_token(tokens[i], 192))) return false;
  }
  return value->observed_at_ms == 0 && (value->cgroup_device == 0) == (value->cgroup_inode == 0) &&
    (value->pid_namespace_inode ? value->namespace_init_pid > 0 && value->bootstrap_pid > 0 : value->namespace_init_pid == 0 && value->bootstrap_pid == 0) &&
    value->prepared_count <= CLIQ_LOCAL_SERVICE_FILES && value->populated <= 1 && value->remaining_descendants <= 4096 && value->all_reaped <= 1;
}
static inline bool cliq_local_birth_observation_transition(const struct cliq_local_birth_frame *previous, const struct cliq_local_birth_frame *next) {
  const struct cliq_local_service_observation *left = &previous->packet.observation, *right = &next->packet.observation;
  if (!cliq_local_birth_observation_valid(right)) return false;
  if (left->cgroup_inode ? left->cgroup_inode != right->cgroup_inode || left->cgroup_device != right->cgroup_device :
      right->cgroup_inode && next->step != CLIQ_LOCAL_BIRTH_CGROUP_CREATED) return false;
  const int64_t old_pids[] = {left->preparation_pid, left->monitor_pid, left->namespace_init_pid, left->bootstrap_pid};
  const int64_t new_pids[] = {right->preparation_pid, right->monitor_pid, right->namespace_init_pid, right->bootstrap_pid};
  const char *old_tokens[] = {left->preparation_start, left->monitor_start, left->namespace_init_start, left->bootstrap_start};
  const char *new_tokens[] = {right->preparation_start, right->monitor_start, right->namespace_init_start, right->bootstrap_start};
  const uint32_t births[] = {CLIQ_LOCAL_BIRTH_PREPARE_FORKED, CLIQ_LOCAL_BIRTH_NAMESPACE_FORKED, CLIQ_LOCAL_BIRTH_READY, CLIQ_LOCAL_BIRTH_READY};
  for (size_t i = 0; i < 4; ++i) {
    if (old_pids[i] ? old_pids[i] != new_pids[i] || strcmp(old_tokens[i], new_tokens[i]) : new_pids[i] && next->step != births[i]) return false;
  }
  if (left->pid_namespace_inode ? left->pid_namespace_inode != right->pid_namespace_inode :
      right->pid_namespace_inode && next->step != CLIQ_LOCAL_BIRTH_READY) return false;
  if (next->step != CLIQ_LOCAL_BIRTH_INPUT_HANDED && left->prepared_count != right->prepared_count) return false;
  if (next->step < CLIQ_LOCAL_BIRTH_QUIESCENT && right->all_reaped) return false;
  if (next->step >= CLIQ_LOCAL_BIRTH_QUIESCENT && (!right->all_reaped || right->populated || right->remaining_descendants)) return false;
  return true;
}
static inline void cliq_local_birth_hash(const void *data, size_t size, unsigned char bytes[32]) {
  struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, data, size); sha256_final(&hash, bytes);
}
static inline bool cliq_local_birth_same_origin(const struct cliq_local_birth_frame *left,
  const struct cliq_local_birth_frame *right) {
  return memcmp(&left->packet.binding, &right->packet.binding, sizeof(left->packet.binding)) == 0 &&
    memcmp(&left->packet.resources, &right->packet.resources, sizeof(left->packet.resources)) == 0 &&
    memcmp(left->packet.input_digest, right->packet.input_digest, sizeof(left->packet.input_digest)) == 0 &&
    left->controller_pid == right->controller_pid && strcmp(left->controller_start, right->controller_start) == 0 &&
    left->controller_device == right->controller_device && left->controller_inode == right->controller_inode && left->controller_uid == right->controller_uid &&
    memcmp(&left->state_root, &right->state_root, sizeof(left->state_root)) == 0 &&
    memcmp(&left->runtime, &right->runtime, sizeof(left->runtime)) == 0 &&
    memcmp(&left->private_parent, &right->private_parent, sizeof(left->private_parent)) == 0 &&
    memcmp(&left->birth, &right->birth, sizeof(left->birth)) == 0 &&
    memcmp(&left->controller_anchor, &right->controller_anchor, sizeof(left->controller_anchor)) == 0 &&
    memcmp(&left->controller_parent, &right->controller_parent, sizeof(left->controller_parent)) == 0 &&
    memcmp(&left->controller_leaf, &right->controller_leaf, sizeof(left->controller_leaf)) == 0 &&
    memcmp(left->controller_leaf_name, right->controller_leaf_name, sizeof(left->controller_leaf_name)) == 0;
}
static inline bool cliq_local_birth_step_valid(const struct cliq_local_birth_frame *previous,
  const struct cliq_local_birth_frame *next) {
  if (!previous) {
    struct cliq_local_service_observation empty = {0};
    return next->step == CLIQ_LOCAL_BIRTH_RESERVED && next->ordinal == 1 && !memcmp(&next->packet.observation, &empty, sizeof(empty));
  }
  if (!cliq_local_birth_same_origin(previous, next) || !cliq_local_birth_observation_transition(previous, next)) return false;
  unsigned from = previous->step, to = next->step;
  if (to == CLIQ_LOCAL_BIRTH_QUIESCENT) return from >= CLIQ_LOCAL_BIRTH_RESERVED && from < CLIQ_LOCAL_BIRTH_QUIESCENT;
  if (from == CLIQ_LOCAL_BIRTH_QUIESCENT) return to == CLIQ_LOCAL_BIRTH_FDS_RETIRED;
  if (from == CLIQ_LOCAL_BIRTH_INPUT_HANDED && to == CLIQ_LOCAL_BIRTH_INPUT_HANDED)
    return next->packet.observation.prepared_count == previous->packet.observation.prepared_count + 1;
  if (from == CLIQ_LOCAL_BIRTH_PREPARE_FORKED && to == CLIQ_LOCAL_BIRTH_INPUT_HANDED)
    return next->packet.observation.prepared_count == 1;
  if (from == CLIQ_LOCAL_BIRTH_INPUT_HANDED && to == CLIQ_LOCAL_BIRTH_PREPARE_JOINED)
    return next->packet.observation.prepared_count == previous->packet.observation.prepared_count;
  return to == from + 1;
}
static inline bool cliq_local_birth_read_exact(int descriptor, void *bytes, size_t size, off_t offset) {
  size_t done = 0;
  while (done < size) {
    ssize_t count = pread(descriptor, (unsigned char *)bytes + done, size - done, offset + (off_t)done);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    done += (size_t)count;
  }
  return true;
}
static inline bool cliq_local_birth_read_complete(int descriptor, struct cliq_local_birth_history *history,
  unsigned char complete_digest[32], uint64_t *complete_bytes) {
  if ((complete_digest == NULL) != (complete_bytes == NULL)) return false;
  memset(history, 0, sizeof(*history)); struct stat before, after;
  if (fstat(descriptor, &before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() || before.st_gid != getegid() ||
      (before.st_mode & 07777) != 0600 || before.st_nlink != 1 || before.st_size <= 0 ||
      (uint64_t)before.st_size > sizeof(struct cliq_local_birth_frame) * (uint64_t)CLIQ_LOCAL_BIRTH_MAX_FRAMES ||
      before.st_size % sizeof(struct cliq_local_birth_frame)) return false;
  unsigned char previous[32] = {0}; struct sha256_context complete;
  if (complete_digest) sha256_init(&complete);
  size_t count = (size_t)before.st_size / sizeof(struct cliq_local_birth_frame);
  for (size_t i = 0; i < count; ++i) {
    struct cliq_local_birth_frame frame; unsigned char digest[32];
    if (!cliq_local_birth_read_exact(descriptor, &frame, sizeof(frame), (off_t)(i * sizeof(frame)))) return false;
    cliq_local_birth_hash(&frame, offsetof(struct cliq_local_birth_frame, digest), digest);
    if (frame.magic != CLIQ_LOCAL_BIRTH_MAGIC || frame.version != 1 || frame.ordinal != i + 1 ||
        frame.step < CLIQ_LOCAL_BIRTH_RESERVED || frame.step > CLIQ_LOCAL_BIRTH_FDS_RETIRED ||
        frame.packet.magic != CLIQ_LOCAL_SERVICE_MAGIC || frame.packet.version != 1 || frame.packet.command != CLIQ_LOCAL_SERVICE_RESERVE || frame.packet.status ||
        !cliq_local_service_binding_valid(&frame.packet.binding) || !cliq_local_service_resources_valid(&frame.packet.resources) || !cliq_hex_digest(frame.packet.input_digest) ||
        frame.controller_pid <= 0 || frame.controller_pid > INT32_MAX || !cliq_local_birth_token(frame.controller_start, sizeof(frame.controller_start)) ||
        !cliq_local_birth_controller_name(frame.controller_leaf_name) || !cliq_local_birth_observation_valid(&frame.packet.observation) ||
        memcmp(previous, frame.previous, 32) || memcmp(digest, frame.digest, 32) ||
        !cliq_local_birth_step_valid(i ? &history->last : NULL, &frame)) return false;
    if (i == 0) history->first = frame;
    if (frame.step == CLIQ_LOCAL_BIRTH_NAMESPACE_INTENT) history->namespace_intent = true;
    if (frame.step == CLIQ_LOCAL_BIRTH_READY) history->ready = frame;
    history->last = frame; memcpy(previous, frame.digest, 32);
    if (complete_digest) sha256_update(&complete, (const unsigned char *)&frame, sizeof(frame));
  }
  history->count = (uint32_t)count;
  bool stable = fstat(descriptor, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
    before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_mode == after.st_mode &&
    before.st_size == after.st_size && before.st_nlink == after.st_nlink &&
    before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
    before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  if (stable && complete_digest) {
    sha256_final(&complete, complete_digest); *complete_bytes = (uint64_t)before.st_size;
  }
  return stable;
}
static inline bool cliq_local_birth_read(int descriptor, struct cliq_local_birth_history *history) {
  return cliq_local_birth_read_complete(descriptor, history, NULL, NULL);
}
static inline bool cliq_local_birth_append(int descriptor, struct cliq_local_birth_frame *next) {
  struct cliq_local_birth_history history; struct stat file;
  if (fstat(descriptor, &file) || !S_ISREG(file.st_mode) || file.st_uid != geteuid() || file.st_gid != getegid() ||
      (file.st_mode & 07777) != 0600 || file.st_nlink != 1 || file.st_size < 0) return false;
  memset(&history, 0, sizeof(history));
  if (file.st_size && !cliq_local_birth_read(descriptor, &history)) return false;
  next->ordinal = history.count + 1;
  if (history.count >= CLIQ_LOCAL_BIRTH_MAX_FRAMES ||
      !cliq_local_birth_step_valid(history.count ? &history.last : NULL, next)) return false;
  next->magic = CLIQ_LOCAL_BIRTH_MAGIC; next->version = 1; next->ordinal = history.count + 1;
  memset(next->previous, 0, sizeof(next->previous));
  if (history.count) memcpy(next->previous, history.last.digest, sizeof(next->previous));
  cliq_local_birth_hash(next, offsetof(struct cliq_local_birth_frame, digest), next->digest);
  const unsigned char *bytes = (const unsigned char *)next; size_t offset = 0;
  while (offset < sizeof(*next)) {
    ssize_t count = pwrite(descriptor, bytes + offset, sizeof(*next) - offset, file.st_size + (off_t)offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += (size_t)count;
  }
  int result; do { result = fsync(descriptor); } while (result < 0 && errno == EINTR);
  return result == 0;
}
#endif
