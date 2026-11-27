#ifndef CLIQ_LOCAL_INFERENCE_PROTOCOL_H
#define CLIQ_LOCAL_INFERENCE_PROTOCOL_H
/* Independent closed purpose in the same signed controller image. No Run,
 * Journal, Worker parent, MCP/Admin grant, caller argv or host pathname is
 * represented by this descriptor protocol. Existing worker wire9 is intact. */
#include <stddef.h>
#include <stdint.h>
#include "worker-common.h"
#define CLIQ_LOCAL_SERVICE_MAGIC UINT32_C(0x434c5331)
#define CLIQ_LOCAL_SERVICE_VERSION 1U
#define CLIQ_LOCAL_SERVICE_FDS 40U
#define CLIQ_LOCAL_SERVICE_FILES 32U
#define CLIQ_LOCAL_SERVICE_ID 257U
#define CLIQ_LOCAL_SERVICE_PATH 4096U
enum cliq_local_service_command {
  CLIQ_LOCAL_SERVICE_HELLO = 1, CLIQ_LOCAL_SERVICE_RESERVE = 2,
  CLIQ_LOCAL_SERVICE_PREPARE = 3, CLIQ_LOCAL_SERVICE_POLL_PREPARED = 4,
  CLIQ_LOCAL_SERVICE_CREATE_BLOCKED = 5, CLIQ_LOCAL_SERVICE_RELEASE_ENGINE = 6,
  CLIQ_LOCAL_SERVICE_CONNECT_HEALTH = 7, CLIQ_LOCAL_SERVICE_CONNECT_MODEL = 8,
  CLIQ_LOCAL_SERVICE_STOP = 9, CLIQ_LOCAL_SERVICE_ACK = 10,
  CLIQ_LOCAL_SERVICE_CLEANUP_ORIGINAL = 11, CLIQ_LOCAL_SERVICE_READY = 12,
  CLIQ_LOCAL_SERVICE_ACTIVATED = 13, CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE = 14, CLIQ_LOCAL_SERVICE_INSPECT_ACTIVE = 15
};
struct cliq_local_service_binding {
  char owner[CLIQ_LOCAL_SERVICE_ID], service[CLIQ_LOCAL_SERVICE_ID], launch[CLIQ_LOCAL_SERVICE_ID];
  char cycle[CLIQ_LOCAL_SERVICE_ID], supervisor[CLIQ_LOCAL_SERVICE_ID];
  char registration_ref[65], registration_digest[65], service_ref[65], service_digest[65];
  char runtime_ref[65], runtime_digest[65], model_ref[65], model_digest[65], closure_ref[65], closure_digest[65];
  char profile_ref[65], profile_digest[65], plan_ref[65], plan_digest[65], spec_ref[65], spec_digest[65];
  char native_nonce[65], activation_nonce[65];
  uint64_t owner_epoch, created_at_ms, activation_deadline_ms;
  uint32_t attempt, port;
};
struct cliq_local_service_resources {
  uint64_t max_processes, memory_bytes, cpu_quota, max_open_files, max_file_bytes;
  uint64_t max_generation_bytes, max_output_bytes, max_ipc_bytes, max_queued_ipc_bytes;
};
struct cliq_local_service_observation {
  uint64_t observed_at_ms, cgroup_device, cgroup_inode, pid_namespace_inode;
  int64_t preparation_pid, monitor_pid, namespace_init_pid, bootstrap_pid;
  char preparation_start[192], monitor_start[192], namespace_init_start[192], bootstrap_start[192];
  uint32_t prepared_count, populated, remaining_descendants, all_reaped;
};
struct cliq_local_service_packet {
  uint32_t magic, version, command, status;
  char input_digest[65];
  struct cliq_local_service_binding binding;
  struct cliq_local_service_resources resources;
  struct cliq_local_service_observation observation;
};
enum cliq_local_service_file_kind {
  CLIQ_LOCAL_FILE_MANIFEST = 1, CLIQ_LOCAL_FILE_TOKENIZER = 2, CLIQ_LOCAL_FILE_MODEL = 3,
  CLIQ_LOCAL_FILE_ENGINE = 4, CLIQ_LOCAL_FILE_LIBRARY = 5, CLIQ_LOCAL_FILE_HELPER = 6, CLIQ_LOCAL_FILE_LOADER = 7
};
struct cliq_local_service_file {
  uint32_t kind, mode;
  uint64_t byte_count;
  char digest[65], guest_path[CLIQ_LOCAL_SERVICE_PATH];
};
struct cliq_local_service_input {
  uint32_t magic, version, file_count, model_mount_count;
  struct cliq_local_service_binding binding;
  struct cliq_local_service_resources resources;
  char bootstrap_digest[65], controller_digest[65], bubblewrap_digest[65];
  uint64_t bootstrap_bytes, controller_bytes, bubblewrap_bytes;
  struct cliq_local_service_file files[CLIQ_LOCAL_SERVICE_FILES];
};
#if defined(__x86_64__)
/* Durable little-endian native input v1. The data-only reader checks the
 * same fixed offsets and complete bytes independently of the native ABI. */
_Static_assert(sizeof(struct cliq_local_service_binding) == 2488, "local binding v1 layout changed");
_Static_assert(sizeof(struct cliq_local_service_file) == 4184, "local file v1 layout changed");
_Static_assert(sizeof(struct cliq_local_service_input) == 136688, "local input v1 layout changed");
_Static_assert(offsetof(struct cliq_local_service_input, files) == 2800, "local file v1 offset changed");
_Static_assert(sizeof(struct cliq_local_service_packet) == 3496, "local packet v1 layout changed");
_Static_assert(offsetof(struct cliq_local_service_packet, observation) == 2648, "local observation v1 offset changed");
#endif
static inline bool cliq_local_service_text(const char *value, size_t capacity) {
  return capacity > 1 && value[0] != '\0' && memchr(value, '\0', capacity) != NULL;
}
static inline bool cliq_local_service_binding_valid(const struct cliq_local_service_binding *binding) {
  const char *ids[] = {binding->owner, binding->service, binding->launch, binding->cycle, binding->supervisor};
  for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i)
    if (!cliq_local_service_text(ids[i], CLIQ_LOCAL_SERVICE_ID)) return false;
  const char *refs[] = {binding->registration_ref, binding->registration_digest, binding->service_ref, binding->service_digest,
    binding->runtime_ref, binding->runtime_digest, binding->model_ref, binding->model_digest, binding->closure_ref, binding->closure_digest,
    binding->profile_ref, binding->profile_digest, binding->plan_ref, binding->plan_digest, binding->spec_ref, binding->spec_digest,
    binding->native_nonce, binding->activation_nonce};
  for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); ++i) if (!cliq_hex_digest(refs[i])) return false;
  return binding->owner_epoch > 0 && binding->owner_epoch <= UINT64_C(9007199254740991) &&
    (binding->attempt == 1 || binding->attempt == 2) && binding->port >= 49152 && binding->port <= 65535 &&
    binding->created_at_ms > 0 && binding->created_at_ms <= UINT64_C(9007199254620991) &&
    binding->activation_deadline_ms == binding->created_at_ms + 120000;
}
static inline bool cliq_local_service_resources_valid(const struct cliq_local_service_resources *resource) {
  /* The first fixed local-service recipe uses the displayed original defaults.
   * This is not an opportunity to raise writable file/memory/IPC ceilings. */
  return resource->max_processes == 256 && resource->memory_bytes == UINT64_C(4294967296) && resource->cpu_quota == 400000 &&
    resource->max_open_files == 1024 && resource->max_file_bytes == UINT64_C(268435456) &&
    resource->max_generation_bytes == UINT64_C(21474836480) && resource->max_output_bytes == UINT64_C(16777216) &&
    resource->max_ipc_bytes == UINT64_C(16777216) && resource->max_queued_ipc_bytes == UINT64_C(67108864);
}
static inline bool cliq_local_service_guest_path(const char *path) {
  size_t length = strnlen(path, CLIQ_LOCAL_SERVICE_PATH);
  if (length < 2 || length == CLIQ_LOCAL_SERVICE_PATH || path[0] != '/' || path[length - 1] == '/') return false;
  const char *cursor = path + 1; unsigned depth = 0;
  while (*cursor) {
    const char *end = strchr(cursor, '/'); size_t count = end ? (size_t)(end - cursor) : strlen(cursor);
    if (!count || count > 255 || ++depth > 68 || (count == 1 && cursor[0] == '.') ||
        (count == 2 && cursor[0] == '.' && cursor[1] == '.')) return false;
    for (size_t i = 0; i < count; ++i) if ((unsigned char)cursor[i] < 0x20 || cursor[i] == '\\') return false;
    cursor = end ? end + 1 : cursor + count;
  }
  return true;
}
static inline bool cliq_local_service_input_valid(const struct cliq_local_service_input *input) {
  if (input->magic != CLIQ_LOCAL_SERVICE_MAGIC || input->version != CLIQ_LOCAL_SERVICE_VERSION || input->file_count < 5 ||
      input->file_count > CLIQ_LOCAL_SERVICE_FILES || !cliq_local_service_binding_valid(&input->binding) ||
      !cliq_local_service_resources_valid(&input->resources) || !cliq_hex_digest(input->bootstrap_digest) ||
      !cliq_hex_digest(input->controller_digest) || !cliq_hex_digest(input->bubblewrap_digest) ||
      !input->bootstrap_bytes || input->bootstrap_bytes > input->resources.max_file_bytes || !input->controller_bytes ||
      input->controller_bytes > input->resources.max_file_bytes || !input->bubblewrap_bytes || input->bubblewrap_bytes > input->resources.max_file_bytes) return false;
  unsigned manifests = 0, tokenizers = 0, engines = 0, helpers = 0, loaders = 0, models = 0; uint64_t total = 0;
  for (uint32_t i = 0; i < input->file_count; ++i) {
    const struct cliq_local_service_file *file = &input->files[i];
    if (file->kind < CLIQ_LOCAL_FILE_MANIFEST || file->kind > CLIQ_LOCAL_FILE_LOADER || !cliq_hex_digest(file->digest) ||
        !file->byte_count || file->byte_count > input->resources.max_file_bytes ||
        file->byte_count > input->resources.memory_bytes - total || !cliq_local_service_guest_path(file->guest_path) ||
        file->mode != (file->kind == CLIQ_LOCAL_FILE_ENGINE || file->kind == CLIQ_LOCAL_FILE_HELPER || file->kind == CLIQ_LOCAL_FILE_LOADER ? 0500U : 0400U)) return false;
    total += file->byte_count;
    if (file->kind == CLIQ_LOCAL_FILE_MANIFEST) {
      if (++manifests != 1 || strcmp(file->guest_path, "/models/model-manifest.json") || strcmp(file->digest, input->binding.model_ref)) return false;
    } else if (file->kind == CLIQ_LOCAL_FILE_TOKENIZER) {
      if (++tokenizers != 1 || strcmp(file->guest_path, "/models/tokenizer")) return false;
    } else if (file->kind == CLIQ_LOCAL_FILE_MODEL) {
      if (strncmp(file->guest_path, "/models/files/", 14)) return false;
      ++models;
    } else if (file->kind == CLIQ_LOCAL_FILE_ENGINE) {
      if (++engines != 1 || strcmp(file->guest_path, "/runtime/bin/ollama")) return false;
    } else if (file->kind == CLIQ_LOCAL_FILE_HELPER) {
      if (++helpers != 1 || strcmp(file->guest_path, "/runtime/lib/ollama/llama-server")) return false;
    } else if (file->kind == CLIQ_LOCAL_FILE_LOADER) {
      if (++loaders != 1 || strcmp(file->guest_path, "/lib64/ld-linux-x86-64.so.2")) return false;
    } else if (strncmp(file->guest_path, "/runtime/lib/", 13) && strncmp(file->guest_path, "/lib/", 5) &&
        strncmp(file->guest_path, "/lib64/", 7) && strncmp(file->guest_path, "/usr/lib/", 9)) return false;
    for (uint32_t j = 0; j < i; ++j) {
      size_t left = strlen(input->files[j].guest_path), right = strlen(file->guest_path);
      if (strcmp(input->files[j].guest_path, file->guest_path) == 0 ||
          (left < right && !memcmp(input->files[j].guest_path, file->guest_path, left) && file->guest_path[left] == '/') ||
          (right < left && !memcmp(input->files[j].guest_path, file->guest_path, right) && input->files[j].guest_path[right] == '/')) return false;
    }
  }
  for (uint32_t i = input->file_count; i < CLIQ_LOCAL_SERVICE_FILES; ++i) {
    struct cliq_local_service_file empty = {0};
    if (memcmp(&input->files[i], &empty, sizeof(empty))) return false;
  }
  return manifests == 1 && tokenizers == 1 && models > 0 && engines == 1 && helpers == 1 && loaders == 1 && input->model_mount_count == models + 2;
}
/* Same fixed SCM_RIGHTS discipline as the existing controller, with the
 * family's own exact packet and no alternate JSON/framing path. Rejected
 * rights are consumed once, including every overflow/truncated message. */
static inline bool cliq_local_service_send(int channel, const struct cliq_local_service_packet *packet,
  const int *fds, size_t count) {
  if (count > CLIQ_LOCAL_SERVICE_FDS || (count && !fds)) { errno = EINVAL; return false; }
  struct iovec vector = {.iov_base = (void *)packet, .iov_len = sizeof(*packet)};
  char ancillary[CMSG_SPACE(CLIQ_LOCAL_SERVICE_FDS * sizeof(int))]; memset(ancillary, 0, sizeof(ancillary));
  struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
  if (count) {
    message.msg_control = ancillary; message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(header), fds, count * sizeof(int));
  }
  ssize_t bytes;
  do { bytes = sendmsg(channel, &message, MSG_NOSIGNAL); } while (bytes < 0 && errno == EINTR);
  return bytes == (ssize_t)sizeof(*packet);
}
static inline bool cliq_local_service_receive(int channel, struct cliq_local_service_packet *packet,
  int *fds, size_t capacity, size_t *count, int flags, bool *close_uncertain) {
  *count = 0;
  if (capacity > CLIQ_LOCAL_SERVICE_FDS || (capacity && !fds)) { errno = EINVAL; return false; }
  struct iovec vector = {.iov_base = packet, .iov_len = sizeof(*packet)};
  char ancillary[CMSG_SPACE(CLIQ_LOCAL_SERVICE_FDS * sizeof(int))]; memset(ancillary, 0, sizeof(ancillary));
  struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1, .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
  ssize_t bytes;
  do { bytes = recvmsg(channel, &message, MSG_CMSG_CLOEXEC | flags); } while (bytes < 0 && errno == EINTR);
  if (bytes < 0) return false;
  bool valid = true;
  for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len < CMSG_LEN(0) ||
        (header->cmsg_len - CMSG_LEN(0)) % sizeof(int)) { valid = false; continue; }
    size_t rights = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int); int *received = (int *)CMSG_DATA(header);
    for (size_t i = 0; i < rights; ++i) {
      if (*count < capacity) fds[(*count)++] = received[i];
      else { valid = false; if (close(received[i]) != 0) *close_uncertain = true; }
    }
  }
  valid = valid && bytes == (ssize_t)sizeof(*packet) && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
    packet->magic == CLIQ_LOCAL_SERVICE_MAGIC && packet->version == CLIQ_LOCAL_SERVICE_VERSION &&
    packet->command >= CLIQ_LOCAL_SERVICE_HELLO && packet->command <= CLIQ_LOCAL_SERVICE_ACTIVATED;
  if (!valid) {
    for (size_t i = 0; i < *count; ++i) if (close(fds[i]) != 0) *close_uncertain = true;
    *count = 0; errno = bytes == 0 ? EPIPE : EPROTO;
  }
  return valid;
}
#endif
