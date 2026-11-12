#ifndef CLIQ_LOCAL_INFERENCE_PREPARE_H
#define CLIQ_LOCAL_INFERENCE_PREPARE_H
/* Fixed signed service preparation, called only by that service's original
 * cgroup-owned preparation child. Not a generic uploader, JS seam or Run
 * runner. No model/engine/parser is executed while bytes are being sealed. */
#include <poll.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <time.h>
#include "worker-common.h"
#include "worker-sha256.h"
#include "local-inference-protocol.h"

#define CLIQ_LOCAL_PREPARE_MAGIC UINT32_C(0x434c5031)
#define CLIQ_LOCAL_PREPARE_MAX_FILES 32U
#define CLIQ_LOCAL_PREPARE_CHUNK 65536U
enum cliq_local_prepare_kind { CLIQ_LOCAL_PREPARE_FILE = 1, CLIQ_LOCAL_PREPARE_ACK = 2,
  CLIQ_LOCAL_PREPARE_DONE = 3, CLIQ_LOCAL_PREPARE_CANCEL = 4 };
struct cliq_local_prepare_message {
  uint32_t magic, version, kind, index;
  uint64_t byte_count;
  char digest[65];
};
struct cliq_local_prepare_file {
  int source;
  uint32_t kind;
  uint64_t byte_count;
  char digest[65];
  mode_t mode;
  struct stat original;
};
struct cliq_local_prepare_child {
  int channel, cgroup;
  struct stat cgroup_identity;
  uint64_t monotonic_deadline;
  uint64_t max_file_bytes, memory_bytes;
};
static uint64_t cliq_local_prepare_clock(clockid_t clock) {
  struct timespec time;
  if (clock_gettime(clock, &time) || time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1000000000 ||
      (uint64_t)time.tv_sec > (UINT64_C(9007199254740991) - 999) / 1000) return 0;
  return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}
static bool cliq_local_prepare_same(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino && left->st_uid == right->st_uid &&
    left->st_gid == right->st_gid && left->st_mode == right->st_mode && left->st_size == right->st_size && left->st_nlink == right->st_nlink &&
    left->st_mtim.tv_sec == right->st_mtim.tv_sec && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
    left->st_ctim.tv_sec == right->st_ctim.tv_sec && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}
static bool cliq_local_prepare_member(struct cliq_local_prepare_child *child) {
  struct stat identity; struct statfs filesystem;
  if (fstat(child->cgroup, &identity) || fstatfs(child->cgroup, &filesystem) || filesystem.f_type != 0x63677270 ||
      !S_ISDIR(identity.st_mode) || identity.st_dev != child->cgroup_identity.st_dev || identity.st_ino != child->cgroup_identity.st_ino ||
      identity.st_uid != geteuid() || (identity.st_mode & 0022)) return false;
  int file = openat(child->cgroup, "cgroup.procs", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (file < 0) return false;
  char bytes[64]; ssize_t count;
  do { count = pread(file, bytes, sizeof(bytes) - 1, 0); } while (count < 0 && errno == EINTR);
  int owned = file; file = -1;
  if (close(owned) || count <= 0 || (size_t)count >= sizeof(bytes) - 1) return false;
  bytes[count] = '\0';
  char expected[64]; int length = snprintf(expected, sizeof(expected), "%ld\n", (long)getpid());
  return length > 0 && (size_t)length < sizeof(expected) && strcmp(bytes, expected) == 0;
}
static bool cliq_local_prepare_live(struct cliq_local_prepare_child *child) {
  uint64_t now = cliq_local_prepare_clock(CLOCK_MONOTONIC);
  if (!now || now >= child->monotonic_deadline || !cliq_local_prepare_member(child)) return false;
  struct pollfd input = {.fd = child->channel, .events = POLLIN};
  int ready;
  do { ready = poll(&input, 1, 0); } while (ready < 0 && errno == EINTR);
  /* During a copy the only legal parent input is cancellation. Any data or
   * loss of the original channel ends preparation without publishing a file. */
  return ready == 0;
}
static bool cliq_local_prepare_read(struct cliq_local_prepare_child *child, int descriptor,
  unsigned char *bytes, size_t count, uint64_t offset) {
  size_t consumed = 0;
  while (consumed < count) {
    if (!cliq_local_prepare_live(child)) return false;
    ssize_t size = pread(descriptor, bytes + consumed, count - consumed, (off_t)(offset + consumed));
    if (size < 0 && errno == EINTR) continue;
    if (size <= 0) return false;
    consumed += (size_t)size;
  }
  return true;
}
static bool cliq_local_prepare_write(struct cliq_local_prepare_child *child, int descriptor,
  const unsigned char *bytes, size_t count, uint64_t offset) {
  size_t consumed = 0;
  while (consumed < count) {
    if (!cliq_local_prepare_live(child)) return false;
    ssize_t size = pwrite(descriptor, bytes + consumed, count - consumed, (off_t)(offset + consumed));
    if (size < 0 && errno == EINTR) continue;
    if (size <= 0) return false;
    consumed += (size_t)size;
  }
  return true;
}
static bool cliq_local_prepare_hash(struct cliq_local_prepare_child *child, int descriptor,
  const struct cliq_local_prepare_file *input, int destination, bool copying) {
  unsigned char bytes[CLIQ_LOCAL_PREPARE_CHUNK], raw[32]; char digest[65]; struct sha256_context hash;
  sha256_init(&hash); uint64_t offset = 0;
  while (offset < input->byte_count) {
    size_t count = input->byte_count - offset < sizeof(bytes) ? (size_t)(input->byte_count - offset) : sizeof(bytes);
    struct stat current;
    if (fstat(input->source, &current) || !cliq_local_prepare_same(&current, &input->original) ||
        !cliq_local_prepare_read(child, descriptor, bytes, count, offset) ||
        (copying && !cliq_local_prepare_write(child, destination, bytes, count, offset))) return false;
    sha256_update(&hash, bytes, count); offset += count;
  }
  sha256_final(&hash, raw);
  for (size_t i = 0; i < sizeof(raw); ++i) snprintf(digest + i * 2, 3, "%02x", raw[i]);
  struct stat current;
  return strcmp(digest, input->digest) == 0 && fstat(input->source, &current) == 0 &&
    cliq_local_prepare_same(&current, &input->original) && cliq_local_prepare_live(child);
}
static bool cliq_local_prepare_seal(struct cliq_local_prepare_child *child,
  const struct cliq_local_prepare_file *input, int *output) {
  *output = -1;
  /* The original fixed per-file ceiling is not raised for model weights.
   * Signed inputs outside it are explicitly unsupported by this recipe. */
  if (!input->byte_count || input->byte_count > child->max_file_bytes || input->byte_count > child->memory_bytes ||
      input->byte_count > INT64_MAX || (uint64_t)(off_t)input->byte_count != input->byte_count ||
      !S_ISREG(input->original.st_mode) || input->original.st_nlink != 1 ||
      (input->kind < CLIQ_LOCAL_FILE_MANIFEST || input->kind > CLIQ_LOCAL_FILE_LOADER) ||
      (input->kind < CLIQ_LOCAL_FILE_ENGINE ? input->original.st_uid != geteuid() || input->original.st_gid != getegid() :
        !((input->original.st_uid == geteuid() && input->original.st_gid == getegid()) ||
          (input->original.st_uid == 0 && input->original.st_gid == 0))) ||
      (uint64_t)input->original.st_size != input->byte_count ||
      input->mode != (input->kind == CLIQ_LOCAL_FILE_ENGINE || input->kind == CLIQ_LOCAL_FILE_HELPER || input->kind == CLIQ_LOCAL_FILE_LOADER ? 0500 : 0400) ||
      ((input->original.st_mode & 07777) != 0400 && (input->original.st_mode & 07777) != 0500) ||
      !cliq_hex_digest(input->digest) || !cliq_local_prepare_live(child)) return false;
  /* Allocation and every first-touch occur only after actual original-cgroup
   * membership is checked. No Supervisor buffer or outside-domain memfd. */
  int sealed = memfd_create("cliq-local-model-input-v1", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (sealed < 0) return false;
  bool valid = ftruncate(sealed, (off_t)input->byte_count) == 0 &&
    cliq_local_prepare_hash(child, input->source, input, sealed, true) &&
    cliq_local_prepare_hash(child, input->source, input, -1, false) && fchmod(sealed, input->mode) == 0 &&
    fcntl(sealed, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0 &&
    fcntl(sealed, F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
    cliq_local_prepare_hash(child, sealed, input, -1, false);
  if (!valid) { int consumed = sealed; sealed = -1; (void)close(consumed); return false; }
  *output = sealed; return true;
}
#endif
