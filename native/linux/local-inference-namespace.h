#ifndef CLIQ_LOCAL_INFERENCE_NAMESPACE_H
#define CLIQ_LOCAL_INFERENCE_NAMESPACE_H
/* Only the fixed signed controller image executes this private PID1 role.
 * Model traffic reaches a connected fixed loopback socket, never host routing. */
#include "local-inference-birth.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

static bool local_packet_same(const struct cliq_local_service_packet *left, const struct cliq_local_service_packet *right) {
  return left->magic == CLIQ_LOCAL_SERVICE_MAGIC && left->version == 1 &&
    !memcmp(&left->binding, &right->binding, sizeof(left->binding)) &&
    !memcmp(&left->resources, &right->resources, sizeof(left->resources)) &&
    !memcmp(left->input_digest, right->input_digest, sizeof(left->input_digest));
}
static bool local_namespace_loopback(void) {
  struct if_nameindex *names = if_nameindex(); if (!names) return false;
  bool valid = names[0].if_index != 0 && names[0].if_name && !strcmp(names[0].if_name, "lo") && names[1].if_index == 0;
  if_freenameindex(names);
  int control = valid ? socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) : -1;
  struct ifreq interface; memset(&interface, 0, sizeof(interface)); memcpy(interface.ifr_name, "lo", 3);
  valid = valid && control >= 0 && !ioctl(control, SIOCGIFFLAGS, &interface);
  interface.ifr_flags |= IFF_UP;
  valid = valid && !ioctl(control, SIOCSIFFLAGS, &interface) && !ioctl(control, SIOCGIFFLAGS, &interface) &&
    (interface.ifr_flags & (IFF_UP | IFF_LOOPBACK)) == (IFF_UP | IFF_LOOPBACK);
  if (control >= 0 && close(control)) valid = false;
  return valid;
}
static bool local_namespace_socket_filter(void) {
#if !defined(__x86_64__) || defined(__ILP32__)
  return false;
#else
  /* The common immutable-mount/namespace/ptrace filter stays unchanged for
   * every existing caller. Only this verified private network namespace may
   * use sockets, narrowed again to IPv4 loopback-domain and private Unix IPC. */
  if (!verifier_filter_network(true)) return false;
  struct sock_filter instructions[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 5),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 2, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {.len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])), .filter = instructions};
  return !prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
#endif
}
static bool local_namespace_read_file(const struct cliq_local_service_file *file) {
  int fd = open(file->guest_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK); struct stat before, after;
  bool valid = fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_uid == geteuid() && before.st_gid == getegid() &&
    (uint64_t)before.st_size == file->byte_count && (before.st_mode & 07777) == (file->mode == 0500 ? 0555U : 0444U);
  unsigned char bytes[65536], digest[32]; char text[65]; struct sha256_context hash; sha256_init(&hash); uint64_t offset = 0;
  while (valid && offset < file->byte_count) {
    size_t wanted = file->byte_count - offset < sizeof(bytes) ? (size_t)(file->byte_count - offset) : sizeof(bytes);
    ssize_t count = pread(fd, bytes, wanted, (off_t)offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) { valid = false; break; }
    sha256_update(&hash, bytes, (size_t)count); offset += (uint64_t)count;
  }
  sha256_final(&hash, digest); for (size_t i = 0; i < 32; ++i) snprintf(text + i * 2, 3, "%02x", digest[i]);
  valid = valid && !strcmp(text, file->digest) && !fstat(fd, &after) && source_stat_same(&before, &after);
  /* A named --file code copy is bound before making exactly that selected
   * code executable. Data mounts are never made executable. */
  if (valid && file->kind >= CLIQ_LOCAL_FILE_ENGINE) {
    char source[64]; int length = snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    valid = length > 0 && (size_t)length < sizeof(source) && !mount(source, file->guest_path, NULL, MS_BIND, NULL) &&
      !fstat(fd, &after) && source_stat_same(&before, &after);
  }
  if (fd >= 0 && close(fd)) valid = false;
  return valid;
}
static bool local_namespace_config(int fd, const struct cliq_local_service_packet *origin, struct cliq_local_service_input *config) {
  struct stat file; unsigned char digest[32]; char text[65];
  int seals = fcntl(fd, F_GET_SEALS);
  if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size != (off_t)sizeof(*config) || seals !=
      (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) ||
      !cliq_local_birth_read_exact(fd, config, sizeof(*config), 0) || !cliq_local_service_input_valid(config) ||
      memcmp(&config->binding, &origin->binding, sizeof(config->binding)) || memcmp(&config->resources, &origin->resources, sizeof(config->resources))) return false;
  cliq_local_birth_hash(config, sizeof(*config), digest);
  for (size_t i = 0; i < 32; ++i) snprintf(text + i * 2, 3, "%02x", digest[i]);
  return !strcmp(text, origin->input_digest);
}
static bool local_namespace_confinement(const struct cliq_local_service_input *config) {
  for (uint32_t i = 0; i < config->file_count; ++i) if (!local_namespace_read_file(&config->files[i])) return false;
  struct cliq_local_service_file bootstrap = {.kind = CLIQ_LOCAL_FILE_ENGINE, .mode = 0500, .byte_count = config->bootstrap_bytes};
  memcpy(bootstrap.digest, config->bootstrap_digest, sizeof(bootstrap.digest)); strcpy(bootstrap.guest_path, "/runtime/bin/cliq-local-inference");
  if (!local_namespace_read_file(&bootstrap) || !local_namespace_loopback() ||
      !verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0) ||
      !verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0) ||
      !verifier_mount_attributes("/scratch", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0) ||
      !verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0) ||
      !verifier_mount_attributes(bootstrap.guest_path, 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC)) return false;
  for (uint32_t i = 0; i < config->file_count; ++i) {
    const struct cliq_local_service_file *file = &config->files[i];
    if (!verifier_mount_attributes(file->guest_path, 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
        (file->kind < CLIQ_LOCAL_FILE_ENGINE ? MOUNT_ATTR_NOEXEC : 0), file->kind >= CLIQ_LOCAL_FILE_ENGINE ? MOUNT_ATTR_NOEXEC : 0) ||
        !verifier_mount_observed(file->guest_path, true, file->kind >= CLIQ_LOCAL_FILE_ENGINE, false)) return false;
  }
  return verifier_mount_observed("/", true, false, false) && verifier_mount_observed("/scratch", false, false, false) &&
    verifier_mount_observed("/proc", true, false, false) && verifier_mount_observed("/dev", false, false, true) &&
    verifier_mount_observed(bootstrap.guest_path, true, true, false) && verifier_drop_capabilities() && local_namespace_socket_filter();
}
static int local_namespace(void) {
  if (getpid() != 1 || !close_above_channel() || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 70;
  struct cliq_local_service_packet origin; int inputs[1] = {-1}; size_t count; bool uncertain = false;
  if (!cliq_local_service_receive(3, &origin, inputs, 1, &count, 0, &uncertain) || uncertain || count != 1 ||
      origin.command != CLIQ_LOCAL_SERVICE_CREATE_BLOCKED || origin.status) return 70;
  struct cliq_local_service_input *config = calloc(1, sizeof(*config));
  bool valid = config && local_namespace_config(inputs[0], &origin, config) && local_namespace_confinement(config);
  if (!source_close_fd(&inputs[0])) valid = false;
  if (!valid) { free(config); return 70; }
  int bootstrap[2]; if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, bootstrap)) { free(config); return 70; }
  pid_t child = fork();
  if (!child) {
    if (close(bootstrap[0]) || dup2(bootstrap[1], 3) < 0 || !close_above_channel()) _exit(70);
    char port[16]; snprintf(port, sizeof(port), "%u", origin.binding.port);
    char *const arguments[] = {"/runtime/bin/cliq-local-inference", "serve", "--manifest", "/models/model-manifest.json", "--model-root", "/models/files",
      "--tokenizer", "/models/tokenizer", "--host", "127.0.0.1", "--port", port, NULL};
    char *const environment[] = {"LANG=C", "LC_ALL=C", NULL}; execve(arguments[0], arguments, environment); _exit(70);
  }
  valid = child == 2 && source_close_fd(&bootstrap[1]) && cliq_local_service_send(bootstrap[0], &origin, NULL, 0) && readable(bootstrap[0], 5000);
  struct cliq_local_service_packet reply;
  valid = valid && cliq_local_service_receive(bootstrap[0], &reply, NULL, 0, &count, 0, &uncertain) && !count && !uncertain &&
    !reply.status && reply.command == CLIQ_LOCAL_SERVICE_READY && local_packet_same(&reply, &origin) && reply.observation.bootstrap_pid == 2;
  struct stat pid_namespace;
  if (valid) valid = !stat("/proc/self/ns/pid", &pid_namespace) && cliq_process_token(1, reply.observation.namespace_init_start);
  if (valid) {
    reply.observation.namespace_init_pid = 1; reply.observation.pid_namespace_inode = pid_namespace.st_ino;
    valid = cliq_local_service_send(3, &reply, NULL, 0);
  }
  bool released = false, active = false;
  while (valid) {
    int status; pid_t reaped = waitpid(-1, &status, WNOHANG);
    if (reaped == child || (reaped < 0 && errno != EINTR && errno != ECHILD)) break;
    struct pollfd control = {.fd = 3, .events = POLLIN}; int available = poll(&control, 1, 10);
    if (available < 0 && errno == EINTR) continue;
    if (available < 0 || (available && !(control.revents & POLLIN))) break;
    if (!available) continue;
    struct cliq_local_service_packet request;
    if (!cliq_local_service_receive(3, &request, NULL, 0, &count, 0, &uncertain) || uncertain || count || request.status || !local_packet_same(&request, &origin)) break;
    reply = request; int connected = -1;
    if (request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE && !released) {
      valid = cliq_local_service_send(bootstrap[0], &request, NULL, 0) && readable(bootstrap[0], 5000) &&
        cliq_local_service_receive(bootstrap[0], &reply, NULL, 0, &count, 0, &uncertain) && !uncertain && !count &&
        !reply.status && local_packet_same(&reply, &origin) && reply.command == CLIQ_LOCAL_SERVICE_ACTIVATED;
      released = valid;
    } else if (request.command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE && released && !active) active = true;
    else if ((request.command == CLIQ_LOCAL_SERVICE_CONNECT_HEALTH && released) || (request.command == CLIQ_LOCAL_SERVICE_CONNECT_MODEL && active)) {
      connected = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
      struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_port = htons((uint16_t)origin.binding.port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
      if (connected < 0) reply.status = 1;
      else if (connect(connected, (struct sockaddr *)&endpoint, sizeof(endpoint))) {
        if (errno != EINPROGRESS) reply.status = errno == ECONNREFUSED ? 2 : 1;
        else {
          struct pollfd ready = {.fd = connected, .events = POLLOUT}; int error = 0; socklen_t size = sizeof(error);
          if (poll(&ready, 1, 10) != 1 || getsockopt(connected, SOL_SOCKET, SO_ERROR, &error, &size)) reply.status = 1;
          else if (error) reply.status = error == ECONNREFUSED ? 2 : 1;
        }
      }
    } else valid = false;
    if (valid) valid = cliq_local_service_send(3, &reply, reply.status == 0 && connected >= 0 ? &connected : NULL, reply.status == 0 && connected >= 0 ? 1 : 0);
    if (!source_close_fd(&connected)) valid = false;
  }
  (void)source_close_fd(&bootstrap[0]);
  if (kill(-1, SIGKILL) && errno != ESRCH) { free(config); return 70; }
  pid_t reaped; do { reaped = waitpid(-1, NULL, 0); } while (reaped > 0 || (reaped < 0 && errno == EINTR));
  free(config); return reaped < 0 && errno == ECHILD ? 0 : 70;
}
#endif
