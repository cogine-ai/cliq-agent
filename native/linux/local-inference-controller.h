#ifndef CLIQ_LOCAL_INFERENCE_CONTROLLER_H
#define CLIQ_LOCAL_INFERENCE_CONTROLLER_H
/* One fixed local-service owner in the original signed controller image.
 * Independent purpose/packet/birth; no Worker, MCP, Run or Admin authority. */
#include "local-inference-prepare.h"
#include "local-inference-namespace.h"
#include <linux/sched.h>
#include <sys/file.h>
struct local_service_scope {
  int anchor, cgroup, birth, config_fd, bootstrap, controller_image, bwrap;
  int sources[CLIQ_LOCAL_SERVICE_FILES], sealed[CLIQ_LOCAL_SERVICE_FILES];
  int prepare_channel, channel, output[2], construction[4];
  struct stat anchor_identity, cgroup_identity;
  struct cliq_local_service_input config;
  struct cliq_local_birth_frame origin;
  struct cliq_local_service_packet identity;
  char cgroup_name[96];
  pid_t preparation, monitor; bool attempted, created, prepared, blocked, released, active, failed, dead, retired;
  bool prepare_done, preparation_joined, monitor_joined, uncertain, cleanup_only;
  uint32_t prepared_count;
};
static struct local_service_scope local_service;
static bool local_close(struct local_service_scope *scope, int *fd) {
  int owned = *fd; *fd = -1;
  if (owned < 0 || !close(owned)) return true;
  scope->uncertain = true; return false;
}
static void local_service_initialize(void) {
  memset(&local_service, 0, sizeof(local_service));
  int *fds[] = {&local_service.anchor, &local_service.cgroup, &local_service.birth, &local_service.config_fd,
    &local_service.bootstrap, &local_service.controller_image, &local_service.bwrap, &local_service.prepare_channel, &local_service.channel,
    &local_service.output[0], &local_service.output[1]};
  for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) *fds[i] = -1;
  for (size_t i = 0; i < CLIQ_LOCAL_SERVICE_FILES; ++i) local_service.sources[i] = local_service.sealed[i] = -1;
  for (size_t i = 0; i < 4; ++i) local_service.construction[i] = -1;
}
static bool local_identity_is(const struct cliq_local_birth_identity *identity, const struct stat *actual) {
  return identity->device == (uint64_t)actual->st_dev && identity->inode == (uint64_t)actual->st_ino &&
    identity->uid == (uint64_t)actual->st_uid && identity->gid == (uint64_t)actual->st_gid && identity->mode == (uint64_t)actual->st_mode;
}
static bool local_service_current(struct local_service_scope *scope) {
  struct stat anchor, cgroup, named;
  if (!scope->attempted || scope->uncertain || scope->retired || scope->anchor < 0 || scope->birth < 0 ||
      !native_cgroup(scope->anchor) || fstat(scope->anchor, &anchor) || anchor.st_dev != scope->anchor_identity.st_dev ||
      anchor.st_ino != scope->anchor_identity.st_ino || anchor.st_uid != scope->anchor_identity.st_uid ||
      anchor.st_gid != scope->anchor_identity.st_gid || anchor.st_mode != scope->anchor_identity.st_mode) return false;
  if (!scope->created) return true;
  return scope->cgroup >= 0 && native_cgroup(scope->cgroup) && !fstat(scope->cgroup, &cgroup) &&
    cgroup.st_dev == scope->cgroup_identity.st_dev && cgroup.st_ino == scope->cgroup_identity.st_ino &&
    cgroup.st_mode == scope->cgroup_identity.st_mode && cgroup.st_uid == scope->cgroup_identity.st_uid &&
    !fstatat(scope->anchor, scope->cgroup_name, &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&cgroup, &named);
}
static bool local_service_step(struct local_service_scope *scope, uint32_t step) {
  if (!local_service_current(scope)) return false;
  struct cliq_local_birth_frame next = scope->origin; next.step = step; next.packet = scope->identity;
  return cliq_local_birth_append(scope->birth, &next);
}
static bool local_service_stamp(struct cliq_local_service_packet *packet) {
  packet->observation.observed_at_ms = cliq_local_prepare_clock(CLOCK_REALTIME);
  return packet->observation.observed_at_ms != 0;
}
static bool local_activation_live(const struct local_service_scope *scope) {
  uint64_t now = cliq_local_prepare_clock(CLOCK_REALTIME);
  return now >= scope->identity.binding.created_at_ms && now < scope->identity.binding.activation_deadline_ms;
}
static void local_resources_packet(struct cliq_worker_packet *packet, const struct cliq_local_service_resources *resources) {
  memset(packet, 0, sizeof(*packet)); packet->max_processes = resources->max_processes; packet->memory_bytes = resources->memory_bytes;
  packet->cpu_quota = resources->cpu_quota; packet->max_open_files = resources->max_open_files; packet->max_file_bytes = resources->max_file_bytes;
  packet->max_generation_bytes = resources->max_generation_bytes; packet->max_output_bytes = resources->max_output_bytes;
}
static bool local_service_reserve(struct local_service_scope *scope, const struct cliq_local_service_packet *request, int *passed, size_t count) {
  if (scope->attempted || count < 12 || count > CLIQ_LOCAL_SERVICE_FDS || request->command != CLIQ_LOCAL_SERVICE_RESERVE || request->status ||
      !cliq_local_service_binding_valid(&request->binding) || !cliq_local_service_resources_valid(&request->resources)) return false;
  struct cliq_local_birth_history history; struct stat anchor, self;
  if (!native_cgroup(passed[0]) || fstat(passed[0], &anchor) || !local_namespace_config(passed[2], request, &scope->config) ||
      count != 6 + scope->config.file_count || !cliq_local_birth_read(passed[1], &history) || history.count != 1 ||
      !local_packet_same(request, &history.first.packet) || history.first.controller_pid != getpid() ||
      !local_identity_is(&history.first.controller_anchor, &anchor) || stat("/proc/self/exe", &self) ||
      history.first.controller_device != (uint64_t)self.st_dev || history.first.controller_inode != (uint64_t)self.st_ino ||
      history.first.controller_uid != (uint64_t)self.st_uid || flock(passed[1], LOCK_EX | LOCK_NB)) return false;
  char token[CLIQ_WORKER_TOKEN_BYTES];
  if (!cliq_process_token(getpid(), token) || strcmp(token, history.first.controller_start) ||
      !builtin_sealed_data(passed[3], scope->config.bootstrap_bytes, scope->config.bootstrap_digest) ||
      !builtin_sealed_data(passed[4], scope->config.bubblewrap_bytes, scope->config.bubblewrap_digest) ||
      !builtin_sealed_data(passed[5], scope->config.controller_bytes, scope->config.controller_digest)) return false;
  for (uint32_t i = 0; i < scope->config.file_count; ++i) {
    struct stat file; int flags = fcntl(passed[6 + i], F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat(passed[6 + i], &file) || !S_ISREG(file.st_mode) ||
        file.st_uid != geteuid() || file.st_gid != getegid() || (file.st_mode & 07777) != 0400 || file.st_nlink != 1 ||
        file.st_size < 1 || (uint64_t)file.st_size != scope->config.files[i].byte_count) return false;
  }
  scope->attempted = true; scope->origin = history.first; scope->identity = *request; scope->anchor_identity = anchor;
  int *slots[] = {&scope->anchor, &scope->birth, &scope->config_fd, &scope->bootstrap, &scope->bwrap, &scope->controller_image};
  for (size_t i = 0; i < 6; ++i) { *slots[i] = passed[i]; passed[i] = -1; }
  for (uint32_t i = 0; i < scope->config.file_count; ++i) { scope->sources[i] = passed[6 + i]; passed[6 + i] = -1; }
  int length = snprintf(scope->cgroup_name, sizeof(scope->cgroup_name), "cliq-local-%s", request->binding.native_nonce);
  if (length <= 0 || (size_t)length >= sizeof(scope->cgroup_name) || !local_service_step(scope, CLIQ_LOCAL_BIRTH_CREATE_INTENT) ||
      mkdirat(scope->anchor, scope->cgroup_name, 0700)) return false;
  scope->cgroup = openat(scope->anchor, scope->cgroup_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  scope->created = scope->cgroup >= 0;
  struct cliq_worker_packet resource; local_resources_packet(&resource, &request->resources);
  if (!scope->created || !native_cgroup(scope->cgroup) || fstat(scope->cgroup, &scope->cgroup_identity) || !cgroup_empty(scope->cgroup) ||
      !resources(scope->cgroup, &resource)) return false;
  char text[128]; snprintf(text, sizeof(text), "%llu\n", (unsigned long long)request->resources.max_processes);
  if (!source_control_equals(scope->cgroup, "pids.max", text)) return false;
  snprintf(text, sizeof(text), "%llu\n", (unsigned long long)request->resources.memory_bytes);
  if (!source_control_equals(scope->cgroup, "memory.max", text) || !source_control_equals(scope->cgroup, "memory.swap.max", "0\n")) return false;
  snprintf(text, sizeof(text), "%llu 1000000\n", (unsigned long long)request->resources.cpu_quota);
  if (!source_control_equals(scope->cgroup, "cpu.max", text)) return false;
  scope->identity.observation.cgroup_device = scope->cgroup_identity.st_dev; scope->identity.observation.cgroup_inode = scope->cgroup_identity.st_ino;
  return local_service_step(scope, CLIQ_LOCAL_BIRTH_CGROUP_CREATED);
}
static void local_prepare_child(struct local_service_scope *scope, int channel, int barrier) {
  int keep[CLIQ_LOCAL_SERVICE_FDS]; size_t count = 0; keep[count++] = channel; keep[count++] = barrier; keep[count++] = scope->cgroup;
  for (uint32_t i = 0; i < scope->config.file_count; ++i) keep[count++] = scope->sources[i];
  if (!retain_descriptors(keep, count)) _exit(70);
  char go; if (read(barrier, &go, 1) != 1 || go != '1' || close(barrier)) _exit(70);
  struct cliq_worker_packet limits; local_resources_packet(&limits, &scope->config.resources); if (!configure_limits(&limits)) _exit(70);
  uint64_t now = cliq_local_prepare_clock(CLOCK_REALTIME), monotonic = cliq_local_prepare_clock(CLOCK_MONOTONIC);
  if (!now || !monotonic || now >= scope->identity.binding.activation_deadline_ms) _exit(70);
  struct cliq_local_prepare_child child = {.channel = channel, .cgroup = scope->cgroup, .cgroup_identity = scope->cgroup_identity,
    .monotonic_deadline = monotonic + (scope->identity.binding.activation_deadline_ms - now),
    .max_file_bytes = scope->config.resources.max_file_bytes, .memory_bytes = scope->config.resources.memory_bytes};
  for (uint32_t i = 0; i < scope->config.file_count; ++i) {
    const struct cliq_local_service_file *file = &scope->config.files[i];
    struct cliq_local_prepare_file input = {.source = scope->sources[i], .kind = file->kind, .byte_count = file->byte_count, .mode = file->mode};
    memcpy(input.digest, file->digest, sizeof(input.digest)); int sealed = -1;
    if (fstat(input.source, &input.original) || !cliq_local_prepare_seal(&child, &input, &sealed)) _exit(70);
    struct cliq_local_service_packet output = scope->identity; output.command = CLIQ_LOCAL_SERVICE_PREPARE; output.observation.prepared_count = i + 1;
    if (!cliq_local_service_send(channel, &output, &sealed, 1) || close(sealed)) _exit(70);
    for (;;) {
      uint64_t clock = cliq_local_prepare_clock(CLOCK_MONOTONIC); if (!clock || clock >= child.monotonic_deadline) _exit(70);
      struct pollfd ready = {.fd = channel, .events = POLLIN}; int available = poll(&ready, 1, 10);
      if (available < 0 && errno == EINTR) continue;
      if (available < 0 || (available && !(ready.revents & POLLIN))) _exit(70);
      if (!available) continue;
      struct cliq_local_service_packet ack; size_t extra; bool uncertain = false;
      if (!cliq_local_service_receive(channel, &ack, NULL, 0, &extra, 0, &uncertain) || extra || uncertain ||
          ack.status || !local_packet_same(&ack, &scope->identity) || ack.command != CLIQ_LOCAL_SERVICE_ACK || ack.observation.prepared_count != i + 1) _exit(70);
      break;
    }
  }
  for (uint32_t i = 0; i < scope->config.file_count; ++i) if (close(scope->sources[i])) _exit(70);
  if (close(scope->cgroup)) _exit(70);
  struct cliq_local_service_packet done = scope->identity; done.command = CLIQ_LOCAL_SERVICE_POLL_PREPARED; done.observation.prepared_count = scope->config.file_count;
  if (!cliq_local_service_send(channel, &done, NULL, 0) || close(channel)) _exit(70);
  _exit(0);
}
static bool local_service_prepare(struct local_service_scope *scope) {
  if (!local_service_current(scope) || !local_activation_live(scope) || !scope->created || scope->preparation > 0 || !cgroup_empty(scope->cgroup) ||
      !local_service_step(scope, CLIQ_LOCAL_BIRTH_PREPARE_INTENT) ||
      socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, scope->construction) || pipe2(scope->construction + 2, O_CLOEXEC)) return false;
  struct clone_args args; memset(&args, 0, sizeof(args)); args.flags = CLONE_INTO_CGROUP; args.exit_signal = SIGCHLD; args.cgroup = (uint64_t)scope->cgroup;
  scope->preparation = (pid_t)syscall(SYS_clone3, &args, sizeof(args));
  if (scope->preparation < 0) return false;
  if (!scope->preparation) {
    if (close(scope->construction[0]) || close(scope->construction[3])) _exit(70);
    local_prepare_child(scope, scope->construction[1], scope->construction[2]); _exit(70);
  }
  scope->identity.observation.preparation_pid = scope->preparation;
  if (!cliq_process_token(scope->preparation, scope->identity.observation.preparation_start) ||
      !local_close(scope, &scope->construction[1]) || !local_close(scope, &scope->construction[2]) ||
      !local_service_step(scope, CLIQ_LOCAL_BIRTH_PREPARE_FORKED) || write(scope->construction[3], "1", 1) != 1 ||
      !local_close(scope, &scope->construction[3])) return false;
  scope->prepare_channel = scope->construction[0]; scope->construction[0] = -1; return true;
}
static bool local_service_pump_prepare(struct local_service_scope *scope) {
  if (!scope->preparation || scope->prepared || scope->dead) return true;
  if (!local_service_current(scope)) return false;
  if (!scope->prepare_done && readable(scope->prepare_channel, 0)) {
    struct cliq_local_service_packet packet; int descriptor[1] = {-1}; size_t count = 0; bool uncertain = false;
    bool valid = cliq_local_service_receive(scope->prepare_channel, &packet, descriptor, 1, &count, MSG_DONTWAIT, &uncertain) &&
      !uncertain && !packet.status && local_packet_same(&packet, &scope->identity);
    if (uncertain) scope->uncertain = true;
    if (valid && packet.command == CLIQ_LOCAL_SERVICE_PREPARE && count == 1 && scope->prepared_count < scope->config.file_count &&
        packet.observation.prepared_count == scope->prepared_count + 1) {
      const struct cliq_local_service_file *file = &scope->config.files[scope->prepared_count]; struct stat sealed;
      valid = !fstat(descriptor[0], &sealed) && S_ISREG(sealed.st_mode) && (uint64_t)sealed.st_size == file->byte_count &&
        (sealed.st_mode & 07777) == file->mode && fcntl(descriptor[0], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
      if (valid) {
        scope->sealed[scope->prepared_count++] = descriptor[0]; descriptor[0] = -1;
        scope->identity.observation.prepared_count = scope->prepared_count;
        packet = scope->identity; packet.command = CLIQ_LOCAL_SERVICE_ACK;
        valid = local_service_step(scope, CLIQ_LOCAL_BIRTH_INPUT_HANDED) && cliq_local_service_send(scope->prepare_channel, &packet, NULL, 0);
      }
    } else if (valid && packet.command == CLIQ_LOCAL_SERVICE_POLL_PREPARED && !count && scope->prepared_count == scope->config.file_count &&
        packet.observation.prepared_count == scope->prepared_count) scope->prepare_done = true;
    else valid = false;
    if (!local_close(scope, &descriptor[0])) valid = false;
    if (!valid) return false;
  }
  int status; pid_t joined = waitpid(scope->preparation, &status, WNOHANG);
  if (joined < 0 && errno == EINTR) return true;
  if (joined < 0) return false;
  if (joined == scope->preparation) {
    scope->preparation_joined = true;
    if (!scope->prepare_done && WIFEXITED(status) && WEXITSTATUS(status) == 0 && scope->prepared_count == scope->config.file_count) {
      /* The child can send DONE and exit between our last input ACK and
       * waitpid. Consume that exact already-queued final packet; successful
       * exit alone never substitutes for the real authenticated handoff. */
      struct cliq_local_service_packet done; size_t extra = 0; bool uncertain = false;
      scope->prepare_done = cliq_local_service_receive(scope->prepare_channel, &done, NULL, 0, &extra, MSG_DONTWAIT, &uncertain) &&
        !extra && !uncertain && !done.status && local_packet_same(&done, &scope->identity) &&
        done.command == CLIQ_LOCAL_SERVICE_POLL_PREPARED && done.observation.prepared_count == scope->config.file_count;
      if (uncertain) scope->uncertain = true;
    }
    if (!scope->prepare_done || !WIFEXITED(status) || WEXITSTATUS(status) || !cgroup_empty(scope->cgroup) ||
        !original_process_absent(scope->preparation, scope->identity.observation.preparation_start) || !local_close(scope, &scope->prepare_channel)) return false;
    for (uint32_t i = 0; i < scope->config.file_count; ++i) if (!local_close(scope, &scope->sources[i])) return false;
    if (!local_service_step(scope, CLIQ_LOCAL_BIRTH_PREPARE_JOINED)) return false;
    scope->prepared = true;
  }
  return true;
}
static void local_service_bubblewrap(struct local_service_scope *scope) {
  int keep[CLIQ_LOCAL_SERVICE_FDS]; size_t count = 0;
  keep[count++] = scope->controller_image; keep[count++] = scope->bootstrap; keep[count++] = scope->bwrap;
  for (uint32_t i = 0; i < scope->config.file_count; ++i) keep[count++] = scope->sealed[i];
  if (!retain_descriptors(keep, count)) _exit(70);
  char descriptors[CLIQ_LOCAL_SERVICE_FILES + 2][24];
  int init = independent_image_fd(scope->controller_image, 4), bootstrap = independent_image_fd(scope->bootstrap, 4);
  if (init < 0 || bootstrap < 0) _exit(70);
  snprintf(descriptors[0], sizeof(descriptors[0]), "%d", init); snprintf(descriptors[1], sizeof(descriptors[1]), "%d", bootstrap);
  for (uint32_t i = 0; i < scope->config.file_count; ++i) {
    int fd = independent_image_fd(scope->sealed[i], 4); if (fd < 0) _exit(70);
    snprintf(descriptors[i + 2], sizeof(descriptors[i + 2]), "%d", fd);
  }
  const size_t directory_capacity = CLIQ_LOCAL_SERVICE_FILES * 68 + 16;
  char (*directories)[CLIQ_LOCAL_SERVICE_PATH] = calloc(directory_capacity, CLIQ_LOCAL_SERVICE_PATH); size_t directory_count = 0;
  if (!directories) _exit(70);
  /* The pinned engine enumerates both indexes before serving model metadata.
   * Create the fixed directories in the fresh root before making it readonly. */
  const char *fixed[] = {"/runtime", "/runtime/bin", "/runtime/lib", "/runtime/lib/ollama", "/models", "/models/files",
    "/models/files/manifests", "/models/files/manifests-v2",
    "/lib", "/lib64", "/usr", "/usr/lib", "/home", "/home/cliq", "/tmp", "/work"};
  for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i) strcpy(directories[directory_count++], fixed[i]);
  for (uint32_t i = 0; i < scope->config.file_count; ++i) {
    char path[CLIQ_LOCAL_SERVICE_PATH]; strcpy(path, scope->config.files[i].guest_path);
    for (char *end = path + 1; (end = strchr(end, '/')) != NULL; ++end) {
      *end = '\0'; bool exists = false;
      for (size_t j = 0; j < directory_count; ++j) if (!strcmp(directories[j], path)) exists = true;
      if (!exists) { if (directory_count >= directory_capacity) _exit(70); strcpy(directories[directory_count++], path); }
      *end = '/';
    }
  }
  char *arguments[CLIQ_LOCAL_SERVICE_FILES * 150 + 128]; size_t at = 0;
#define LOCAL_ARG(value) do { if (at >= sizeof(arguments) / sizeof(arguments[0]) - 1) _exit(70); arguments[at++] = (char *)(value); } while (0)
  LOCAL_ARG("bwrap"); LOCAL_ARG("--unshare-user"); LOCAL_ARG("--uid"); LOCAL_ARG("0"); LOCAL_ARG("--gid"); LOCAL_ARG("0");
  LOCAL_ARG("--unshare-pid"); LOCAL_ARG("--as-pid-1"); LOCAL_ARG("--unshare-net"); LOCAL_ARG("--unshare-ipc"); LOCAL_ARG("--unshare-uts");
  LOCAL_ARG("--unshare-cgroup"); LOCAL_ARG("--new-session"); LOCAL_ARG("--die-with-parent"); LOCAL_ARG("--cap-drop"); LOCAL_ARG("ALL");
  LOCAL_ARG("--cap-add"); LOCAL_ARG("CAP_SYS_ADMIN"); LOCAL_ARG("--cap-add"); LOCAL_ARG("CAP_SETPCAP"); LOCAL_ARG("--cap-add"); LOCAL_ARG("CAP_NET_ADMIN");
  LOCAL_ARG("--clearenv"); LOCAL_ARG("--tmpfs"); LOCAL_ARG("/");
  for (size_t i = 0; i < directory_count; ++i) { LOCAL_ARG("--dir"); LOCAL_ARG(directories[i]); }
  LOCAL_ARG("--perms"); LOCAL_ARG("0555"); LOCAL_ARG("--ro-bind-data"); LOCAL_ARG(descriptors[0]); LOCAL_ARG("/runtime/cliq-linux-local-init");
  LOCAL_ARG("--perms"); LOCAL_ARG("0555"); LOCAL_ARG("--file"); LOCAL_ARG(descriptors[1]); LOCAL_ARG("/runtime/bin/cliq-local-inference");
  for (uint32_t i = 0; i < scope->config.file_count; ++i) {
    const struct cliq_local_service_file *file = &scope->config.files[i]; LOCAL_ARG("--perms"); LOCAL_ARG(file->mode == 0500 ? "0555" : "0444");
    LOCAL_ARG(file->kind >= CLIQ_LOCAL_FILE_ENGINE ? "--file" : "--ro-bind-data"); LOCAL_ARG(descriptors[i + 2]); LOCAL_ARG(file->guest_path);
  }
  LOCAL_ARG("--proc"); LOCAL_ARG("/proc"); LOCAL_ARG("--dev"); LOCAL_ARG("/dev"); LOCAL_ARG("--size"); LOCAL_ARG("4294967296");
  LOCAL_ARG("--tmpfs"); LOCAL_ARG("/scratch"); LOCAL_ARG("--dir"); LOCAL_ARG("/scratch/home"); LOCAL_ARG("--dir"); LOCAL_ARG("/scratch/tmp");
  LOCAL_ARG("--chdir"); LOCAL_ARG("/"); LOCAL_ARG("--"); LOCAL_ARG("/runtime/cliq-linux-local-init"); LOCAL_ARG("--local-inference-namespace"); arguments[at] = NULL;
#undef LOCAL_ARG
  char *const environment[] = {"LANG=C", "LC_ALL=C", NULL}; fexecve(scope->bwrap, arguments, environment); _exit(70);
}
static bool local_service_create_blocked(struct local_service_scope *scope) {
  if (!local_service_current(scope) || !local_activation_live(scope) || !scope->prepared || scope->blocked || scope->monitor > 0 || !cgroup_empty(scope->cgroup) ||
      !local_service_step(scope, CLIQ_LOCAL_BIRTH_NAMESPACE_INTENT) || socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, scope->construction) ||
      pipe2(scope->construction + 2, O_CLOEXEC)) return false;
  for (size_t i = 0; i < 2; ++i) {
    scope->output[i] = memfd_create("cliq-local-service-output-v1", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (scope->output[i] < 0 || ftruncate(scope->output[i], (off_t)(scope->config.resources.max_output_bytes / 2)) ||
        fcntl(scope->output[i], F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL)) return false;
  }
  struct clone_args args; memset(&args, 0, sizeof(args)); args.flags = CLONE_INTO_CGROUP; args.exit_signal = SIGCHLD; args.cgroup = (uint64_t)scope->cgroup;
  scope->monitor = (pid_t)syscall(SYS_clone3, &args, sizeof(args));
  if (scope->monitor < 0) return false;
  if (!scope->monitor) {
    if (close(scope->construction[0]) || close(scope->construction[3])) _exit(70);
    char go; if (read(scope->construction[2], &go, 1) != 1 || go != '1' || close(scope->construction[2]) ||
        dup2(scope->construction[1], 3) < 0 || dup2(scope->output[0], 1) < 0 || dup2(scope->output[1], 2) < 0) _exit(70);
    struct cliq_worker_packet resource; local_resources_packet(&resource, &scope->config.resources); if (!configure_limits(&resource)) _exit(70);
    local_service_bubblewrap(scope); _exit(70);
  }
  scope->identity.observation.monitor_pid = scope->monitor;
  if (!cliq_process_token(scope->monitor, scope->identity.observation.monitor_start) || !local_close(scope, &scope->construction[1]) ||
      !local_close(scope, &scope->construction[2]) || !local_service_step(scope, CLIQ_LOCAL_BIRTH_NAMESPACE_FORKED) ||
      write(scope->construction[3], "1", 1) != 1 || !local_close(scope, &scope->construction[3])) return false;
  scope->channel = scope->construction[0]; scope->construction[0] = -1;
  struct cliq_local_service_packet request = scope->identity; request.command = CLIQ_LOCAL_SERVICE_CREATE_BLOCKED;
  struct cliq_local_service_packet ready; size_t count; bool uncertain = false;
  int64_t started = milliseconds();
  if (started < 0 || !cliq_local_service_send(scope->channel, &request, &scope->config_fd, 1) || !readable(scope->channel, 5000)) return false;
  bool received = cliq_local_service_receive(scope->channel, &ready, NULL, 0, &count, 0, &uncertain);
  if (uncertain) scope->uncertain = true;
  if (!received || count || uncertain || ready.status || !local_packet_same(&ready, &scope->identity) || ready.command != CLIQ_LOCAL_SERVICE_READY) return false;
  struct scope process; memset(&process, 0, sizeof(process)); process.process_group = scope->cgroup;
  struct cliq_worker_packet physical; memset(&physical, 0, sizeof(physical)); physical.pid_namespace_inode = ready.observation.pid_namespace_inode;
  memcpy(physical.init_start_token, ready.observation.namespace_init_start, sizeof(physical.init_start_token));
  memcpy(physical.start_token, ready.observation.bootstrap_start, sizeof(physical.start_token));
  if (!inspect_processes(&process, &physical) || milliseconds() < started || milliseconds() - started > 5000) return false;
  scope->identity.observation.namespace_init_pid = process.init; scope->identity.observation.bootstrap_pid = process.worker;
  scope->identity.observation.pid_namespace_inode = ready.observation.pid_namespace_inode;
  memcpy(scope->identity.observation.namespace_init_start, physical.init_start_token, sizeof(physical.init_start_token));
  memcpy(scope->identity.observation.bootstrap_start, physical.start_token, sizeof(physical.start_token));
  scope->identity.observation.populated = 1;
  if (!local_service_step(scope, CLIQ_LOCAL_BIRTH_READY)) return false;
  scope->blocked = true; return true;
}
static bool local_service_stop(struct local_service_scope *scope) {
  if (scope->retired) return !scope->uncertain;
  if (!local_service_current(scope)) return false;
  int64_t started = milliseconds(); if (started < 0) return false;
  struct tracked_set tracked = {0};
  if (!scope->created) {
    struct stat unexpected;
    if (fstatat(scope->anchor, scope->cgroup_name, &unexpected, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) return false;
  }
  if (scope->created && !collect_processes(scope->cgroup, &tracked, 0)) return false;
  struct cliq_local_service_observation *observed = &scope->identity.observation;
  if (scope->preparation > 0 && !track_process(&tracked, scope->preparation, observed->preparation_start)) return false;
  if (scope->monitor > 0 && !track_process(&tracked, scope->monitor, observed->monitor_start)) return false;
  if (scope->blocked && (!track_process(&tracked, (pid_t)observed->namespace_init_pid, observed->namespace_init_start) ||
      !track_process(&tracked, (pid_t)observed->bootstrap_pid, observed->bootstrap_start))) return false;
  if (scope->created && !write_control(scope->cgroup, "cgroup.kill", "1")) return false;
  for (size_t i = 0; i < 4; ++i) if (!local_close(scope, &scope->construction[i])) return false;
  if (!local_close(scope, &scope->prepare_channel) || !local_close(scope, &scope->channel)) return false;
  for (;;) {
    int status; pid_t reaped;
    do { reaped = waitpid(-1, &status, WNOHANG); if (reaped == scope->preparation) scope->preparation_joined = true; if (reaped == scope->monitor) scope->monitor_joined = true; }
    while (reaped > 0 || (reaped < 0 && errno == EINTR));
    if (reaped < 0 && errno != ECHILD) return false;
    bool joined = (scope->preparation <= 0 || scope->preparation_joined) && (scope->monitor <= 0 || scope->monitor_joined);
    if (joined && reaped < 0 && errno == ECHILD && (!scope->created || cgroup_empty(scope->cgroup)) && tracked_absent(&tracked)) break;
    int64_t now = milliseconds(); if (now < started || now - started >= 2000) return false;
    struct timespec pause = {0, 1000000}; nanosleep(&pause, NULL);
  }
  scope->dead = true; observed->populated = 0; observed->remaining_descendants = 0; observed->all_reaped = 1;
  if (!local_service_step(scope, CLIQ_LOCAL_BIRTH_QUIESCENT)) return false;
  int *fixed[] = {&scope->config_fd, &scope->bootstrap, &scope->controller_image, &scope->bwrap, &scope->output[0], &scope->output[1]};
  for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i) if (!local_close(scope, fixed[i])) return false;
  for (size_t i = 0; i < CLIQ_LOCAL_SERVICE_FILES; ++i) if (!local_close(scope, &scope->sources[i]) || !local_close(scope, &scope->sealed[i])) return false;
  if (!local_service_step(scope, CLIQ_LOCAL_BIRTH_FDS_RETIRED) || !local_close(scope, &scope->cgroup) || !local_close(scope, &scope->birth) ||
      !local_close(scope, &scope->anchor)) return false;
  scope->retired = true;
  int64_t now = milliseconds(); return now >= started && now - started < 2000;
}
static bool local_service_inspect_active(struct local_service_scope *scope) {
  /* The original health and boundary checks must precede the active row CAS.
   * This inspection releases no model peer. It remains available afterwards
   * for fresh dispatch and lease observations. */
  if (!local_service_current(scope) || !scope->blocked || !scope->released || scope->failed || scope->dead || scope->monitor_joined ||
      (!scope->active && !local_activation_live(scope)))
    return false;
  const struct cliq_local_service_observation *identity = &scope->identity.observation;
  pid_t pids[] = {scope->monitor, (pid_t)identity->namespace_init_pid, (pid_t)identity->bootstrap_pid};
  const char *tokens[] = {identity->monitor_start, identity->namespace_init_start, identity->bootstrap_start};
  for (size_t i = 0; i < 3; ++i) {
    char token[CLIQ_WORKER_TOKEN_BYTES];
    if (pids[i] < 1 || !cliq_process_token(pids[i], token) || strcmp(token, tokens[i])) return false;
    if (i) {
      char filename[64]; struct stat namespace; pid_t inside;
      int length = snprintf(filename, sizeof(filename), "/proc/%ld/ns/pid", (long)pids[i]);
      if (length < 0 || (size_t)length >= sizeof(filename) || stat(filename, &namespace) ||
          (uint64_t)namespace.st_ino != identity->pid_namespace_inode || !cliq_namespace_pid(pids[i], &inside) || inside != (pid_t)i) return false;
    }
  }
  char executable[96], bound[128]; struct stat image, mounted;
  int left = snprintf(executable, sizeof(executable), "/proc/%ld/exe", (long)identity->bootstrap_pid);
  int right = snprintf(bound, sizeof(bound), "/proc/%ld/root/runtime/bin/cliq-local-inference", (long)identity->bootstrap_pid);
  if (left < 0 || (size_t)left >= sizeof(executable) || right < 0 || (size_t)right >= sizeof(bound) ||
      stat(executable, &image) || stat(bound, &mounted) || !S_ISREG(image.st_mode) || image.st_dev != mounted.st_dev || image.st_ino != mounted.st_ino) return false;
  char network_path[64]; struct stat host_network, service_network;
  int network_length = snprintf(network_path, sizeof(network_path), "/proc/%ld/ns/net", (long)identity->namespace_init_pid);
  if (network_length < 0 || (size_t)network_length >= sizeof(network_path) || stat("/proc/self/ns/net", &host_network) ||
      stat(network_path, &service_network) || (host_network.st_dev == service_network.st_dev && host_network.st_ino == service_network.st_ino))
    return false;
  struct tracked_set observed = {0};
  if (!collect_processes(scope->cgroup, &observed, 0) || !observed.count) return false;
  bool monitor = false, init = false, bootstrap = false;
  for (size_t i = 0; i < observed.count; ++i) {
    const struct tracked_process *process = &observed.process[i];
    if (process->pid == pids[0]) { if (strcmp(process->token, tokens[0])) return false; monitor = true; continue; }
    char filename[64]; struct stat namespace;
    int length = snprintf(filename, sizeof(filename), "/proc/%ld/ns/pid", (long)process->pid);
    if (length < 0 || (size_t)length >= sizeof(filename) || stat(filename, &namespace) || (uint64_t)namespace.st_ino != identity->pid_namespace_inode) return false;
    length = snprintf(filename, sizeof(filename), "/proc/%ld/ns/net", (long)process->pid);
    if (length < 0 || (size_t)length >= sizeof(filename) || stat(filename, &namespace) ||
        namespace.st_dev != service_network.st_dev || namespace.st_ino != service_network.st_ino) return false;
    if (process->pid == pids[1] && !strcmp(process->token, tokens[1])) init = true;
    if (process->pid == pids[2] && !strcmp(process->token, tokens[2])) bootstrap = true;
  }
  return monitor && init && bootstrap && local_service_current(scope);
}
static bool local_recovery_named(int parent, const char *name, int fd, const struct cliq_local_birth_identity *expected) {
  struct stat held, named;
  return fd >= 0 && native_cgroup(fd) && !fstat(fd, &held) && local_identity_is(expected, &held) &&
    !fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) && local_identity_is(expected, &named);
}
/* The current cleanup purpose receives only the held anchor and original
 * witness. It never transfers model inputs, opens a peer or resumes a process. */
static bool local_cleanup_retained(struct local_service_scope *scope, const struct cliq_local_service_packet *request,
  int *passed, size_t count, struct cliq_local_service_packet *response) {
  if (scope->attempted || count != 2 || request->status || request->command != CLIQ_LOCAL_SERVICE_CLEANUP_ORIGINAL) return false;
  int root = passed[0], birth = passed[1], parent = -1, leaf = -1, group = -1;
  passed[0] = passed[1] = -1;
  struct cliq_local_birth_history history, final; struct stat held, named;
  int64_t started = milliseconds();
  bool valid = started >= 0 && native_cgroup(root) && !fstat(root, &held) && flock(birth, LOCK_EX | LOCK_NB) == 0 &&
    cliq_local_birth_read(birth, &history) && local_packet_same(request, &history.first.packet) &&
    local_identity_is(&history.first.controller_anchor, &held) &&
    history.first.controller_pid != getpid() && original_process_absent((pid_t)history.first.controller_pid, history.first.controller_start);
  char group_name[96];
  int length = snprintf(group_name, sizeof(group_name), "cliq-local-%s", request->binding.native_nonce);
  valid = valid && length > 0 && (size_t)length < sizeof(group_name);
  const struct cliq_local_service_observation *original = valid ? &history.last.packet.observation : NULL;
  if (valid) {
    parent = openat(root, "controllers", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    valid = local_recovery_named(root, "controllers", parent, &history.first.controller_parent);
  }
  if (valid) {
    leaf = openat(parent, history.first.controller_leaf_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    valid = leaf >= 0 ? local_recovery_named(parent, history.first.controller_leaf_name, leaf, &history.first.controller_leaf) &&
      cgroup_empty(leaf) : errno == ENOENT;
  }
  if (valid) {
    group = openat(root, group_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (!original->cgroup_inode) valid = group < 0 && errno == ENOENT;
    else valid = group >= 0 && native_cgroup(group) && !fstat(group, &held) &&
      (uint64_t)held.st_dev == original->cgroup_device && (uint64_t)held.st_ino == original->cgroup_inode &&
      held.st_uid == geteuid() && held.st_gid == getegid() && (held.st_mode & 07777) == 0700 &&
      !fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&held, &named);
  }
  struct tracked_set tracked = {0};
  if (valid && group >= 0) valid = collect_processes(group, &tracked, 0);
  if (valid) {
    const int64_t pids[] = {original->preparation_pid, original->monitor_pid, original->namespace_init_pid, original->bootstrap_pid};
    const char *tokens[] = {original->preparation_start, original->monitor_start, original->namespace_init_start, original->bootstrap_start};
    for (size_t i = 0; valid && i < 4; ++i) if (pids[i]) valid = track_process(&tracked, (pid_t)pids[i], tokens[i]);
  }
  /* Both local child forks enter the recorded cgroup atomically via clone3.
   * Kill only the still-held born cgroup, never a caller-selected PID/name. */
  if (valid && group >= 0) valid = write_control(group, "cgroup.kill", "1");
  while (valid && ((group >= 0 && !cgroup_empty(group)) || !tracked_absent(&tracked))) {
    int64_t now = milliseconds();
    if (shutdown_requested || now < started || now - started >= 2000) { valid = false; break; }
    struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
  }
  if (valid) valid = original_process_absent((pid_t)history.first.controller_pid, history.first.controller_start) &&
    cliq_local_birth_read(birth, &final) && final.count == history.count &&
    !memcmp(final.last.digest, history.last.digest, sizeof(history.last.digest)) &&
    !fstat(root, &held) && local_identity_is(&history.first.controller_anchor, &held) &&
    local_recovery_named(root, "controllers", parent, &history.first.controller_parent);
  if (valid) valid = leaf >= 0 ? local_recovery_named(parent, history.first.controller_leaf_name, leaf, &history.first.controller_leaf) &&
    cgroup_empty(leaf) : fstatat(parent, history.first.controller_leaf_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
  if (valid) valid = group >= 0 ? !fstat(group, &held) && (uint64_t)held.st_dev == original->cgroup_device &&
    (uint64_t)held.st_ino == original->cgroup_inode && cgroup_empty(group) &&
    !fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&held, &named) :
    fstatat(root, group_name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
  if (!local_close(scope, &group)) valid = false;
  if (!local_close(scope, &leaf)) valid = false;
  if (!local_close(scope, &parent)) valid = false;
  if (!local_close(scope, &birth)) valid = false;
  if (!local_close(scope, &root)) valid = false;
  if (!valid || milliseconds() < started || milliseconds() - started >= 2000) return false;
  *response = history.last.packet; response->command = request->command;
  response->observation.populated = 0; response->observation.remaining_descendants = 0; response->observation.all_reaped = 1;
  scope->retired = true;
  scope->cleanup_only = true;
  return true;
}
static int local_service_controller(void) {
  umask(0077); local_service_initialize();
  if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 70;
  struct sigaction action; memset(&action, 0, sizeof(action)); action.sa_handler = request_shutdown; sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 70;
  /* Reuse only the physical original-controller HELLO, before any local
   * service input/row/resource can exist. All subsequent packets are local. */
  struct cliq_worker_packet hello = cliq_packet(CLIQ_CONTROLLER_HELLO); hello.pid = getpid();
  if (!cliq_process_token(getpid(), hello.start_token) || !cliq_send(3, &hello, NULL, 0)) return 70;
  bool valid = true;
  while (valid && !shutdown_requested) {
    if (local_service.attempted && !local_service.cleanup_only && !local_service.active && !local_activation_live(&local_service)) break;
    if (!local_service_pump_prepare(&local_service)) { local_service.failed = true; break; }
    struct pollfd control = {.fd = 3, .events = POLLIN}; int available = poll(&control, 1, local_service.preparation && !local_service.prepared ? 1 : 10);
    if (available < 0 && errno == EINTR) continue;
    if (available < 0 || (available && !(control.revents & POLLIN))) break;
    if (!available) continue;
    struct cliq_local_service_packet request, response; int passed[CLIQ_LOCAL_SERVICE_FDS]; size_t count; bool uncertain = false;
    if (!cliq_local_service_receive(3, &request, passed, CLIQ_LOCAL_SERVICE_FDS, &count, 0, &uncertain) || uncertain) {
      if (uncertain) local_service.uncertain = true;
      break;
    }
    response = local_service.attempted ? local_service.identity : request; response.command = request.command; int connected = -1; bool ok = false, forwarded = false;
    if (request.command == CLIQ_LOCAL_SERVICE_CLEANUP_ORIGINAL && !local_service.cleanup_only) {
      ok = local_cleanup_retained(&local_service, &request, passed, count, &response);
      forwarded = ok;
    } else if (request.command == CLIQ_LOCAL_SERVICE_RESERVE && !local_service.cleanup_only) ok = local_service_reserve(&local_service, &request, passed, count);
    else if (!count && !request.status && local_packet_same(&request, &local_service.identity) && local_service.attempted) {
      if (request.command == CLIQ_LOCAL_SERVICE_PREPARE) ok = local_service_prepare(&local_service);
      else if (request.command == CLIQ_LOCAL_SERVICE_POLL_PREPARED) ok = local_service_pump_prepare(&local_service);
      else if (request.command == CLIQ_LOCAL_SERVICE_CREATE_BLOCKED) ok = local_service_create_blocked(&local_service);
      else if (request.command == CLIQ_LOCAL_SERVICE_STOP) ok = local_service_stop(&local_service);
      else if (request.command == CLIQ_LOCAL_SERVICE_INSPECT_ACTIVE) ok = local_service_inspect_active(&local_service);
      else if (local_service.blocked && !local_service.failed && !local_service.dead &&
          (request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE || request.command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE ||
            request.command == CLIQ_LOCAL_SERVICE_CONNECT_HEALTH || request.command == CLIQ_LOCAL_SERVICE_CONNECT_MODEL)) {
        bool allowed = request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE ? !local_service.released && local_activation_live(&local_service) :
          request.command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE ? local_service.released && !local_service.active && local_activation_live(&local_service) :
          request.command == CLIQ_LOCAL_SERVICE_CONNECT_HEALTH ? local_service.released : local_service.active;
        if (allowed && request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE) allowed = local_service_step(&local_service, CLIQ_LOCAL_BIRTH_ENGINE_RELEASED);
        if (allowed && cliq_local_service_send(local_service.channel, &request, NULL, 0) && readable(local_service.channel, 5000)) {
          size_t extra = 0;
          ok = cliq_local_service_receive(local_service.channel, &response, &connected, 1, &extra, 0, &uncertain) && !uncertain &&
            local_packet_same(&response, &local_service.identity) &&
            response.command == (request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE ? CLIQ_LOCAL_SERVICE_ACTIVATED : request.command) &&
            (request.command == CLIQ_LOCAL_SERVICE_CONNECT_HEALTH || request.command == CLIQ_LOCAL_SERVICE_CONNECT_MODEL ?
              (response.status == 0 && extra == 1) || (response.status == 2 && extra == 0) : response.status == 0 && extra == 0);
          if (uncertain) local_service.uncertain = true;
          if (ok && request.command == CLIQ_LOCAL_SERVICE_RELEASE_ENGINE) local_service.released = true;
          if (ok && request.command == CLIQ_LOCAL_SERVICE_PUBLISH_ACTIVE) local_service.active = true;
          response.command = request.command;
          forwarded = true;
        }
      }
    }
    for (size_t i = 0; i < count; ++i) if (!local_close(&local_service, &passed[i])) ok = false;
    if (ok && !forwarded) { response = local_service.identity; response.command = request.command; }
    /* A full count is a preparation-complete reply only after the real
     * preparer joined and its source descriptors retired. Durable progress
     * frames retain the original per-object count for recovery. */
    if ((request.command == CLIQ_LOCAL_SERVICE_PREPARE || request.command == CLIQ_LOCAL_SERVICE_POLL_PREPARED) && !local_service.prepared)
      response.observation.prepared_count = 0;
    if (!ok) { local_service.failed = true; response.status = 1; }
    if (!local_service_stamp(&response) || !cliq_local_service_send(3, &response, connected >= 0 && ok ? &connected : NULL, connected >= 0 && ok ? 1 : 0)) valid = false;
    if (!local_close(&local_service, &connected)) valid = false;
    if (!ok || request.command == CLIQ_LOCAL_SERVICE_STOP) break;
  }
  if (local_service.attempted && !local_service.retired && !local_service_stop(&local_service)) return 70;
  return valid && !local_service.uncertain ? 0 : 70;
}
#endif
