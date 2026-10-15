/* External-boundary component fixture only. A private mount namespace holds a
 * real, same-UID message bus; no host bus, systemd owner, StateOwner, credential
 * grant or installed qualification is replaced or manufactured. */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct fixture {
  GMainLoop *loop;
  GDBusConnection *bus;
  GDBusMethodInvocation *unanswered, *healthy;
  GPid daemon, child;
  guint monitor, timeout, interrupted, registration, subscription;
  unsigned calls;
  bool failed, child_ok, first_gone;
  char first_sender[256];
  /* Fixed independent broker scenario; none of these values is production
   * authority. The actual native create_compare supplies its observation. */
  bool broker_mode, created, preparation_entered, preparation_gone, released, timely;
  char preparation_sender[256], control[32]; size_t control_used;
  int notify; guint control_watch, secret_registrations[3];
  GVariant *item_attributes, *item_secret;
};
static void refuse(struct fixture *fixture) { fixture->failed = true; if (fixture->loop) g_main_loop_quit(fixture->loop); }
static gboolean stop_fixture(gpointer data) { refuse(data); return G_SOURCE_CONTINUE; }
static gboolean observe_children(gpointer data) {
  struct fixture *fixture = data; siginfo_t status = {0};
  /* Observe without reaping. Only join_child consumes an owning PID, so a
   * main-loop callback cannot race PID reuse with failure cleanup. */
  if (waitid(P_PID, (id_t)fixture->daemon, &status, WEXITED | WNOHANG | WNOWAIT) || status.si_pid) {
    refuse(fixture); return G_SOURCE_CONTINUE;
  }
  memset(&status, 0, sizeof(status));
  if (waitid(P_PID, (id_t)fixture->child, &status, WEXITED | WNOHANG | WNOWAIT)) refuse(fixture);
  else if (status.si_pid == fixture->child) {
    fixture->child_ok = status.si_code == CLD_EXITED && status.si_status == 0;
    if (!fixture->child_ok) fixture->failed = true;
    if (!fixture->broker_mode || !fixture->preparation_entered || (fixture->first_gone && fixture->preparation_gone))
      g_main_loop_quit(fixture->loop);
  }
  return G_SOURCE_CONTINUE;
}
static void name_changed(GDBusConnection *bus, const gchar *sender, const gchar *path, const gchar *interface,
  const gchar *signal, GVariant *parameters, gpointer data) {
  (void)bus; (void)sender; (void)path; (void)interface; (void)signal;
  struct fixture *fixture = data; const char *name, *before, *after;
  g_variant_get(parameters, "(&s&s&s)", &name, &before, &after);
  if (fixture->first_sender[0] && !strcmp(name, fixture->first_sender) && !strcmp(before, name) && !after[0]) {
    fixture->first_gone = true;
    if (fixture->healthy) {
      GDBusMethodInvocation *reply = fixture->healthy; fixture->healthy = NULL;
      g_dbus_method_invocation_return_value(reply, g_variant_new("()"));
    }
  }
  if (fixture->preparation_sender[0] && !strcmp(name, fixture->preparation_sender) && !strcmp(before, name) && !after[0]) {
    fixture->preparation_gone = true;
    const char retired[] = "prepare-retired\n";
    if (write(fixture->notify, retired, sizeof(retired) - 1) != (ssize_t)(sizeof(retired) - 1)) refuse(fixture);
  }
}
static void reload(GDBusConnection *bus, const gchar *sender, const gchar *path, const gchar *interface,
  const gchar *method, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer data) {
  (void)bus; (void)path; (void)parameters; struct fixture *fixture = data;
  if (strcmp(interface, "org.freedesktop.systemd1.Manager") || strcmp(method, "Reload") ||
      !g_dbus_is_unique_name(sender) || strlen(sender) >= sizeof(fixture->first_sender) || fixture->calls >= 2) {
    g_dbus_method_invocation_return_dbus_error(invocation, "org.cliq.Test.Refused", "fixture request refused"); refuse(fixture); return;
  }
  fixture->calls++;
  if (fixture->calls == 1) {
    strcpy(fixture->first_sender, sender);
    fixture->unanswered = invocation; /* Full ownership, deliberately no remote reply. */
  } else if (fixture->first_gone) g_dbus_method_invocation_return_value(invocation, g_variant_new("()"));
  else fixture->healthy = invocation; /* Signal delivery need not precede this method callback. */
}
#define SECRET_ROOT "/org/freedesktop/secrets"
#define SECRET_COLLECTION SECRET_ROOT "/collection/component"
#define SECRET_ITEM SECRET_COLLECTION "/item"
#define SECRET_SESSION SECRET_ROOT "/session/component"
static void secret_call(GDBusConnection *bus, const gchar *sender, const gchar *path, const gchar *interface,
  const gchar *method, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer data) {
  (void)bus; (void)path; struct fixture *fixture = data;
  if (!g_dbus_is_unique_name(sender) || strlen(sender) >= sizeof(fixture->first_sender)) goto refused;
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "ReadAlias")) {
    const char *alias; g_variant_get(parameters, "(&s)", &alias);
    if (strcmp(alias, "default") && strcmp(alias, "session")) goto refused;
    if (!fixture->first_sender[0]) strcpy(fixture->first_sender, sender);
    if (!strcmp(alias, "default") && strcmp(sender, fixture->first_sender) && !fixture->preparation_entered) {
      if (!fixture->created || fixture->unanswered) goto refused;
      strcpy(fixture->preparation_sender, sender); fixture->preparation_entered = true;
      fixture->unanswered = invocation; /* Real remote call stays unanswered. */
      const char started[] = "prepare-started\n";
      if (write(fixture->notify, started, sizeof(started) - 1) != (ssize_t)(sizeof(started) - 1)) refuse(fixture);
      return;
    }
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", !strcmp(alias, "default")
      ? SECRET_COLLECTION : SECRET_ROOT "/collection/session")); return;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "SearchItems")) {
    GVariant *attributes = g_variant_get_child_value(parameters, 0);
    bool valid = g_variant_n_children(attributes) == 9 && (!fixture->created || g_variant_equal(attributes, fixture->item_attributes));
    g_variant_unref(attributes); if (!valid) goto refused;
    const char *items[] = { SECRET_ITEM, NULL }, *empty[] = { NULL };
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(@ao@ao)",
      g_variant_new_objv(fixture->created ? items : empty, -1), g_variant_new_objv(empty, -1))); return;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "OpenSession")) {
    const char *algorithm; GVariant *box; g_variant_get(parameters, "(&s@v)", &algorithm, &box);
    GVariant *value = g_variant_get_variant(box); bool valid = !strcmp(algorithm, "plain") &&
      g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) && !g_variant_get_string(value, NULL)[0];
    g_variant_unref(value); g_variant_unref(box); if (!valid) goto refused;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(vo)", g_variant_new_string(""), SECRET_SESSION)); return;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Collection") && !strcmp(method, "CreateItem") && !fixture->created) {
    GVariant *properties = g_variant_get_child_value(parameters, 0), *secret = g_variant_get_child_value(parameters, 1);
    fixture->item_attributes = g_variant_lookup_value(properties, "org.freedesktop.Secret.Item.Attributes", G_VARIANT_TYPE("a{ss}"));
    fixture->item_secret = g_variant_get_child_value(secret, 2);
    bool valid = fixture->item_attributes && g_variant_n_children(fixture->item_attributes) == 9 &&
      g_variant_n_children(fixture->item_secret) > 0 && g_variant_n_children(fixture->item_secret) <= 256;
    g_variant_unref(properties); g_variant_unref(secret); if (!valid) goto refused;
    fixture->created = true;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(oo)", SECRET_ITEM, "/")); return;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Item") && !strcmp(method, "GetSecret") && fixture->created) {
    const char *session; g_variant_get(parameters, "(&o)", &session); if (strcmp(session, SECRET_SESSION)) goto refused;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("((o@ay@ays))", SECRET_SESSION,
      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1), g_variant_ref(fixture->item_secret), "application/octet-stream")); return;
  }
refused:
  g_dbus_method_invocation_return_dbus_error(invocation, "org.cliq.Test.Refused", "fixture request refused"); refuse(fixture);
}
static GVariant *secret_property(GDBusConnection *bus, const gchar *sender, const gchar *path,
  const gchar *interface, const gchar *property, GError **error, gpointer data) {
  (void)bus; (void)sender; (void)path; struct fixture *fixture = data;
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(property, "Collections")) {
    const char *collections[] = { SECRET_COLLECTION, NULL }; return g_variant_new_objv(collections, -1);
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Collection") && !strcmp(property, "Items")) {
    const char *items[] = { SECRET_ITEM, NULL }, *empty[] = { NULL }; return g_variant_new_objv(fixture->created ? items : empty, -1);
  }
  if ((!strcmp(interface, "org.freedesktop.Secret.Collection") || !strcmp(interface, "org.freedesktop.Secret.Item")) &&
      !strcmp(property, "Locked")) return g_variant_new_boolean(FALSE);
  if (!strcmp(interface, "org.freedesktop.Secret.Item") && !strcmp(property, "Attributes") && fixture->item_attributes)
    return g_variant_ref(fixture->item_attributes);
  g_set_error_literal(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY, "fixture property refused"); refuse(fixture); return NULL;
}
static gboolean control_reply(gint descriptor, GIOCondition condition, gpointer data) {
  struct fixture *fixture = data;
  if (!(condition & G_IO_IN) || !fixture->preparation_entered || fixture->released || fixture->control_used >= sizeof(fixture->control) - 1) {
    refuse(fixture); return G_SOURCE_CONTINUE;
  }
  ssize_t count; do { count = read(descriptor, fixture->control + fixture->control_used,
    sizeof(fixture->control) - 1 - fixture->control_used); } while (count < 0 && errno == EINTR);
  if (count <= 0) { refuse(fixture); return G_SOURCE_CONTINUE; }
  fixture->control_used += (size_t)count; fixture->control[fixture->control_used] = '\0';
  if (!strchr(fixture->control, '\n')) return G_SOURCE_CONTINUE;
  if (strcmp(fixture->control, "release:timely\n") && strcmp(fixture->control, "release:late\n")) { refuse(fixture); return G_SOURCE_CONTINUE; }
  fixture->timely = !strcmp(fixture->control, "release:timely\n"); fixture->released = true;
  if (fixture->unanswered) {
    GDBusMethodInvocation *reply = fixture->unanswered; fixture->unanswered = NULL;
    g_dbus_method_invocation_return_value(reply, g_variant_new("(o)", SECRET_COLLECTION));
  }
  fixture->control_watch = 0; return G_SOURCE_REMOVE;
}
/* Direct children remain unreaped until this owner joins them; these PIDs
 * cannot be reused. PDEATHSIG also retires them if this coordinator dies. */
static bool join_child(GPid *pid) {
  if (*pid < 0) return true;
  pid_t owned = *pid; int status; siginfo_t observed = {0};
  /* Refuse signalling if this is no longer our unreaped child. */
  if (waitid(P_PID, (id_t)owned, &observed, WEXITED | WNOHANG | WNOWAIT)) return false;
  bool valid = observed.si_pid == owned || kill(owned, SIGTERM) == 0 || errno == ESRCH;
  for (unsigned attempt = 0; attempt < 100; attempt++) {
    pid_t result = waitpid(owned, &status, WNOHANG);
    if (result == owned) { *pid = -1; return valid; }
    if (result < 0 && errno != EINTR) return false;
    struct timespec delay = {0, 10000000}; while (nanosleep(&delay, &delay) && errno == EINTR) {}
  }
  if (kill(owned, SIGKILL) && errno != ESRCH) valid = false;
  pid_t result; do { result = waitpid(owned, &status, 0); } while (result < 0 && errno == EINTR);
  if (result == owned) *pid = -1; else valid = false;
  return valid;
}
static pid_t start_child(char *const arguments[], int output, int input) {
  pid_t parent = getpid(), child = fork();
  if (child != 0) return child;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || (output >= 0 && dup2(output, STDOUT_FILENO) < 0) ||
      (input >= 0 && dup2(input, STDIN_FILENO) < 0)) _exit(126);
  execv(arguments[0], arguments); _exit(127);
}
static bool read_announcement(int descriptor, const char *address) {
  gint64 deadline = g_get_monotonic_time() + 5000000; char announcement[256]; size_t used = 0;
  while (used < sizeof(announcement) - 1) {
    gint64 remaining = deadline - g_get_monotonic_time(); if (remaining <= 0) return false;
    struct pollfd observed = {descriptor, POLLIN, 0}; int polled = poll(&observed, 1, (int)((remaining + 999) / 1000));
    if (polled < 0 && errno == EINTR) continue;
    if (polled != 1 || !(observed.revents & POLLIN)) return false;
    ssize_t count = read(descriptor, announcement + used, sizeof(announcement) - 1 - used);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    used += (size_t)count; announcement[used] = '\0';
    if (strchr(announcement, '\n')) return !strncmp(announcement, address, strlen(address)) &&
      announcement[strlen(address)] == ',' && announcement[used - 1] == '\n';
  }
  return false;
}
static bool isolated_runtime(uid_t *uid, gid_t *gid, char address[128]) {
  pid_t parent = getppid();
  const char *sudo_uid = getenv("SUDO_UID"), *sudo_gid = getenv("SUDO_GID"); char *end;
  if (getuid() || geteuid() || !sudo_uid || !sudo_gid) return false;
  errno = 0; unsigned long actual_uid = strtoul(sudo_uid, &end, 10);
  if (errno || *end || !actual_uid || actual_uid > UINT_MAX) return false;
  errno = 0; unsigned long actual_gid = strtoul(sudo_gid, &end, 10);
  if (errno || *end || actual_gid > UINT_MAX) return false;
  *uid = (uid_t)actual_uid; *gid = (gid_t)actual_gid;
  struct passwd *account = getpwuid(*uid);
  if (!account || account->pw_gid != *gid || !account->pw_dir || account->pw_dir[0] != '/') return false;
  if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
      mount("cliq-platform-component", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") || mkdir("/run/user", 0755)) return false;
  char runtime[64]; int length = snprintf(runtime, sizeof(runtime), "/run/user/%lu", actual_uid);
  if (length < 0 || (size_t)length >= sizeof(runtime) || mkdir(runtime, 0700) || chown(runtime, *uid, *gid) ||
      setgroups(0, NULL) || setresgid(*gid, *gid, *gid) || setresuid(*uid, *uid, *uid)) return false;
  /* Privilege transitions clear PDEATHSIG: install it only after dropping to
   * the real runner identity, before creating any external fixture child. */
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) return false;
  length = snprintf(address, 128, "unix:path=%s/bus", runtime);
  return length > 0 && length < 128 && getuid() == *uid && geteuid() == *uid && getgid() == *gid && getegid() == *gid;
}
static bool mount_option(const char *options, const char *wanted) {
  size_t length = strlen(wanted); const char *cursor = options;
  while (*cursor) {
    const char *end = strchr(cursor, ','); size_t count = end ? (size_t)(end - cursor) : strlen(cursor);
    if (count == length && !memcmp(cursor, wanted, length)) return true;
    if (!end) break;
    cursor = end + 1;
  }
  return false;
}
static bool fixture_mount(int runtime_descriptor) {
  struct stat before, after, named; struct statx mount_before, mount_after;
  if (fstat(runtime_descriptor, &before) || lstat("/run", &named) || named.st_dev != before.st_dev || named.st_ino != before.st_ino ||
      statx(runtime_descriptor, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &mount_before) ||
      !(mount_before.stx_mask & STATX_MNT_ID)) return false;
  char mount_id[24]; int length = snprintf(mount_id, sizeof(mount_id), "%llu", (unsigned long long)mount_before.stx_mnt_id);
  if (length <= 0 || (size_t)length >= sizeof(mount_id)) return false;
  FILE *mounts = fopen("/proc/self/mountinfo", "re"); if (!mounts) return false;
  char line[4096]; size_t rows = 0, bytes = 0, matches = 0; bool valid = true;
  while (fgets(line, sizeof(line), mounts)) {
    size_t length = strlen(line); bytes += length;
    if (++rows > 1024 || bytes > 262144 || !length || line[length - 1] != '\n') { valid = false; break; }
    char *fields[32], *save = NULL; size_t count = 0;
    for (char *field = strtok_r(line, " \n", &save); field; field = strtok_r(NULL, " \n", &save)) {
      if (count == 32) { valid = false; break; }
      fields[count++] = field;
    }
    if (!valid || count < 10) { valid = false; break; }
    /* Covered /run mounts remain in mountinfo. Only the mount actually held
     * by this descriptor can decide our current runtime's qualification. */
    if (strcmp(fields[0], mount_id)) continue;
    matches++;
    /* No shared/master propagation marker is allowed on our new mount. */
    valid = count == 10 && !strcmp(fields[3], "/") && !strcmp(fields[4], "/run") && !strcmp(fields[6], "-") &&
      !strcmp(fields[7], "tmpfs") && !strcmp(fields[8], "cliq-platform-component") &&
      mount_option(fields[5], "nosuid") && mount_option(fields[5], "nodev");
    if (!valid) break;
  }
  if (ferror(mounts)) valid = false;
  if (fclose(mounts)) valid = false;
  if (fstat(runtime_descriptor, &after) || lstat("/run", &named) || named.st_dev != before.st_dev || named.st_ino != before.st_ino ||
      after.st_dev != before.st_dev || after.st_ino != before.st_ino || after.st_uid != before.st_uid ||
      after.st_gid != before.st_gid || after.st_mode != before.st_mode ||
      statx(runtime_descriptor, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &mount_after) ||
      !(mount_after.stx_mask & STATX_MNT_ID) || mount_after.stx_mnt_id != mount_before.stx_mnt_id) valid = false;
  return valid && matches == 1;
}
static bool post_exec_runtime(int *original_namespace, uid_t *uid, gid_t *gid, char address[128]) {
  uid_t real, saved; gid_t real_gid, saved_gid; struct stat before, current, proc, run, users, runtime; int signal;
  if (getresuid(&real, uid, &saved) || getresgid(&real_gid, gid, &saved_gid) || !*uid ||
      real != *uid || saved != *uid || real_gid != *gid || saved_gid != *gid ||
      prctl(PR_GET_PDEATHSIG, &signal) || signal != SIGKILL || lstat("/proc/self/stat", &proc) ||
      !S_ISREG(proc.st_mode) || proc.st_uid != *uid) return false;
  struct passwd *account = getpwuid(*uid);
  if (!account || account->pw_gid != *gid || !account->pw_dir || account->pw_dir[0] != '/' ||
      *original_namespace < 3 || ioctl(*original_namespace, NS_GET_NSTYPE) != CLONE_NEWNS ||
      fstat(*original_namespace, &before)) return false;
  int descriptor = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  bool valid = descriptor >= 0 && ioctl(descriptor, NS_GET_NSTYPE) == CLONE_NEWNS && !fstat(descriptor, &current) &&
    (current.st_dev != before.st_dev || current.st_ino != before.st_ino);
  int owned = descriptor; descriptor = -1; if (owned >= 0 && close(owned)) valid = false;
  owned = *original_namespace; *original_namespace = -1; if (close(owned)) valid = false;
  if (!valid || lstat("/run", &run) || !S_ISDIR(run.st_mode) || run.st_uid || run.st_gid ||
      (run.st_mode & 07777) != 0755 || lstat("/run/user", &users) || !S_ISDIR(users.st_mode) || users.st_uid || users.st_gid ||
      (users.st_mode & 07777) != 0755) return false;
  char directory[64]; int length = snprintf(directory, sizeof(directory), "/run/user/%lu", (unsigned long)*uid);
  if (length < 0 || (size_t)length >= sizeof(directory) || lstat(directory, &runtime) || !S_ISDIR(runtime.st_mode) ||
      runtime.st_uid != *uid || runtime.st_gid != *gid || (runtime.st_mode & 07777) != 0700) return false;
  descriptor = open("/run", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct statfs filesystem;
  valid = descriptor >= 0 && !fstatfs(descriptor, &filesystem) && filesystem.f_type == TMPFS_MAGIC && fixture_mount(descriptor);
  owned = descriptor; descriptor = -1; if (owned >= 0 && close(owned)) valid = false;
  length = snprintf(address, 128, "unix:path=%s/bus", directory);
  char socket[80]; int socket_length = snprintf(socket, sizeof(socket), "%s/bus", directory); struct stat absent;
  return valid && length > 0 && length < 128 && socket_length > 0 && (size_t)socket_length < sizeof(socket) &&
    lstat(socket, &absent) < 0 && errno == ENOENT;
}
int main(int argc, char **argv) {
  struct fixture fixture = {.daemon = -1, .child = -1}; uid_t uid; gid_t gid; char address[128]; int ready[2] = {-1, -1};
  int notify[2] = {-1, -1}, control[2] = {-1, -1};
  GError *error = NULL; GDBusNodeInfo *shape = NULL; int original_namespace = -1; bool pre_exec_root_owned = false, children_joined = true;
  if ((argc == 4 || argc == 6) && argv[0][0] == '/' && argv[1][0] == '/' && argv[2][0] == '/' && argv[3][0] == '/' &&
      (argc == 4 || (argv[4][0] == '/' && argv[5][0] == '/'))) {
    original_namespace = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (original_namespace < 3 || !isolated_runtime(&uid, &gid, address)) goto failed;
    struct stat proc; if (lstat("/proc/self/stat", &proc) || !S_ISREG(proc.st_mode) || (proc.st_uid && proc.st_uid != uid)) goto failed;
    pre_exec_root_owned = proc.st_uid == 0;
    int flags = fcntl(original_namespace, F_GETFD);
    if (flags < 0 || fcntl(original_namespace, F_SETFD, flags & ~FD_CLOEXEC)) goto failed;
    char descriptor[24]; if (snprintf(descriptor, sizeof(descriptor), "%d", original_namespace) >= (int)sizeof(descriptor)) goto failed;
    /* A normal, non-setuid exec gives this service its ordinary non-root
     * /proc identity. Never toggle dumpability or weaken native UID checks. */
    char *continued[] = {argv[0], "--ordinary-nonroot", descriptor, pre_exec_root_owned ? "1" : "0", argv[1], argv[2], argv[3],
      argc == 6 ? argv[4] : NULL, argc == 6 ? argv[5] : NULL, NULL};
    execv(argv[0], continued); goto failed;
  }
  if ((argc != 7 && argc != 9) || strcmp(argv[1], "--ordinary-nonroot") || (strcmp(argv[3], "0") && strcmp(argv[3], "1"))) goto failed;
  char *end; errno = 0; long descriptor = strtol(argv[2], &end, 10);
  if (errno || *end || descriptor < 3 || descriptor > INT_MAX) goto failed;
  original_namespace = (int)descriptor; pre_exec_root_owned = !strcmp(argv[3], "1"); argv += 3; argc -= 3;
  fixture.broker_mode = argc == 6;
  if (fixture.broker_mode && signal(SIGPIPE, SIG_IGN) == SIG_ERR) goto failed;
  if ((argc != 4 && argc != 6) || argv[1][0] != '/' || argv[2][0] != '/' || argv[3][0] != '/' ||
      (fixture.broker_mode && (argv[4][0] != '/' || argv[5][0] != '/')) ||
      !post_exec_runtime(&original_namespace, &uid, &gid, address)) goto failed;
  (void)uid; (void)gid;
  if (pipe2(ready, O_CLOEXEC)) goto failed;
  char listen[160]; if (snprintf(listen, sizeof(listen), "--address=%s", address) >= (int)sizeof(listen)) goto failed;
  char *daemon_args[] = {"/usr/bin/dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1", listen, NULL};
  fixture.daemon = start_child(daemon_args, ready[1], -1);
  int owned = ready[1]; ready[1] = -1; if (close(owned)) goto failed;
  if (fixture.daemon < 0) goto failed;
  if (!read_announcement(ready[0], address)) goto failed;
  owned = ready[0]; ready[0] = -1; if (close(owned)) goto failed;
  fixture.bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
  if (!fixture.bus) goto failed;
  g_dbus_connection_set_exit_on_close(fixture.bus, FALSE);
  shape = g_dbus_node_info_new_for_xml(fixture.broker_mode ?
    "<node><interface name='org.freedesktop.Secret.Service'>"
    "<method name='ReadAlias'><arg type='s' direction='in'/><arg type='o' direction='out'/></method>"
    "<method name='SearchItems'><arg type='a{ss}' direction='in'/><arg type='ao' direction='out'/><arg type='ao' direction='out'/></method>"
    "<method name='OpenSession'><arg type='s' direction='in'/><arg type='v' direction='in'/><arg type='v' direction='out'/><arg type='o' direction='out'/></method>"
    "<property name='Collections' type='ao' access='read'/></interface>"
    "<interface name='org.freedesktop.Secret.Collection'>"
    "<method name='CreateItem'><arg type='a{sv}' direction='in'/><arg type='(oayays)' direction='in'/><arg type='b' direction='in'/>"
    "<arg type='o' direction='out'/><arg type='o' direction='out'/></method>"
    "<property name='Items' type='ao' access='read'/><property name='Locked' type='b' access='read'/></interface>"
    "<interface name='org.freedesktop.Secret.Item'><method name='GetSecret'><arg type='o' direction='in'/><arg type='(oayays)' direction='out'/></method>"
    "<property name='Attributes' type='a{ss}' access='read'/><property name='Locked' type='b' access='read'/></interface></node>" :
    "<node><interface name='org.freedesktop.systemd1.Manager'><method name='Reload'/></interface></node>", &error);
  if (!shape) goto failed;
  const GDBusInterfaceVTable methods = {.method_call = reload}, secret_methods = {.method_call = secret_call, .get_property = secret_property};
  if (fixture.broker_mode) {
    const char *paths[] = { SECRET_ROOT, SECRET_COLLECTION, SECRET_ITEM };
    for (size_t index = 0; index < 3; index++) {
      fixture.secret_registrations[index] = g_dbus_connection_register_object(fixture.bus, paths[index], shape->interfaces[index],
        &secret_methods, &fixture, NULL, &error);
      if (!fixture.secret_registrations[index]) goto failed;
    }
  } else {
    fixture.registration = g_dbus_connection_register_object(fixture.bus, "/org/freedesktop/systemd1", shape->interfaces[0], &methods, &fixture, NULL, &error);
    if (!fixture.registration) goto failed;
  }
  fixture.subscription = g_dbus_connection_signal_subscribe(fixture.bus, "org.freedesktop.DBus", "org.freedesktop.DBus",
    "NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, name_changed, &fixture, NULL);
  GVariant *name = g_dbus_connection_call_sync(fixture.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
    "RequestName", g_variant_new("(su)", fixture.broker_mode ? "org.freedesktop.secrets" : "org.freedesktop.systemd1", 4u),
    G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, &error);
  if (!name) goto failed;
  guint32 name_owned; g_variant_get(name, "(u)", &name_owned); g_variant_unref(name); if (name_owned != 1) goto failed;
  fixture.loop = g_main_loop_new(NULL, FALSE);
  if (fixture.broker_mode) {
    if (pipe2(notify, O_CLOEXEC) || pipe2(control, O_CLOEXEC)) goto failed;
    fixture.notify = notify[1];
  }
  char *node_args[] = {argv[1], "--no-warnings", argv[2], argv[3], fixture.broker_mode ? argv[4] : NULL,
    fixture.broker_mode ? argv[5] : NULL, NULL};
  fixture.child = start_child(node_args, fixture.broker_mode ? control[1] : -1, fixture.broker_mode ? notify[0] : -1);
  if (fixture.child < 0) goto failed;
  if (fixture.broker_mode) {
    owned = control[1]; control[1] = -1; if (close(owned)) goto failed;
    owned = notify[0]; notify[0] = -1; if (close(owned)) goto failed;
    fixture.control_watch = g_unix_fd_add(control[0], G_IO_IN | G_IO_HUP | G_IO_ERR, control_reply, &fixture);
  }
  fixture.monitor = g_timeout_add(10, observe_children, &fixture);
  fixture.timeout = g_timeout_add_seconds(45, stop_fixture, &fixture);
  fixture.interrupted = g_unix_signal_add(SIGTERM, stop_fixture, &fixture);
  g_main_loop_run(fixture.loop);
  if (!fixture.child_ok || !fixture.first_gone || (fixture.broker_mode ?
      (!fixture.preparation_entered || !fixture.preparation_gone || !fixture.released || !fixture.timely) : fixture.calls != 2)) goto failed;
  goto cleanup;
failed:
  fixture.failed = true;
cleanup:
  if (original_namespace >= 0) { int namespace_owned = original_namespace; original_namespace = -1; if (close(namespace_owned)) fixture.failed = true; }
  if (fixture.monitor) g_source_remove(fixture.monitor);
  if (fixture.timeout) g_source_remove(fixture.timeout);
  if (fixture.interrupted) g_source_remove(fixture.interrupted);
  if (fixture.control_watch) g_source_remove(fixture.control_watch);
  if (!join_child(&fixture.child)) { fixture.failed = true; children_joined = false; }
  if (fixture.unanswered) g_dbus_method_invocation_return_dbus_error(fixture.unanswered, "org.cliq.Test.Completed", "fixture completed");
  if (fixture.healthy) g_dbus_method_invocation_return_dbus_error(fixture.healthy, "org.cliq.Test.Completed", "fixture completed");
  if (fixture.bus) {
    if (fixture.subscription) g_dbus_connection_signal_unsubscribe(fixture.bus, fixture.subscription);
    if (fixture.registration && !g_dbus_connection_unregister_object(fixture.bus, fixture.registration)) fixture.failed = true;
    for (size_t index = 0; index < 3; index++)
      if (fixture.secret_registrations[index] && !g_dbus_connection_unregister_object(fixture.bus, fixture.secret_registrations[index])) fixture.failed = true;
    g_clear_error(&error);
    if (!g_dbus_connection_close_sync(fixture.bus, NULL, &error)) fixture.failed = true;
    g_object_unref(fixture.bus);
  }
  if (!join_child(&fixture.daemon)) { fixture.failed = true; children_joined = false; }
  for (size_t index = 0; index < 2; index++) {
    owned = ready[index]; ready[index] = -1;
    if (owned >= 0 && close(owned)) fixture.failed = true;
    owned = notify[index]; notify[index] = -1; if (owned >= 0 && close(owned)) fixture.failed = true;
    owned = control[index]; control[index] = -1; if (owned >= 0 && close(owned)) fixture.failed = true;
  }
  if (fixture.item_attributes) g_variant_unref(fixture.item_attributes);
  if (fixture.item_secret) g_variant_unref(fixture.item_secret);
  g_clear_error(&error); if (shape) g_dbus_node_info_unref(shape); if (fixture.loop) g_main_loop_unref(fixture.loop);
  if (fixture.broker_mode) {
    printf("{\"diagnosticOnly\":true,\"actualPreparationEntered\":%s,\"closeJoinedWithin1500ms\":%s,"
      "\"actualPreparationConnectionRetired\":%s,\"childrenJoined\":%s,\"installedI1Qualified\":false}\n",
      fixture.preparation_entered ? "true" : "false", fixture.timely ? "true" : "false", fixture.preparation_gone ? "true" : "false",
      children_joined && fixture.child < 0 && fixture.daemon < 0 ? "true" : "false");
    return fixture.failed ? 1 : 0;
  }
  if (fixture.failed) { fputs("credential platform timeout component refused\n", stderr); return 1; }
  printf("{\"diagnosticOnly\":true,\"preExecProcRootOwned\":%s,\"postExecSameUidProc\":true,\"actualFirstConnectionRetired\":true,\"healthySubsequentOperation\":true,\"childrenJoined\":true,\"installedI1Qualified\":false}\n", pre_exec_root_owned ? "true" : "false"); return 0;
}
