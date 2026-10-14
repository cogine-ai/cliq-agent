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
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
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
static pid_t start_child(char *const arguments[], int output) {
  pid_t parent = getpid(), child = fork();
  if (child != 0) return child;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || (output >= 0 && dup2(output, STDOUT_FILENO) < 0)) _exit(126);
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
int main(int argc, char **argv) {
  struct fixture fixture = {.daemon = -1, .child = -1}; uid_t uid; gid_t gid; char address[128]; int ready[2] = {-1, -1};
  GError *error = NULL; GDBusNodeInfo *shape = NULL;
  if (argc != 4 || argv[1][0] != '/' || argv[2][0] != '/' || argv[3][0] != '/' || !isolated_runtime(&uid, &gid, address)) goto failed;
  (void)uid; (void)gid;
  if (pipe2(ready, O_CLOEXEC)) goto failed;
  char listen[160]; if (snprintf(listen, sizeof(listen), "--address=%s", address) >= (int)sizeof(listen)) goto failed;
  char *daemon_args[] = {"/usr/bin/dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1", listen, NULL};
  fixture.daemon = start_child(daemon_args, ready[1]);
  int owned = ready[1]; ready[1] = -1; if (close(owned)) goto failed;
  if (fixture.daemon < 0) goto failed;
  if (!read_announcement(ready[0], address)) goto failed;
  owned = ready[0]; ready[0] = -1; if (close(owned)) goto failed;
  fixture.bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
  if (!fixture.bus) goto failed;
  g_dbus_connection_set_exit_on_close(fixture.bus, FALSE);
  shape = g_dbus_node_info_new_for_xml("<node><interface name='org.freedesktop.systemd1.Manager'><method name='Reload'/></interface></node>", &error);
  if (!shape) goto failed;
  const GDBusInterfaceVTable methods = {.method_call = reload};
  fixture.registration = g_dbus_connection_register_object(fixture.bus, "/org/freedesktop/systemd1", shape->interfaces[0], &methods, &fixture, NULL, &error);
  if (!fixture.registration) goto failed;
  fixture.subscription = g_dbus_connection_signal_subscribe(fixture.bus, "org.freedesktop.DBus", "org.freedesktop.DBus",
    "NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, name_changed, &fixture, NULL);
  GVariant *name = g_dbus_connection_call_sync(fixture.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
    "RequestName", g_variant_new("(su)", "org.freedesktop.systemd1", 4u), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 5000, NULL, &error);
  if (!name) goto failed;
  guint32 name_owned; g_variant_get(name, "(u)", &name_owned); g_variant_unref(name); if (name_owned != 1) goto failed;
  fixture.loop = g_main_loop_new(NULL, FALSE);
  char *node_args[] = {argv[1], "--no-warnings", argv[2], argv[3], NULL};
  fixture.child = start_child(node_args, -1); if (fixture.child < 0) goto failed;
  fixture.monitor = g_timeout_add(10, observe_children, &fixture);
  fixture.timeout = g_timeout_add_seconds(45, stop_fixture, &fixture);
  fixture.interrupted = g_unix_signal_add(SIGTERM, stop_fixture, &fixture);
  g_main_loop_run(fixture.loop);
  if (!fixture.child_ok || fixture.calls != 2 || !fixture.first_gone) goto failed;
  goto cleanup;
failed:
  fixture.failed = true;
cleanup:
  if (fixture.monitor) g_source_remove(fixture.monitor);
  if (fixture.timeout) g_source_remove(fixture.timeout);
  if (fixture.interrupted) g_source_remove(fixture.interrupted);
  if (!join_child(&fixture.child)) fixture.failed = true;
  if (fixture.unanswered) g_dbus_method_invocation_return_dbus_error(fixture.unanswered, "org.cliq.Test.Completed", "fixture completed");
  if (fixture.healthy) g_dbus_method_invocation_return_dbus_error(fixture.healthy, "org.cliq.Test.Completed", "fixture completed");
  if (fixture.bus) {
    if (fixture.subscription) g_dbus_connection_signal_unsubscribe(fixture.bus, fixture.subscription);
    if (fixture.registration && !g_dbus_connection_unregister_object(fixture.bus, fixture.registration)) fixture.failed = true;
    g_clear_error(&error);
    if (!g_dbus_connection_close_sync(fixture.bus, NULL, &error)) fixture.failed = true;
    g_object_unref(fixture.bus);
  }
  if (!join_child(&fixture.daemon)) fixture.failed = true;
  for (size_t index = 0; index < 2; index++) {
    owned = ready[index]; ready[index] = -1;
    if (owned >= 0 && close(owned)) fixture.failed = true;
  }
  g_clear_error(&error); if (shape) g_dbus_node_info_unref(shape); if (fixture.loop) g_main_loop_unref(fixture.loop);
  if (fixture.failed) { fputs("credential platform timeout component refused\n", stderr); return 1; }
  puts("{\"diagnosticOnly\":true,\"actualFirstConnectionRetired\":true,\"healthySubsequentOperation\":true,\"childrenJoined\":true,\"installedI1Qualified\":false}"); return 0;
}
