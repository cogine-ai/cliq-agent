/* Test-only external Secret Service on the disposable user's ACTUAL manager
 * bus. No namespace, child manager, StateOwner, phase injector or process pause.
 * This is not GNOME Keyring qualification. */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "credential-secret-service-fixture.h"

struct installed_fixture {
  GMainLoop *loop;
  GDBusConnection *bus;
  GDBusMethodInvocation *unanswered;
  struct fixture_secret_data secret;
  guint registrations[3], subscription;
  pid_t supervisor;
  unsigned long long start;
  struct stat image;
  const char *image_path;
  bool armed, inspected, retired, finished, failed;
  char sender[256], command[128];
  size_t used;
  guint input, interrupted, deadline;
};

static bool announce(const char *event) {
  return fputs(event, stdout) != EOF && fflush(stdout) == 0;
}
static void installed_fail(struct installed_fixture *fixture) { fixture->failed = true; if (fixture->loop) g_main_loop_quit(fixture->loop); }
static bool original_supervisor(struct installed_fixture *fixture, const char *sender) {
  GError *error = NULL;
  GVariant *pid = g_dbus_connection_call_sync(fixture->bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
    "org.freedesktop.DBus", "GetConnectionUnixProcessID", g_variant_new("(s)", sender), G_VARIANT_TYPE("(u)"),
    G_DBUS_CALL_FLAGS_NO_AUTO_START, 1000, NULL, &error);
  if (!pid) { g_clear_error(&error); return false; }
  guint32 actual_pid; g_variant_get(pid, "(u)", &actual_pid); g_variant_unref(pid);
  if (actual_pid != (guint32)fixture->supervisor) return false;
  GVariant *uid = g_dbus_connection_call_sync(fixture->bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
    "org.freedesktop.DBus", "GetConnectionUnixUser", g_variant_new("(s)", sender), G_VARIANT_TYPE("(u)"),
    G_DBUS_CALL_FLAGS_NO_AUTO_START, 1000, NULL, &error);
  if (!uid) { g_clear_error(&error); installed_fail(fixture); return false; }
  guint32 actual_uid; g_variant_get(uid, "(u)", &actual_uid); g_variant_unref(uid);
  if (actual_uid != getuid()) { installed_fail(fixture); return false; }
  char proc[80], bytes[8192]; struct stat current, selected;
  int count = snprintf(proc, sizeof(proc), "/proc/%ld/stat", (long)fixture->supervisor);
  if (count <= 0 || (size_t)count >= sizeof(proc)) goto failed;
  int fd = open(proc, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) goto failed;
  ssize_t length = read(fd, bytes, sizeof(bytes) - 1);
  bool valid = !fstat(fd, &current) && current.st_uid == getuid() && length > 0 && (size_t)length < sizeof(bytes) - 1;
  if (close(fd)) valid = false;
  if (!valid) goto failed;
  bytes[length] = '\0'; char *tail = strrchr(bytes, ')'); if (!tail || tail[1] != ' ') goto failed;
  char *save = NULL, *field = strtok_r(tail + 2, " \n", &save); unsigned index = 0; unsigned long long start = 0;
  while (field) {
    if (!index && (!strcmp(field, "Z") || !strcmp(field, "X") || !strcmp(field, "x"))) goto failed;
    if (index == 19) { char *end; errno = 0; start = strtoull(field, &end, 10); if (errno || *end) goto failed; break; }
    index++; field = strtok_r(NULL, " \n", &save);
  }
  if (!start || start != fixture->start) goto failed;
  count = snprintf(proc, sizeof(proc), "/proc/%ld/exe", (long)fixture->supervisor);
  if (count <= 0 || (size_t)count >= sizeof(proc) || stat(proc, &current) || lstat(fixture->image_path, &selected) ||
      !S_ISREG(selected.st_mode) || selected.st_uid != getuid() || current.st_dev != fixture->image.st_dev ||
      current.st_ino != fixture->image.st_ino || current.st_size != fixture->image.st_size ||
      selected.st_dev != current.st_dev || selected.st_ino != current.st_ino || selected.st_size != current.st_size) goto failed;
  return true;
failed:
  installed_fail(fixture); return false;
}
static void installed_method(GDBusConnection *bus, const gchar *sender, const gchar *object_path, const gchar *interface,
  const gchar *method, GVariant *parameters, GDBusMethodInvocation *invocation, gpointer data) {
  struct installed_fixture *fixture = data;
  if (!g_dbus_is_unique_name(sender) || strlen(sender) >= sizeof(fixture->sender)) goto failed;
  if (!strcmp(interface, "org.freedesktop.Secret.Service") && !strcmp(method, "ReadAlias")) {
    const char *alias; g_variant_get(parameters, "(&s)", &alias);
    if (strcmp(alias, "default") && strcmp(alias, "session")) goto failed;
    if (!strcmp(alias, "default") && fixture->armed && !fixture->inspected && original_supervisor(fixture, sender)) {
      if (!fixture->secret.created || fixture->unanswered) goto failed;
      fixture->inspected = true; strcpy(fixture->sender, sender);
      fixture->unanswered = invocation; /* Actual remote request remains unanswered until its connection retires. */
      if (!announce("inspection-started\n")) installed_fail(fixture);
      return;
    }
    if (fixture->failed) goto failed;
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", !strcmp(alias, "default")
      ? SECRET_COLLECTION : SECRET_ROOT "/collection/session")); return;
  }
  if (!strcmp(interface, "org.freedesktop.Secret.Item") && !strcmp(method, "Delete") && fixture->secret.created) {
    fixture_secret_clear(&fixture->secret);
    g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", "/")); return;
  }
  (void)bus; (void)object_path;
  if (fixture_secret_method(&fixture->secret, interface, method, parameters, invocation)) return;
failed:
  g_dbus_method_invocation_return_dbus_error(invocation, "org.cliq.Test.Refused", "fixture request refused"); installed_fail(fixture);
}
static GVariant *installed_property(GDBusConnection *bus, const gchar *sender, const gchar *object_path,
  const gchar *interface, const gchar *property, GError **error, gpointer data) {
  (void)bus; (void)sender; (void)object_path; struct installed_fixture *fixture = data;
  GVariant *value = fixture_secret_property(&fixture->secret, interface, property); if (value) return value;
  g_set_error_literal(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY, "fixture property refused"); installed_fail(fixture); return NULL;
}
static void installed_name_changed(GDBusConnection *bus, const gchar *sender, const gchar *object_path, const gchar *interface,
  const gchar *signal, GVariant *parameters, gpointer data) {
  (void)bus; (void)sender; (void)object_path; (void)interface; (void)signal;
  struct installed_fixture *fixture = data; const char *name, *before, *after;
  g_variant_get(parameters, "(&s&s&s)", &name, &before, &after);
  if (fixture->inspected && !fixture->retired && !strcmp(name, fixture->sender) && !strcmp(before, name) && !after[0]) {
    fixture->retired = true;
    /* Discard the now-unreachable invocation only AFTER the actual message
     * bus reports this original connection gone. No forced service reply. */
    if (fixture->unanswered) {
      g_dbus_method_invocation_return_dbus_error(fixture->unanswered, "org.cliq.Test.Retired", "original connection retired");
      fixture->unanswered = NULL;
    }
    if (!announce("inspection-retired\n")) installed_fail(fixture);
  }
}
static gboolean installed_control(gint descriptor, GIOCondition condition, gpointer data) {
  struct installed_fixture *fixture = data;
  if (!(condition & G_IO_IN) || fixture->used >= sizeof(fixture->command) - 1) { installed_fail(fixture); return G_SOURCE_CONTINUE; }
  ssize_t count = read(descriptor, fixture->command + fixture->used, sizeof(fixture->command) - 1 - fixture->used);
  if (count < 0 && errno == EINTR) return G_SOURCE_CONTINUE;
  if (count <= 0) { installed_fail(fixture); return G_SOURCE_CONTINUE; }
  fixture->used += (size_t)count; fixture->command[fixture->used] = '\0';
  if (!strchr(fixture->command, '\n')) return G_SOURCE_CONTINUE;
  if (!strcmp(fixture->command, "finish\n") && fixture->inspected && fixture->retired && !fixture->secret.created) {
    fixture->finished = true; g_main_loop_quit(fixture->loop); fixture->input = 0; return G_SOURCE_REMOVE;
  }
  long pid; unsigned long long start; char extra; int parsed = 0;
  if (fixture->armed || sscanf(fixture->command, "arm %ld %llu%c%n", &pid, &start, &extra, &parsed) != 3 || extra != '\n' ||
      parsed < 0 || (size_t)parsed != fixture->used ||
      pid <= 0 || pid > INT_MAX || !start) { installed_fail(fixture); return G_SOURCE_CONTINUE; }
  fixture->supervisor = (pid_t)pid; fixture->start = start; fixture->armed = true; fixture->used = 0;
  if (!announce("armed\n")) installed_fail(fixture);
  return G_SOURCE_CONTINUE;
}
static gboolean installed_interrupted(gpointer data) { installed_fail(data); return G_SOURCE_CONTINUE; }

int main(int argc, char **argv) {
  struct installed_fixture fixture = {0}; GError *error = NULL; GDBusNodeInfo *shape = NULL;
  if (argc != 2 || !getuid() || geteuid() != getuid() || argv[1][0] != '/' || signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
      lstat(argv[1], &fixture.image) || !S_ISREG(fixture.image.st_mode) || fixture.image.st_uid != getuid()) goto failed;
  fixture.image_path = argv[1]; char address[128];
  int length = snprintf(address, sizeof(address), "unix:path=/run/user/%lu/bus", (unsigned long)getuid());
  if (length <= 0 || (size_t)length >= sizeof(address)) goto failed;
  fixture.bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
  if (!fixture.bus) goto failed;
  g_dbus_connection_set_exit_on_close(fixture.bus, FALSE);
  shape = g_dbus_node_info_new_for_xml(
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
    "<method name='Delete'><arg type='o' direction='out'/></method>"
    "<property name='Attributes' type='a{ss}' access='read'/><property name='Locked' type='b' access='read'/></interface></node>", &error);
  if (!shape) goto failed;
  const GDBusInterfaceVTable methods = {.method_call = installed_method, .get_property = installed_property};
  const char *paths[] = {SECRET_ROOT, SECRET_COLLECTION, SECRET_ITEM};
  for (size_t index = 0; index < 3; index++) {
    fixture.registrations[index] = g_dbus_connection_register_object(fixture.bus, paths[index], shape->interfaces[index],
      &methods, &fixture, NULL, &error);
    if (!fixture.registrations[index]) goto failed;
  }
  fixture.subscription = g_dbus_connection_signal_subscribe(fixture.bus, "org.freedesktop.DBus", "org.freedesktop.DBus",
    "NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, installed_name_changed, &fixture, NULL);
  GVariant *reply = g_dbus_connection_call_sync(fixture.bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
    "RequestName", g_variant_new("(su)", "org.freedesktop.secrets", 4u), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NO_AUTO_START, 1000, NULL, &error);
  if (!reply) goto failed;
  guint32 acquired; g_variant_get(reply, "(u)", &acquired); g_variant_unref(reply); if (acquired != 1) goto failed;
  fixture.loop = g_main_loop_new(NULL, FALSE);
  fixture.input = g_unix_fd_add(STDIN_FILENO, G_IO_IN | G_IO_HUP | G_IO_ERR, installed_control, &fixture);
  fixture.interrupted = g_unix_signal_add(SIGTERM, installed_interrupted, &fixture);
  fixture.deadline = g_timeout_add_seconds(90, installed_interrupted, &fixture);
  if (!announce("ready\n")) goto failed;
  g_main_loop_run(fixture.loop);
  if (!fixture.finished || fixture.failed) goto failed;
  goto cleanup;
failed:
  fixture.failed = true;
cleanup:
  if (fixture.input) g_source_remove(fixture.input);
  if (fixture.interrupted) g_source_remove(fixture.interrupted);
  if (fixture.deadline) g_source_remove(fixture.deadline);
  if (fixture.unanswered) g_dbus_method_invocation_return_dbus_error(fixture.unanswered, "org.cliq.Test.Stopped", "fixture stopped");
  if (fixture.bus) {
    if (fixture.subscription) g_dbus_connection_signal_unsubscribe(fixture.bus, fixture.subscription);
    for (size_t index = 0; index < 3; index++) if (fixture.registrations[index] &&
      !g_dbus_connection_unregister_object(fixture.bus, fixture.registrations[index])) fixture.failed = true;
    g_clear_error(&error); if (!g_dbus_connection_close_sync(fixture.bus, NULL, &error)) fixture.failed = true;
    g_object_unref(fixture.bus);
  }
  fixture_secret_clear(&fixture.secret);
  g_clear_error(&error); if (shape) g_dbus_node_info_unref(shape);
  if (fixture.loop) g_main_loop_unref(fixture.loop);
  if (!fixture.failed && !announce("closed\n")) fixture.failed = true;
  return fixture.failed ? 1 : 0;
}
