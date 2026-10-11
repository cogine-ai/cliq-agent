/* Test-only Linux OS prerequisite, not a production credential store.
 * cc -std=c11 -Wall -Wextra -Werror cliq-secret-service-probe.c \
 *   $(pkg-config --cflags --libs gio-2.0) -o cliq-secret-service-probe
 * Secret Service: https://specifications.freedesktop.org/secret-service/latest/
 * GIO: https://docs.gtk.org/gio/method.DBusConnection.call_sync.html
 */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SERVICE "org.freedesktop.secrets"
#define ROOT "/org/freedesktop/secrets"
#define SECRET_IFACE "org.freedesktop.Secret."
#define BUS "org.freedesktop.DBus"
#define BUS_PATH "/org/freedesktop/DBus"
#define SCHEMA "org.freedesktop.Secret.Generic"
#define GENERATION "cliq-probe-generation"
#define CONTENT_TYPE "application/octet-stream"
#define TIMEOUT_MS 10000

typedef struct {
  GDBusConnection *bus;
  char *owner, *unique, *collection, *session, *item;
  const char *generation;
  uid_t uid;
  guint32 service_uid, service_pid;
  int runtime_fd, failed;
  struct stat runtime, socket;
  guint8 secret[33];
  gboolean created, readback, owned, deleted, absent, connection_closed;
} Probe;

static gboolean fail(Probe *p, const char *phase, GError **error) {
  p->failed = 1;
  fprintf(stderr, "secret-service-probe: phase=%s errorDomain=%u errorCode=%d\n",
    phase, error && *error ? (*error)->domain : 0, error && *error ? (*error)->code : 0);
  if (error) g_clear_error(error); /* Never print a remote error message. */
  return FALSE;
}

static GVariant *call(Probe *p, const char *destination, const char *path,
    const char *interface, const char *method, GVariant *parameters, const char *reply_type) {
  GError *error = NULL;
  GVariant *reply = g_dbus_connection_call_sync(p->bus, destination, path, interface, method,
    parameters, G_VARIANT_TYPE(reply_type), G_DBUS_CALL_FLAGS_NO_AUTO_START, TIMEOUT_MS, NULL, &error);
  if (!reply) fail(p, method, &error);
  return reply;
}

static gboolean object_path(const char *path) {
  return path && strlen(path) <= 1024 && strcmp(path, "/") && g_variant_is_object_path(path);
}

static GVariant *property(Probe *p, const char *path, const char *interface, const char *name, const char *type) {
  g_autoptr(GVariant) reply = call(p, p->owner, path, "org.freedesktop.DBus.Properties", "Get",
    g_variant_new("(ss)", interface, name), "(v)");
  if (!reply) return NULL;
  g_autoptr(GVariant) box = g_variant_get_child_value(reply, 0);
  GVariant *value = g_variant_get_variant(box);
  if (!g_variant_is_of_type(value, G_VARIANT_TYPE(type))) {
    g_variant_unref(value); fail(p, "property-type", NULL); return NULL;
  }
  return value;
}

static GVariant *attributes(Probe *p) {
  GVariantBuilder builder;
  g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));
  g_variant_builder_add(&builder, "{ss}", "xdg:schema", SCHEMA);
  g_variant_builder_add(&builder, "{ss}", GENERATION, p->generation);
  return g_variant_builder_end(&builder);
}

static gboolean owner_current(Probe *p) {
  g_autoptr(GVariant) owner = call(p, BUS, BUS_PATH, BUS, "GetNameOwner", g_variant_new("(s)", SERVICE), "(s)");
  if (!owner) return FALSE;
  const char *name; g_variant_get(owner, "(&s)", &name);
  if (!g_dbus_is_unique_name(name) || strlen(name) > 255 || (p->owner && strcmp(name, p->owner)))
    return fail(p, "service-owner", NULL);
  if (!p->owner) p->owner = g_strdup(name);
  g_autoptr(GVariant) uid = call(p, BUS, BUS_PATH, BUS, "GetConnectionUnixUser", g_variant_new("(s)", p->owner), "(u)");
  g_autoptr(GVariant) pid = call(p, BUS, BUS_PATH, BUS, "GetConnectionUnixProcessID", g_variant_new("(s)", p->owner), "(u)");
  if (!uid || !pid) return FALSE;
  guint32 actual_uid, actual_pid;
  g_variant_get(uid, "(u)", &actual_uid); g_variant_get(pid, "(u)", &actual_pid);
  if (actual_uid != p->uid || !actual_pid || actual_pid > INT_MAX ||
      (p->service_pid && actual_pid != p->service_pid)) return fail(p, "service-credentials", NULL);
  p->service_uid = actual_uid; p->service_pid = actual_pid;
  return TRUE;
}

static gboolean unlocked(Probe *p, const char *path, const char *interface) {
  g_autoptr(GVariant) value = property(p, path, interface, "Locked", "b");
  return value && (!g_variant_get_boolean(value) || fail(p, "locked", NULL));
}

static gboolean search(Probe *p, gboolean absent) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "SearchItems",
    g_variant_new("(@a{ss})", attributes(p)), "(aoao)");
  if (!reply) return FALSE;
  g_autoptr(GVariant) unlocked_items = g_variant_get_child_value(reply, 0);
  g_autoptr(GVariant) locked_items = g_variant_get_child_value(reply, 1);
  if (g_variant_n_children(locked_items) || g_variant_n_children(unlocked_items) != (absent ? 0u : 1u))
    return fail(p, "generation-search", NULL);
  if (!absent) {
    const char *path; g_variant_get_child(unlocked_items, 0, "&o", &path);
    if (strcmp(path, p->item)) return fail(p, "generation-item", NULL);
  }
  return TRUE;
}

static gboolean default_collection(Probe *p) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "default"), "(o)");
  g_autoptr(GVariant) temporary = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "session"), "(o)");
  if (!reply || !temporary) return FALSE;
  const char *path, *session_path;
  g_variant_get(reply, "(&o)", &path); g_variant_get(temporary, "(&o)", &session_path);
  if (!object_path(path) || !strcmp(path, "/org/freedesktop/secrets/collection/session") ||
      !strcmp(path, session_path) || (p->collection && strcmp(path, p->collection)))
    return fail(p, "durable-default-collection", NULL);
  if (!p->collection) p->collection = g_strdup(path);
  g_autoptr(GVariant) collections = property(p, ROOT, SECRET_IFACE "Service", "Collections", "ao");
  if (!collections || g_variant_n_children(collections) > 1024) return fail(p, "collection-inventory", NULL);
  guint matches = 0;
  for (gsize i = 0; i < g_variant_n_children(collections); i++) {
    const char *named; g_variant_get_child(collections, i, "&o", &named);
    if (!strcmp(named, p->collection)) matches++;
  }
  return (matches == 1 || fail(p, "default-collection-membership", NULL)) && unlocked(p, p->collection, SECRET_IFACE "Collection");
}

static gboolean read_item(Probe *p) {
  g_autoptr(GVariant) attrs = property(p, p->item, SECRET_IFACE "Item", "Attributes", "a{ss}");
  if (!attrs || g_variant_n_children(attrs) != 2) return fail(p, "item-attributes", NULL);
  gboolean schema = FALSE, generation = FALSE;
  GVariantIter iter; const char *key, *value; g_variant_iter_init(&iter, attrs);
  while (g_variant_iter_next(&iter, "{&s&s}", &key, &value)) {
    if (!strcmp(key, "xdg:schema") && !schema && !strcmp(value, SCHEMA)) schema = TRUE;
    else if (!strcmp(key, GENERATION) && !generation && !strcmp(value, p->generation)) generation = TRUE;
    else return fail(p, "item-attribute-binding", NULL);
  }
  g_autoptr(GVariant) items = property(p, p->collection, SECRET_IFACE "Collection", "Items", "ao");
  if (!items || g_variant_n_children(items) > 4096) return fail(p, "item-inventory", NULL);
  guint matches = 0;
  for (gsize i = 0; i < g_variant_n_children(items); i++) {
    const char *path; g_variant_get_child(items, i, "&o", &path); if (!strcmp(path, p->item)) matches++;
  }
  if (!schema || !generation || matches != 1 || !search(p, FALSE) || !unlocked(p, p->item, SECRET_IFACE "Item"))
    return fail(p, "item-binding", NULL);
  g_autoptr(GVariant) reply = call(p, p->owner, p->item, SECRET_IFACE "Item", "GetSecret", g_variant_new("(o)", p->session), "((oayays))");
  if (!reply) return FALSE;
  g_autoptr(GVariant) parameters = NULL; g_autoptr(GVariant) bytes = NULL;
  const char *session, *content_type;
  g_variant_get(reply, "((&o@ay@ay&s))", &session, &parameters, &bytes, &content_type);
  gsize count = 0; const guint8 *actual = g_variant_get_fixed_array(bytes, &count, 1);
  if (strcmp(session, p->session) || g_variant_n_children(parameters) || strcmp(content_type, CONTENT_TYPE) || count != 32)
    return fail(p, "secret-envelope", NULL);
  guint8 different = 0; for (gsize i = 0; i < 32; i++) different |= actual[i] ^ p->secret[i];
  if (different) return fail(p, "secret-comparison", NULL);
  p->readback = TRUE; p->owned = TRUE; return TRUE;
}

static gboolean delete_item(Probe *p) {
  g_autoptr(GVariant) reply = call(p, p->owner, p->item, SECRET_IFACE "Item", "Delete", NULL, "(o)");
  if (!reply) return FALSE;
  const char *prompt; g_variant_get(reply, "(&o)", &prompt);
  if (strcmp(prompt, "/")) return fail(p, "delete-prompt", NULL);
  p->deleted = TRUE;
  if (!search(p, TRUE)) return FALSE;
  p->absent = TRUE; return TRUE;
}

static gboolean external_only(GDBusAuthObserver *observer, const gchar *mechanism, gpointer data) {
  (void) observer; (void) data; return !strcmp(mechanism, "EXTERNAL");
}

static gboolean connect_bus(Probe *p) {
  char directory[64], address[96]; struct stat root, users, named;
  snprintf(directory, sizeof(directory), "/run/user/%lu", (unsigned long) p->uid);
  snprintf(address, sizeof(address), "unix:path=%s/bus", directory);
  if (lstat("/run", &root) || lstat("/run/user", &users) || !S_ISDIR(root.st_mode) || !S_ISDIR(users.st_mode) ||
      root.st_uid || users.st_uid || (root.st_mode & 0022) || (users.st_mode & 0022)) return fail(p, "runtime-ancestors", NULL);
  p->runtime_fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (p->runtime_fd < 0 || fstat(p->runtime_fd, &p->runtime) || p->runtime.st_uid != p->uid ||
      (p->runtime.st_mode & 07777) != 0700 || fstatat(p->runtime_fd, "bus", &p->socket, AT_SYMLINK_NOFOLLOW) ||
      !S_ISSOCK(p->socket.st_mode) || p->socket.st_uid != p->uid) return fail(p, "runtime-bus-ownership", NULL);
  g_autoptr(GDBusAuthObserver) observer = g_dbus_auth_observer_new();
  g_signal_connect(observer, "allow-mechanism", G_CALLBACK(external_only), NULL);
  GError *error = NULL;
  p->bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, observer, NULL, &error);
  if (!p->bus) return fail(p, "private-bus-connection", &error);
  g_dbus_connection_set_exit_on_close(p->bus, FALSE);
  GIOStream *stream = g_dbus_connection_get_stream(p->bus);
  if (!G_IS_SOCKET_CONNECTION(stream)) return fail(p, "unix-bus-stream", NULL);
  g_autoptr(GCredentials) peer = g_socket_get_credentials(g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)), &error);
  if (!peer) return fail(p, "bus-peer-credentials", &error);
  uid_t uid = g_credentials_get_unix_user(peer, &error);
  if (error) return fail(p, "bus-peer-uid", &error);
  pid_t pid = g_credentials_get_unix_pid(peer, &error);
  if (error) return fail(p, "bus-peer-pid", &error);
  if (uid != p->uid || pid <= 0 || lstat(directory, &named) || named.st_dev != p->runtime.st_dev || named.st_ino != p->runtime.st_ino ||
      fstatat(p->runtime_fd, "bus", &named, AT_SYMLINK_NOFOLLOW) || named.st_dev != p->socket.st_dev || named.st_ino != p->socket.st_ino ||
      !S_ISSOCK(named.st_mode) || named.st_uid != p->uid) return fail(p, "bus-peer-binding", NULL);
  const char *unique = g_dbus_connection_get_unique_name(p->bus);
  if (!unique || !g_dbus_is_unique_name(unique) || strlen(unique) > 255) return fail(p, "client-unique-name", NULL);
  p->unique = g_strdup(unique); return TRUE;
}

int main(int argc, char **argv) {
  Probe p = { .runtime_fd = -1, .uid = getuid() };
  if (unsetenv("G_DBUS_DEBUG")) { fail(&p, "disable-payload-debug", NULL); goto done; }
  gboolean consume = argc == 4 && !strcmp(argv[1], "consume");
  if ((!consume && !(argc == 3 && !strcmp(argv[1], "create"))) || !p.uid || geteuid() != p.uid ||
      strlen(argv[2]) != 64 || strspn(argv[2], "0123456789abcdef") != 64 || (consume && !object_path(argv[3]))) {
    fail(&p, "arguments", NULL); goto done;
  }
  p.generation = argv[2]; if (consume) p.item = g_strdup(argv[3]);
  gsize count = 0;
  for (;;) {
    struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
    int ready; do { ready = poll(&input, 1, TIMEOUT_MS); } while (ready < 0 && errno == EINTR);
    if (ready <= 0 || (input.revents & (POLLERR | POLLNVAL))) { fail(&p, "secret-input", NULL); goto done; }
    ssize_t n; do { n = read(STDIN_FILENO, p.secret + count, sizeof(p.secret) - count); } while (n < 0 && errno == EINTR);
    if (n < 0) { fail(&p, "secret-input", NULL); goto done; }
    if (!n) break;
    count += (gsize) n; if (count > 32) { fail(&p, "secret-input-length", NULL); goto done; }
  }
  if (count != 32) { fail(&p, "secret-input-length", NULL); goto done; }
  if (!connect_bus(&p) || !owner_current(&p) || !default_collection(&p)) goto done;
  {
    g_autoptr(GVariant) reply = call(&p, p.owner, ROOT, SECRET_IFACE "Service", "OpenSession",
      g_variant_new("(sv)", "plain", g_variant_new_string("")), "(vo)");
    if (!reply) goto done;
    const char *path; g_variant_get_child(reply, 1, "&o", &path);
    if (!object_path(path)) { fail(&p, "session-path", NULL); goto done; }
    p.session = g_strdup(path);
    g_autoptr(GVariant) box = g_variant_get_child_value(reply, 0);
    g_autoptr(GVariant) output = g_variant_get_variant(box);
    if (!g_variant_is_of_type(output, G_VARIANT_TYPE_STRING) || strcmp(g_variant_get_string(output, NULL), "")) {
      fail(&p, "plain-session-output", NULL); goto done;
    }
  }
  if (!consume) {
    if (!search(&p, TRUE)) goto done;
    GVariantBuilder properties; g_variant_builder_init(&properties, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&properties, "{sv}", SECRET_IFACE "Item.Label", g_variant_new_string("Cliq OS prerequisite probe"));
    g_variant_builder_add(&properties, "{sv}", SECRET_IFACE "Item.Attributes", attributes(&p));
    g_autoptr(GVariant) reply = call(&p, p.owner, p.collection, SECRET_IFACE "Collection", "CreateItem",
      g_variant_new("(@a{sv}(o@ay@ays)b)", g_variant_builder_end(&properties), p.session,
        g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1),
        g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, p.secret, 32, 1), CONTENT_TYPE, FALSE), "(oo)");
    if (!reply) goto done;
    const char *item, *prompt; g_variant_get(reply, "(&o&o)", &item, &prompt);
    if (!object_path(item)) { fail(&p, "created-item-path", NULL); goto done; }
    p.item = g_strdup(item); p.created = TRUE; p.owned = TRUE;
    if (strcmp(prompt, "/")) { fail(&p, "create-prompt", NULL); goto done; }
  }
  if (!read_item(&p) || (consume && !delete_item(&p)) || !owner_current(&p) || !default_collection(&p)) goto done;
done:
  if (p.session) {
    char *session = p.session; p.session = NULL;
    g_autoptr(GVariant) closed = call(&p, p.owner, session, SECRET_IFACE "Session", "Close", NULL, "()");
    g_free(session);
    if (!closed) p.failed = 1;
  }
  if (!p.failed && p.bus && !owner_current(&p)) p.failed = 1;
  if (p.runtime_fd >= 0) {
    int fd = p.runtime_fd; p.runtime_fd = -1; if (close(fd)) fail(&p, "runtime-close", NULL);
  }
  if (p.failed && p.owned && !p.deleted) (void) delete_item(&p);
  if (p.bus) {
    GError *error = NULL;
    p.connection_closed = g_dbus_connection_close_sync(p.bus, NULL, &error);
    if (!p.connection_closed) fail(&p, "connection-close", &error);
    g_object_unref(p.bus); p.bus = NULL;
  }
  volatile guint8 *wipe = p.secret; for (gsize i = 0; i < sizeof(p.secret); i++) wipe[i] = 0;
  if (!p.failed) {
    if (printf("{\"clientPid\":%ld,\"busUniqueName\":\"%s\",\"collection\":\"%s\",\"item\":\"%s\","
      "\"nameOwner\":\"%s\",\"serviceUid\":%u,\"servicePid\":%u,\"create\":%s,\"readback\":true,"
      "\"deleted\":%s,\"absent\":%s,\"connectionClosed\":true}\n", (long) getpid(), p.unique,
      p.collection, p.item, p.owner, p.service_uid, p.service_pid, p.created ? "true" : "false",
      p.deleted ? "true" : "false", p.absent ? "true" : "false") < 0 || fflush(stdout)) fail(&p, "report-output", NULL);
  }
  g_free(p.owner); g_free(p.unique); g_free(p.collection); g_free(p.item);
  return p.failed ? 1 : 0;
}
