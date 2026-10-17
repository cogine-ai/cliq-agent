/* Test-only observer for the actual installed credential journey. The closed
 * retain-systemd mode holds only unit-object references while exit is observed.
 * The prerequisite entry is renamed, never invoked: its create/delete and
 * failure-deletion paths are not part of this observer's command interface.
 * cc -std=c11 -O2 -Wall -Wextra -Werror credential-journey-observer.c \
 *   $(pkg-config --cflags --libs gio-2.0) -o credential-journey-observer
 */
#define main prerequisite_main
#include "../cliq-secret-service-probe.c"
#undef main
#include <signal.h>

#define OBSERVER_MAX_ITEMS 4096
#define OBSERVER_MAX_PATH_BYTES 32768

static gint observer_path_order(gconstpointer left, gconstpointer right) {
  return strcmp(*(const char *const *) left, *(const char *const *) right);
}

static GPtrArray *observer_inventory(Probe *p) {
  g_autoptr(GVariant) items = property(p, p->collection, SECRET_IFACE "Collection", "Items", "ao");
  if (!items || g_variant_n_children(items) > OBSERVER_MAX_ITEMS) {
    fail(p, "observer-item-inventory", NULL); return NULL;
  }
  g_autoptr(GPtrArray) paths = g_ptr_array_new_with_free_func(g_free);
  gsize bytes = 0, prefix = strlen(p->collection);
  for (gsize i = 0; i < g_variant_n_children(items); i++) {
    const char *named; g_variant_get_child(items, i, "&o", &named);
    if (!object_path(named) || strncmp(named, p->collection, prefix) || named[prefix] != '/' ||
        !named[prefix + 1] || strchr(named + prefix + 1, '/') ||
        (bytes += strlen(named)) > OBSERVER_MAX_PATH_BYTES) {
      fail(p, "observer-item-path", NULL); return NULL;
    }
    g_ptr_array_add(paths, g_strdup(named));
  }
  g_ptr_array_sort(paths, observer_path_order);
  for (guint i = 1; i < paths->len; i++) {
    if (!strcmp(g_ptr_array_index(paths, i - 1), g_ptr_array_index(paths, i))) {
      fail(p, "observer-duplicate-item", NULL); return NULL;
    }
  }
  return g_steal_pointer(&paths);
}

static gboolean observer_same_inventory(Probe *p, GPtrArray *before, GPtrArray *after) {
  if (before->len != after->len) return fail(p, "observer-inventory-changed", NULL);
  for (guint i = 0; i < before->len; i++) {
    if (strcmp(g_ptr_array_index(before, i), g_ptr_array_index(after, i)))
      return fail(p, "observer-inventory-changed", NULL);
  }
  return TRUE;
}

static gboolean observer_target(Probe *p, GPtrArray *items, const char *logical_id) {
  guint membership = 0;
  for (guint i = 0; i < items->len; i++) {
    if (!strcmp(g_ptr_array_index(items, i), p->item)) membership++;
  }
  if (membership != 1) return fail(p, "observer-item-membership", NULL);
  g_autoptr(GVariant) attrs = property(p, p->item, SECRET_IFACE "Item", "Attributes", "a{ss}");
  if (!attrs || g_variant_n_children(attrs) > 128) return fail(p, "observer-item-attributes", NULL);
  guint schema = 0, logical_matches = 0;
  GVariantIter iter; const char *key, *value; g_variant_iter_init(&iter, attrs);
  while (g_variant_iter_next(&iter, "{&s&s}", &key, &value)) {
    if (!strcmp(key, "xdg:schema")) {
      if (strcmp(value, SCHEMA)) return fail(p, "observer-item-schema", NULL);
      schema++;
    }
    /* The production attribute names remain producer-owned. Match the actual
     * logical id by value, without inventing an attribute-name contract. */
    if (!strcmp(value, logical_id)) logical_matches++;
  }
  if (schema != 1 || logical_matches != 1) return fail(p, "observer-logical-item-binding", NULL);
  return unlocked(p, p->item, SECRET_IFACE "Item");
}

static gboolean observer_input(Probe *p) {
  const gint64 deadline = g_get_monotonic_time() + TIMEOUT_MS * G_TIME_SPAN_MILLISECOND;
  gsize count = 0;
  for (;;) {
    const gint64 remaining = deadline - g_get_monotonic_time();
    if (remaining <= 0) return fail(p, "observer-secret-input", NULL);
    struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
    int ready = poll(&input, 1, (int) ((remaining + G_TIME_SPAN_MILLISECOND - 1) / G_TIME_SPAN_MILLISECOND));
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (input.revents & (POLLERR | POLLNVAL))) return fail(p, "observer-secret-input", NULL);
    ssize_t n = read(STDIN_FILENO, p->secret + count, sizeof(p->secret) - count);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return fail(p, "observer-secret-input", NULL);
    if (!n) break;
    count += (gsize) n;
    if (count > 32) return fail(p, "observer-secret-input-length", NULL);
  }
  return count == 32 || fail(p, "observer-secret-input-length", NULL);
}

static gboolean observer_session(Probe *p) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "OpenSession",
    g_variant_new("(sv)", "plain", g_variant_new_string("")), "(vo)");
  if (!reply) return FALSE;
  const char *named; g_variant_get_child(reply, 1, "&o", &named);
  if (!object_path(named)) return fail(p, "observer-session-path", NULL);
  p->session = g_strdup(named);
  g_autoptr(GVariant) box = g_variant_get_child_value(reply, 0);
  g_autoptr(GVariant) output = g_variant_get_variant(box);
  return (g_variant_is_of_type(output, G_VARIANT_TYPE_STRING) && !strcmp(g_variant_get_string(output, NULL), "")) ||
    fail(p, "observer-plain-session-output", NULL);
}

static gboolean observer_compare(Probe *p) {
  g_autoptr(GVariant) reply = call(p, p->owner, p->item, SECRET_IFACE "Item", "GetSecret",
    g_variant_new("(o)", p->session), "((oayays))");
  if (!reply) return FALSE;
  g_autoptr(GVariant) parameters = NULL; g_autoptr(GVariant) bytes = NULL;
  const char *session, *content_type;
  g_variant_get(reply, "((&o@ay@ay&s))", &session, &parameters, &bytes, &content_type);
  gsize count = 0; const guint8 *actual = g_variant_get_fixed_array(bytes, &count, 1);
  if (strcmp(session, p->session) || g_variant_n_children(parameters) || count != 32 || !actual)
    return fail(p, "observer-secret-envelope", NULL);
  if (strcmp(content_type, CONTENT_TYPE) && strcmp(content_type, "text/plain"))
    return fail(p, "observer-secret-content-type", NULL);
  guint8 different = 0;
  for (gsize i = 0; i < 32; i++) different |= actual[i] ^ p->secret[i];
  if (different) return fail(p, "observer-secret-comparison", NULL);
  p->readback = TRUE; return TRUE;
}

static gboolean observer_systemd_units(const char *supervisor, const char *keeper) {
  const char *supervisor_suffix = "-supervisor.service", *keeper_suffix = "-keeper.service";
  const gsize prefix = 5 + 64;
  if (strlen(supervisor) != prefix + strlen(supervisor_suffix) || strncmp(supervisor, "cliq-", 5) ||
      strcmp(supervisor + prefix, supervisor_suffix) || strlen(keeper) != prefix + strlen(keeper_suffix) ||
      memcmp(supervisor, keeper, prefix) || strcmp(keeper + prefix, keeper_suffix)) return FALSE;
  for (gsize i = 5; i < prefix; i++) {
    if (!((supervisor[i] >= '0' && supervisor[i] <= '9') || (supervisor[i] >= 'a' && supervisor[i] <= 'f'))) return FALSE;
  }
  return TRUE;
}

static gboolean observer_systemd_owner(Probe *p) {
  g_autoptr(GVariant) owner = call(p, BUS, BUS_PATH, BUS, "GetNameOwner",
    g_variant_new("(s)", "org.freedesktop.systemd1"), "(s)");
  if (!owner) return FALSE;
  const char *name; g_variant_get(owner, "(&s)", &name);
  if (!g_dbus_is_unique_name(name) || strlen(name) > 255 || (p->owner && strcmp(name, p->owner)))
    return fail(p, "observer-systemd-owner", NULL);
  if (!p->owner) p->owner = g_strdup(name);
  g_autoptr(GVariant) uid = call(p, BUS, BUS_PATH, BUS, "GetConnectionUnixUser", g_variant_new("(s)", p->owner), "(u)");
  g_autoptr(GVariant) pid = call(p, BUS, BUS_PATH, BUS, "GetConnectionUnixProcessID", g_variant_new("(s)", p->owner), "(u)");
  if (!uid || !pid) return FALSE;
  guint32 actual_uid, actual_pid;
  g_variant_get(uid, "(u)", &actual_uid); g_variant_get(pid, "(u)", &actual_pid);
  if (actual_uid != p->uid || !actual_pid || actual_pid > INT_MAX || (p->service_pid && actual_pid != p->service_pid))
    return fail(p, "observer-systemd-credentials", NULL);
  p->service_uid = actual_uid; p->service_pid = actual_pid;
  return TRUE;
}

static gboolean observer_systemd_release_input(Probe *p) {
  const gint64 deadline = g_get_monotonic_time() + TIMEOUT_MS * G_TIME_SPAN_MILLISECOND;
  guint8 bytes[2]; gsize count = 0;
  for (;;) {
    const gint64 remaining = deadline - g_get_monotonic_time();
    if (remaining <= 0) return fail(p, "observer-systemd-release-input", NULL);
    struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
    int ready = poll(&input, 1, (int) ((remaining + G_TIME_SPAN_MILLISECOND - 1) / G_TIME_SPAN_MILLISECOND));
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (input.revents & (POLLERR | POLLNVAL)) || !(input.revents & (POLLIN | POLLHUP)))
      return fail(p, "observer-systemd-release-input", NULL);
    ssize_t n = read(STDIN_FILENO, bytes + count, sizeof(bytes) - count);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return fail(p, "observer-systemd-release-input", NULL);
    if (g_get_monotonic_time() >= deadline) return fail(p, "observer-systemd-release-input", NULL);
    if (!n) return count == 1 || fail(p, "observer-systemd-release-frame", NULL);
    count += (gsize) n;
    if (count != 1 || bytes[0] != 'R') return fail(p, "observer-systemd-release-frame", NULL);
  }
}

static int observer_retain_systemd(int argc, char **argv) {
  Probe p = { .runtime_fd = -1, .uid = getuid() };
  const char *units[2] = { NULL, NULL }; guint retained = 0;
  if (unsetenv("G_DBUS_DEBUG") || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    fail(&p, "observer-systemd-initialize", NULL); goto done;
  }
  if (argc != 4 || !p.uid || geteuid() != p.uid || !observer_systemd_units(argv[2], argv[3])) {
    fail(&p, "observer-systemd-arguments", NULL); goto done;
  }
  units[0] = argv[2]; units[1] = argv[3];
  if (!connect_bus(&p) || !observer_systemd_owner(&p)) goto done;
  for (guint i = 0; i < 2; i++) {
    g_autoptr(GVariant) reply = call(&p, p.owner, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
      "RefUnit", g_variant_new("(s)", units[i]), "()");
    if (!reply) goto done;
    retained++;
  }
  if (!observer_systemd_owner(&p)) goto done;
  if (fputs("systemd_units_retained\n", stdout) == EOF || fflush(stdout)) {
    fail(&p, "observer-systemd-ready-output", NULL); goto done;
  }
  observer_systemd_release_input(&p);
done:
  while (retained) {
    g_autoptr(GVariant) reply = call(&p, p.owner, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
      "UnrefUnit", g_variant_new("(s)", units[--retained]), "()");
    if (!reply) p.failed = 1;
  }
  if (p.bus && p.owner && !observer_systemd_owner(&p)) p.failed = 1;
  if (p.bus) {
    GError *error = NULL;
    p.connection_closed = g_dbus_connection_close_sync(p.bus, NULL, &error);
    if (!p.connection_closed) fail(&p, "observer-systemd-connection-close", &error);
    g_object_unref(p.bus);
  }
  if (p.runtime_fd >= 0 && close(p.runtime_fd)) fail(&p, "observer-systemd-runtime-close", NULL);
  g_free(p.owner); g_free(p.unique);
  if (!p.failed && (fputs("systemd_units_released\n", stdout) == EOF || fflush(stdout)))
    fail(&p, "observer-systemd-release-output", NULL);
  return p.failed ? 1 : 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "retain-systemd")) return observer_retain_systemd(argc, argv);
  Probe p = { .runtime_fd = -1, .uid = getuid() };
  g_autoptr(GPtrArray) items = NULL;
  g_autoptr(GPtrArray) after = NULL;
  gboolean compare = argc == 4 && !strcmp(argv[1], "compare");
  if (unsetenv("G_DBUS_DEBUG")) { fail(&p, "disable-payload-debug", NULL); goto done; }
  if ((!compare && !(argc == 2 && !strcmp(argv[1], "list"))) || !p.uid || geteuid() != p.uid ||
      (compare && (!object_path(argv[2]) || !*argv[3] || strlen(argv[3]) > 1024 || !g_utf8_validate(argv[3], -1, NULL)))) {
    fail(&p, "observer-arguments", NULL); goto done;
  }
  if (compare) {
    p.item = g_strdup(argv[2]);
    if (!observer_input(&p)) goto done;
  }
  if (!connect_bus(&p) || !owner_current(&p) || !default_collection(&p)) goto done;
  items = observer_inventory(&p);
  if (!items) goto done;
  if (compare && (!observer_target(&p, items, argv[3]) || !observer_session(&p) || !observer_compare(&p))) goto done;
  if (!owner_current(&p) || !default_collection(&p)) goto done;
  after = observer_inventory(&p);
  if (!after || !observer_same_inventory(&p, items, after) ||
      (compare && !observer_target(&p, after, argv[3])) || !owner_current(&p)) goto done;
done:
  if (p.session) {
    char *session = p.session; p.session = NULL;
    g_autoptr(GVariant) closed = call(&p, p.owner, session, SECRET_IFACE "Session", "Close", NULL, "()");
    g_free(session);
    if (!closed) p.failed = 1;
  }
  if (!p.failed && p.bus && !owner_current(&p)) p.failed = 1;
  if (p.bus) {
    GError *error = NULL;
    p.connection_closed = g_dbus_connection_close_sync(p.bus, NULL, &error);
    if (!p.connection_closed) fail(&p, "connection-close", &error);
    g_object_unref(p.bus); p.bus = NULL;
  }
  if (p.runtime_fd >= 0) {
    int fd = p.runtime_fd; p.runtime_fd = -1;
    if (close(fd)) fail(&p, "runtime-close", NULL);
  }
  volatile guint8 *wipe = p.secret;
  for (gsize i = 0; i < sizeof(p.secret); i++) wipe[i] = 0;
  if (!p.failed) {
    gboolean written = printf("{\"clientPid\":%ld,\"busUniqueName\":\"%s\",\"nameOwner\":\"%s\","
      "\"serviceUid\":%u,\"servicePid\":%u,\"collection\":\"%s\",\"items\":[",
      (long) getpid(), p.unique, p.owner, p.service_uid, p.service_pid, p.collection) >= 0;
    for (guint i = 0; written && i < items->len; i++)
      written = printf("%s\"%s\"", i ? "," : "", (char *) g_ptr_array_index(items, i)) >= 0;
    if (written) written = printf("]%s", compare ? "" : ",\"connectionClosed\":true}\n") >= 0;
    if (written && compare) written = printf(",\"item\":\"%s\",\"readback\":true,\"logicalItemIdMatched\":true,\"connectionClosed\":true}\n", p.item) >= 0;
    if (!written || fflush(stdout)) fail(&p, "report-output", NULL);
  }
  g_free(p.owner); g_free(p.unique); g_free(p.collection); g_free(p.item);
  return p.failed ? 1 : 0;
}
