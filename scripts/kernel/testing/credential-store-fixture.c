/* Test-only MUTATION of the disposable user's actual GNOME Secret Service.
 * Not a read-only observer, credential AuthorityProof or recovery decision.
 * No secret input, key generation, item creation/deletion, SQL or provider.
 * The renamed prerequisite entry is never invoked by this command interface.
 * cc -std=c11 -O2 -Wall -Wextra -Werror credential-store-fixture.c \
 *   $(pkg-config --cflags --libs gio-2.0) -o credential-store-fixture
 * https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html
 */
#define main prerequisite_main
#include "../cliq-secret-service-probe.c"
#undef main
#include <pwd.h>

typedef struct {
  int home_fd;
  char home[PATH_MAX];
  struct stat home_identity;
  pid_t bus_pid;
  unsigned long long bus_ticks, service_ticks;
  char guid[33];
} Fixture;

static gboolean fixture_same(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
    left->st_uid == right->st_uid && left->st_gid == right->st_gid && left->st_mode == right->st_mode;
}

static gboolean fixture_close(Probe *p, int *descriptor) {
  int owned = *descriptor; *descriptor = -1;
  return owned < 0 || close(owned) == 0 || fail(p, "fixture-descriptor-close", NULL);
}

/* Refuse real account homes even if someone invokes this helper manually.
 * The parent is root-owned, non-writable by the fixture user; its home comes
 * from passwd, not HOME or an argv claim. Every directory is no-follow held. */
static gboolean fixture_home(Probe *p, Fixture *fixture) {
  uid_t real, effective, saved; gid_t real_gid, effective_gid, saved_gid;
  if (getresuid(&real, &effective, &saved) || getresgid(&real_gid, &effective_gid, &saved_gid) ||
      !real || real != p->uid || real != effective || real != saved || real_gid != effective_gid || real_gid != saved_gid)
    return fail(p, "fixture-account", NULL);
  struct passwd record, *found = NULL; char buffer[65536];
  if (getpwuid_r(p->uid, &record, buffer, sizeof(buffer), &found) || !found || record.pw_uid != p->uid ||
      record.pw_gid != effective_gid || !record.pw_dir || !record.pw_name || strlen(record.pw_dir) >= sizeof(fixture->home))
    return fail(p, "fixture-passwd", NULL);
  const char *prefix = "/var/tmp/cliq-systemd-probe.";
  if (strncmp(record.pw_dir, prefix, strlen(prefix))) return fail(p, "fixture-home-layout", NULL);
  const char *suffix = record.pw_dir + strlen(prefix);
  if (strlen(suffix) < 6 ||
      strcmp(suffix + strlen(suffix) - 5, "/home")) return fail(p, "fixture-home-layout", NULL);
  size_t count = strlen(suffix) - 5;
  if (!count || count > 64 || strspn(suffix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != count)
    return fail(p, "fixture-home-layout", NULL);
  char leaf[96], username[96];
  snprintf(leaf, sizeof(leaf), "cliq-systemd-probe.%.*s", (int)count, suffix);
  snprintf(username, sizeof(username), "cliq-probe-%.*s", (int)count, suffix);
  for (char *cursor = username; *cursor; cursor++) *cursor = g_ascii_tolower(*cursor);
  if (strcmp(username, record.pw_name)) return fail(p, "fixture-account-name", NULL);
  strcpy(fixture->home, record.pw_dir);
  int descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  const char *parts[] = {"var", "tmp", leaf, "home"}; gboolean valid = descriptor >= 0;
  for (size_t index = 0; valid && index < G_N_ELEMENTS(parts); index++) {
    int child = openat(descriptor, parts[index], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    valid = child >= 0 && fstat(child, &info) == 0 && S_ISDIR(info.st_mode);
    if (valid && index < 3) valid = info.st_uid == 0 &&
      (index == 1 ? (info.st_mode & 07777) == 01777 : !(info.st_mode & 0022));
    if (valid && index == 3) valid = info.st_uid == p->uid && (info.st_mode & 07777) == 0700;
    if (!fixture_close(p, &descriptor)) valid = FALSE;
    descriptor = child;
  }
  if (!valid || fstat(descriptor, &fixture->home_identity)) {
    fixture_close(p, &descriptor); return fail(p, "fixture-home-binding", NULL);
  }
  fixture->home_fd = descriptor; return TRUE;
}

static gboolean fixture_ticks(Probe *p, pid_t pid, unsigned long long *ticks) {
  char filename[64], body[4096]; struct stat info;
  snprintf(filename, sizeof(filename), "/proc/%ld/stat", (long)pid);
  int descriptor = open(filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (descriptor < 0) return fail(p, "fixture-process-open", NULL);
  ssize_t count;
  do { count = read(descriptor, body, sizeof(body) - 1); } while (count < 0 && errno == EINTR);
  gboolean valid = count > 0 && (size_t)count < sizeof(body) - 1 && fstat(descriptor, &info) == 0 &&
    S_ISREG(info.st_mode) && info.st_uid == p->uid;
  if (!fixture_close(p, &descriptor)) return FALSE;
  if (!valid) return fail(p, "fixture-process-read", NULL);
  body[count] = '\0'; char *cursor = strrchr(body, ')');
  if (!cursor || cursor[1] != ' ' || cursor[2] == 'Z' || cursor[2] == 'X' || cursor[2] == 'x')
    return fail(p, "fixture-process-state", NULL);
  cursor += 2;
  for (int field = 3; field < 22; field++) {
    cursor = strchr(cursor, ' '); if (!cursor) return fail(p, "fixture-process-fields", NULL); cursor++;
  }
  char *end; errno = 0; unsigned long long actual = strtoull(cursor, &end, 10);
  if (errno || end == cursor || *end != ' ' || !actual) return fail(p, "fixture-process-start", NULL);
  *ticks = actual; return TRUE;
}

static gboolean fixture_current(Probe *p, Fixture *fixture) {
  struct stat visible, held;
  if (fstat(fixture->home_fd, &held) || lstat(fixture->home, &visible) ||
      !fixture_same(&held, &fixture->home_identity) || !fixture_same(&visible, &fixture->home_identity))
    return fail(p, "fixture-home-changed", NULL);
  char directory[64]; snprintf(directory, sizeof(directory), "/run/user/%lu", (unsigned long)p->uid);
  if (fstat(p->runtime_fd, &held) || lstat(directory, &visible) || !fixture_same(&held, &p->runtime) ||
      !fixture_same(&visible, &p->runtime) || fstatat(p->runtime_fd, "bus", &visible, AT_SYMLINK_NOFOLLOW) ||
      !fixture_same(&visible, &p->socket) || g_dbus_connection_is_closed(p->bus))
    return fail(p, "fixture-bus-binding", NULL);
  const char *guid = g_dbus_connection_get_guid(p->bus);
  if (!guid || strlen(guid) != 32 || strspn(guid, "0123456789abcdef") != 32 ||
      (fixture->guid[0] && strcmp(guid, fixture->guid))) return fail(p, "fixture-bus-guid", NULL);
  if (!fixture->guid[0]) strcpy(fixture->guid, guid);
  GIOStream *stream = g_dbus_connection_get_stream(p->bus);
  if (!G_IS_SOCKET_CONNECTION(stream)) return fail(p, "fixture-bus-stream", NULL);
  GError *error = NULL;
  g_autoptr(GCredentials) credentials = g_socket_get_credentials(g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)), &error);
  if (!credentials) return fail(p, "fixture-bus-credentials", &error);
  uid_t uid = g_credentials_get_unix_user(credentials, &error);
  if (error) return fail(p, "fixture-bus-uid", &error);
  pid_t pid = g_credentials_get_unix_pid(credentials, &error);
  if (error) return fail(p, "fixture-bus-pid", &error);
  unsigned long long bus_ticks = 0, service_ticks = 0;
  if (uid != p->uid || pid <= 0 || (fixture->bus_pid && pid != fixture->bus_pid)) return fail(p, "fixture-bus-peer-changed", NULL);
  if (!fixture_ticks(p, pid, &bus_ticks) || !owner_current(p) || !fixture_ticks(p, p->service_pid, &service_ticks)) return FALSE;
  char image[PATH_MAX], executable[64]; struct stat actual_image, installed_image;
  snprintf(executable, sizeof(executable), "/proc/%u/exe", p->service_pid);
  ssize_t image_length = readlink(executable, image, sizeof(image) - 1);
  if (image_length <= 0 || (size_t)image_length >= sizeof(image) - 1) return fail(p, "fixture-service-image", NULL);
  image[image_length] = '\0';
  if (strcmp(image, "/usr/bin/gnome-keyring-daemon") || stat(executable, &actual_image) ||
      lstat("/usr/bin/gnome-keyring-daemon", &installed_image) || !S_ISREG(installed_image.st_mode) ||
      installed_image.st_uid || (installed_image.st_mode & 0022) || !fixture_same(&actual_image, &installed_image))
    return fail(p, "fixture-service-image", NULL);
  if ((fixture->bus_ticks && fixture->bus_ticks != bus_ticks) ||
      (fixture->service_ticks && fixture->service_ticks != service_ticks)) return fail(p, "fixture-lifetime-changed", NULL);
  fixture->bus_pid = pid; fixture->bus_ticks = bus_ticks; fixture->service_ticks = service_ticks; return TRUE;
}

static gboolean fixture_member(Probe *p, const char *target, gboolean locked, char **observed_target) {
  g_autoptr(GVariant) collections = property(p, ROOT, SECRET_IFACE "Service", "Collections", "ao");
  if (!collections || g_variant_n_children(collections) > 1024) return fail(p, "fixture-collection-inventory", NULL);
  guint matches = 0; const char *observed = NULL;
  for (gsize index = 0; index < g_variant_n_children(collections); index++) {
    const char *actual; g_variant_get_child(collections, index, "&o", &actual);
    if (!strcmp(actual, target)) { matches++; observed = actual; }
  }
  g_autoptr(GVariant) state = property(p, target, SECRET_IFACE "Collection", "Locked", "b");
  if (matches != 1 || !state || g_variant_get_boolean(state) != locked) return fail(p, "fixture-collection-state", NULL);
  *observed_target = g_strdup(observed); return TRUE;
}

static gboolean fixture_collection(Probe *p, gboolean locked) {
  g_autoptr(GVariant) session = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "session"), "(o)");
  if (!session) return FALSE;
  const char *temporary; g_variant_get(session, "(&o)", &temporary);
  if (!object_path(p->collection) || !strcmp(p->collection, "/org/freedesktop/secrets/collection/session") ||
      !strcmp(p->collection, temporary)) return fail(p, "fixture-durable-collection", NULL);
  char *actual = NULL;
  if (!fixture_member(p, p->collection, locked, &actual)) return FALSE;
  g_free(p->collection); p->collection = actual; return TRUE;
}

static gboolean fixture_session(Probe *p, const char *expected, char **observed) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "session"), "(o)");
  if (!reply) return FALSE;
  const char *actual; g_variant_get(reply, "(&o)", &actual);
  if (!object_path(actual) || !strcmp(actual, p->collection) || (expected && strcmp(actual, expected)))
    return fail(p, "fixture-session-alias", NULL);
  return fixture_member(p, actual, FALSE, observed);
}

static gboolean fixture_alias(Probe *p, const char *expected) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "default"), "(o)");
  if (!reply) return FALSE;
  const char *actual; g_variant_get(reply, "(&o)", &actual);
  return !strcmp(actual, expected) || fail(p, "fixture-default-alias", NULL);
}

static gboolean fixture_restore_ready(Probe *p, gboolean *change) {
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "ReadAlias", g_variant_new("(s)", "default"), "(o)");
  if (!reply) return FALSE;
  const char *actual; g_variant_get(reply, "(&o)", &actual);
  if (!strcmp(actual, "/")) { *change = TRUE; return TRUE; }
  if (!strcmp(actual, p->collection)) { *change = FALSE; return TRUE; }
  char *session = NULL;
  if (!fixture_session(p, actual, &session)) return FALSE;
  g_free(session); *change = TRUE; return TRUE;
}

static gboolean fixture_lock(Probe *p) {
  GVariantBuilder objects; g_variant_builder_init(&objects, G_VARIANT_TYPE("ao"));
  g_variant_builder_add(&objects, "o", p->collection);
  g_autoptr(GVariant) reply = call(p, p->owner, ROOT, SECRET_IFACE "Service", "Lock",
    g_variant_new("(@ao)", g_variant_builder_end(&objects)), "(aoo)");
  if (!reply) return FALSE;
  g_autoptr(GVariant) locked = g_variant_get_child_value(reply, 0);
  const char *prompt; g_variant_get_child(reply, 1, "&o", &prompt);
  if (strcmp(prompt, "/") || g_variant_n_children(locked) != 1) return fail(p, "fixture-lock-result", NULL);
  const char *actual; g_variant_get_child(locked, 0, "&o", &actual);
  return (!strcmp(actual, p->collection) || fail(p, "fixture-lock-target", NULL)) &&
    fixture_collection(p, TRUE) && fixture_alias(p, p->collection);
}

int main(int argc, char **argv) {
  Probe p = { .runtime_fd = -1, .uid = getuid() }; Fixture fixture = { .home_fd = -1 };
  gboolean locking = argc == 2 && !strcmp(argv[1], "lock");
  gboolean alias_session = argc == 2 && !strcmp(argv[1], "alias-session");
  gboolean restoring = argc == 3 && !strcmp(argv[1], "alias-restore");
  gboolean change_alias = TRUE; char *session = NULL;
  if (unsetenv("G_DBUS_DEBUG")) { fail(&p, "disable-payload-debug", NULL); goto done; }
  if ((!locking && !alias_session && !restoring) || !p.uid || geteuid() != p.uid || (restoring && !object_path(argv[2]))) {
    fail(&p, "fixture-arguments", NULL); goto done;
  }
  if (!fixture_home(&p, &fixture) || !connect_bus(&p) || !fixture_current(&p, &fixture)) goto done;
  if (restoring) {
    p.collection = g_strdup(argv[2]);
    if (!fixture_collection(&p, FALSE) || !fixture_restore_ready(&p, &change_alias)) goto done;
  } else if (!default_collection(&p)) goto done;
  if (alias_session && !fixture_session(&p, NULL, &session)) goto done;
  if (!fixture_current(&p, &fixture)) goto done;
  if (locking) {
    if (!fixture_lock(&p)) goto done;
  } else {
    if (change_alias) {
      g_autoptr(GVariant) changed = call(&p, p.owner, ROOT, SECRET_IFACE "Service", "SetAlias",
        g_variant_new("(so)", "default", alias_session ? session : p.collection), "()");
      if (!changed) goto done;
    }
    if (!fixture_alias(&p, alias_session ? session : p.collection) || !fixture_collection(&p, FALSE)) goto done;
    if (alias_session) {
      char *confirmed = NULL;
      if (!fixture_session(&p, session, &confirmed)) goto done;
      g_free(session); session = confirmed;
    }
  }
  if (!fixture_current(&p, &fixture)) goto done;
done:
  if (!p.failed && p.bus && !fixture_current(&p, &fixture)) p.failed = 1;
  if (p.bus) {
    GError *error = NULL; p.connection_closed = g_dbus_connection_close_sync(p.bus, NULL, &error);
    if (!p.connection_closed) fail(&p, "fixture-connection-close", &error);
    g_object_unref(p.bus); p.bus = NULL;
  }
  fixture_close(&p, &p.runtime_fd); fixture_close(&p, &fixture.home_fd);
  if (!p.failed && (printf("{\"diagnosticOnly\":true,\"action\":\"%s\",\"collection\":\"%s\",\"%s\":true,\"connectionClosed\":true}\n",
      locking ? "lock" : alias_session ? "alias-session" : "alias-restore", alias_session ? session : p.collection,
      locking ? "locked" : alias_session ? "defaultAliasSession" : "defaultAliasMatched") < 0 || fflush(stdout)))
    fail(&p, "fixture-report-output", NULL);
  g_free(p.owner); g_free(p.unique); g_free(p.collection); g_free(session);
  return p.failed ? 1 : 0;
}
