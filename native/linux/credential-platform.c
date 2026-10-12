/* Fixed installed Linux platform adapter. Platform observations are physical
 * data, never permission or a credential phase. No SQL, JavaScript, shell or
 * caller-selected bus/interface/method executes on its owning worker. */
#define _GNU_SOURCE
#include <node_api.h>
#include <uv.h>
#include <gio/gio.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TEXT_CAP 4097
#define SELECTOR_TEXT_CAP 65537
#define MAX_SECRET 65536
#define DEADLINE_SECONDS 30
#define BUS_NAME "org.freedesktop.DBus"
#define BUS_PATH "/org/freedesktop/DBus"
#define SECRET_NAME "org.freedesktop.secrets"
#define SECRET_ROOT "/org/freedesktop/secrets"
#define SECRET_INTERFACE "org.freedesktop.Secret."
#define MANAGER_NAME "org.freedesktop.systemd1"
#define MANAGER_PATH "/org/freedesktop/systemd1"
#define MANAGER_INTERFACE "org.freedesktop.systemd1.Manager"

enum operation { CREATE_COMPARE, INSPECT_SECRET, DELETE_KNOWN, RELOAD_MANAGER, START_UNIT, INSPECT_UNIT };
struct selector {
  char item_id[SELECTOR_TEXT_CAP], principal[SELECTOR_TEXT_CAP], root[65], operation[SELECTOR_TEXT_CAP], grant[SELECTOR_TEXT_CAP], target[65];
  uint64_t generation;
};
struct identity { uint64_t device, inode; };
struct service { char unique[256]; uid_t uid; pid_t pid; uint64_t ticks; };
struct platform_observation {
  char guid[33], collection[TEXT_CAP], item[TEXT_CAP];
  struct identity runtime, socket;
  uid_t uid; pid_t pid; uint64_t ticks;
  struct service service;
};
struct task {
  napi_env env; napi_async_work work; napi_deferred deferred; napi_async_cleanup_hook_handle cleanup_hook;
  enum operation operation; uid_t uid; gid_t gid; char home[PATH_MAX], unit[256], job[TEXT_CAP];
  struct selector selector; struct platform_observation expected, observed;
  unsigned char *secret; size_t secret_size;
  struct timespec deadline; pthread_t watchdog; pthread_mutex_t mutex; pthread_cond_t condition;
  bool mutex_ready, condition_ready, watchdog_started, finished, unsafe, env_closing;
  /* Only the main loop reads/writes these timer/completion flags. In
   * particular, expiry never races a worker write to error, unsafe or secret. */
  uv_timer_t deadline_timer;
  bool timer_initialized, timer_closing, timer_closed, work_complete, expired, cancel_requested, main_retirement_failed;
  GCancellable *cancel; GDBusConnection *bus; int runtime_fd;
  char session[TEXT_CAP]; struct stat runtime_identity, socket_identity;
  GVariant *unit_properties, *service_properties;
  const char *error; const char *result_kind;
  struct task *unretired_next;
};
static atomic_bool retirement_failed;
static atomic_bool job_in_flight;
static struct task *unretired_tasks;
static bool manager_shape(struct task *task);

static void wipe(void *memory, size_t count) { volatile unsigned char *bytes = memory; while (count--) *bytes++ = 0; }
static bool fail(struct task *task, const char *code) { if (!task->error) task->error = code; return false; }
static bool retired_close(struct task *task, int *descriptor) {
  int owned = *descriptor; *descriptor = -1;
  if (owned < 0 || close(owned) == 0) return true;
  task->unsafe = true; atomic_store(&retirement_failed, true); return fail(task, "resource_retirement");
}
static bool same_stat(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino && left->st_uid == right->st_uid &&
    left->st_gid == right->st_gid && left->st_mode == right->st_mode;
}
static bool copy_text(char *output, size_t capacity, const char *input) {
  if (!input || strlen(input) >= capacity || !g_utf8_validate(input, -1, NULL)) return false;
  memcpy(output, input, strlen(input) + 1); return true;
}
static bool canonical_path(const char *path) {
  if (path[0] != '/' || !path[1]) return false;
  const char *cursor = path + 1;
  while (*cursor) {
    const char *end = strchr(cursor, '/'); size_t count = end ? (size_t)(end - cursor) : strlen(cursor);
    if (!count || (count == 1 && cursor[0] == '.') || (count == 2 && !memcmp(cursor, "..", 2))) return false;
    if (!end) return true;
    cursor = end + 1;
  }
  return false;
}
static bool process_ticks(struct task *task, pid_t pid, uid_t uid, uint64_t *ticks) {
  char name[64], body[4096]; struct stat owner;
  snprintf(name, sizeof(name), "/proc/%ld/stat", (long)pid);
  int descriptor = open(name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return fail(task, "process_identity_unavailable");
  ssize_t count; do { count = read(descriptor, body, sizeof(body) - 1); } while (count < 0 && errno == EINTR);
  bool valid = count > 0 && (size_t)count < sizeof(body) - 1 && fstat(descriptor, &owner) == 0 && owner.st_uid == uid;
  if (!retired_close(task, &descriptor)) return false;
  if (!valid) return fail(task, "process_identity_unavailable");
  body[count] = '\0'; char *cursor = strrchr(body, ')');
  if (!cursor || cursor[1] != ' ' || cursor[2] == 'Z' || cursor[2] == 'X' || cursor[2] == 'x') return fail(task, "process_identity_unavailable");
  cursor += 2;
  for (int field = 3; field < 22; field++) { cursor = strchr(cursor, ' '); if (!cursor) return fail(task, "process_identity_unavailable"); cursor++; }
  char *end; errno = 0; unsigned long long result = strtoull(cursor, &end, 10);
  if (errno || end == cursor || *end != ' ' || !result) return fail(task, "process_identity_unavailable");
  *ticks = result; return true;
}
static bool current_user(uid_t *uid, gid_t *gid, char home[PATH_MAX]) {
  uid_t real, saved; gid_t real_gid, saved_gid;
  if (getresuid(&real, uid, &saved) || getresgid(&real_gid, gid, &saved_gid) || !*uid ||
      real != *uid || saved != *uid || real_gid != *gid || saved_gid != *gid) return false;
  struct passwd record, *found = NULL; char buffer[65536];
  if (getpwuid_r(*uid, &record, buffer, sizeof(buffer), &found) || !found || record.pw_uid != *uid ||
      !copy_text(home, PATH_MAX, record.pw_dir) || !canonical_path(home)) return false;
  return true;
}
static gboolean external_only(GDBusAuthObserver *observer, const gchar *mechanism, gpointer data) {
  (void)observer; (void)data; return !strcmp(mechanism, "EXTERNAL");
}
static int remaining(struct task *task) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
  int64_t milliseconds = (task->deadline.tv_sec - now.tv_sec) * 1000 + (task->deadline.tv_nsec - now.tv_nsec) / 1000000;
  return milliseconds > 0 && milliseconds <= INT_MAX ? (int)milliseconds : 0;
}
static GVariant *call(struct task *task, const char *destination, const char *path, const char *interface,
  const char *method, GVariant *parameters, const char *type) {
  int timeout = remaining(task);
  if (!timeout) { fail(task, "platform_timeout"); return NULL; }
  GError *error = NULL;
  GVariant *result = g_dbus_connection_call_sync(task->bus, destination, path, interface, method, parameters,
    G_VARIANT_TYPE(type), G_DBUS_CALL_FLAGS_NO_AUTO_START, timeout, task->cancel, &error);
  if (!result) fail(task, g_cancellable_is_cancelled(task->cancel) ? "platform_timeout" : "platform_store_unavailable");
  g_clear_error(&error); /* Remote error payloads never enter an exception. */
  return result;
}
static GVariant *property(struct task *task, const char *destination, const char *path,
  const char *interface, const char *name, const char *type) {
  GVariant *reply = call(task, destination, path, "org.freedesktop.DBus.Properties", "Get", g_variant_new("(ss)", interface, name), "(v)");
  if (!reply) return NULL;
  GVariant *box = g_variant_get_child_value(reply, 0), *value = g_variant_get_variant(box);
  g_variant_unref(box); g_variant_unref(reply);
  if (!g_variant_is_of_type(value, G_VARIANT_TYPE(type))) { g_variant_unref(value); fail(task, "platform_shape_mismatch"); return NULL; }
  return value;
}
static bool connect_bus(struct task *task) {
  char directory[64], address[96]; struct stat run, users, named;
  snprintf(directory, sizeof(directory), "/run/user/%lu", (unsigned long)task->uid);
  snprintf(address, sizeof(address), "unix:path=%s/bus", directory);
  if (lstat("/run", &run) || lstat("/run/user", &users) || !S_ISDIR(run.st_mode) || !S_ISDIR(users.st_mode) ||
      run.st_uid || users.st_uid || (run.st_mode & 0022) || (users.st_mode & 0022)) return fail(task, "platform_bus_unavailable");
  task->runtime_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (task->runtime_fd < 0 || fstat(task->runtime_fd, &task->runtime_identity) || !S_ISDIR(task->runtime_identity.st_mode) ||
      task->runtime_identity.st_uid != task->uid || (task->runtime_identity.st_mode & 07777) != 0700 ||
      fstatat(task->runtime_fd, "bus", &task->socket_identity, AT_SYMLINK_NOFOLLOW) ||
      !S_ISSOCK(task->socket_identity.st_mode) || task->socket_identity.st_uid != task->uid) return fail(task, "platform_bus_unavailable");
  GDBusAuthObserver *observer = g_dbus_auth_observer_new();
  g_signal_connect(observer, "allow-mechanism", G_CALLBACK(external_only), NULL);
  GError *error = NULL;
  task->bus = g_dbus_connection_new_for_address_sync(address, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, observer, task->cancel, &error);
  g_object_unref(observer); g_clear_error(&error);
  if (!task->bus) return fail(task, "platform_bus_unavailable");
  g_dbus_connection_set_exit_on_close(task->bus, FALSE);
  GIOStream *stream = g_dbus_connection_get_stream(task->bus);
  if (!G_IS_SOCKET_CONNECTION(stream)) return fail(task, "platform_bus_identity");
  GCredentials *credentials = g_socket_get_credentials(g_socket_connection_get_socket(G_SOCKET_CONNECTION(stream)), &error);
  if (!credentials) { g_clear_error(&error); return fail(task, "platform_bus_identity"); }
  uid_t uid = g_credentials_get_unix_user(credentials, &error);
  pid_t pid = error ? -1 : g_credentials_get_unix_pid(credentials, &error);
  g_object_unref(credentials); bool valid = !error && uid == task->uid && pid > 0;
  g_clear_error(&error);
  if (!valid || lstat(directory, &named) || !same_stat(&task->runtime_identity, &named) ||
      fstatat(task->runtime_fd, "bus", &named, AT_SYMLINK_NOFOLLOW) || !same_stat(&task->socket_identity, &named)) return fail(task, "platform_bus_identity");
  struct platform_observation *value = &task->observed;
  const char *guid = g_dbus_connection_get_guid(task->bus);
  if (!guid || strlen(guid) != 32 || strspn(guid, "0123456789abcdef") != 32 || !copy_text(value->guid, sizeof(value->guid), guid) ||
      !process_ticks(task, pid, uid, &value->ticks)) return fail(task, "platform_bus_identity");
  value->uid = uid; value->pid = pid;
  value->runtime = (struct identity){task->runtime_identity.st_dev, task->runtime_identity.st_ino};
  value->socket = (struct identity){task->socket_identity.st_dev, task->socket_identity.st_ino};
  return true;
}
static bool observe_owner(struct task *task, const char *name, struct service *expected) {
  GVariant *reply = call(task, BUS_NAME, BUS_PATH, BUS_NAME, "GetNameOwner", g_variant_new("(s)", name), "(s)");
  if (!reply) return false;
  const char *unique; g_variant_get(reply, "(&s)", &unique);
  char owner[256]; bool valid = g_dbus_is_unique_name(unique) && copy_text(owner, sizeof(owner), unique);
  g_variant_unref(reply);
  if (!valid) return fail(task, "platform_service_identity");
  reply = call(task, BUS_NAME, BUS_PATH, BUS_NAME, "GetConnectionUnixUser", g_variant_new("(s)", owner), "(u)");
  if (!reply) return false;
  guint32 uid; g_variant_get(reply, "(u)", &uid); g_variant_unref(reply);
  reply = call(task, BUS_NAME, BUS_PATH, BUS_NAME, "GetConnectionUnixProcessID", g_variant_new("(s)", owner), "(u)");
  if (!reply) return false;
  guint32 pid; g_variant_get(reply, "(u)", &pid); g_variant_unref(reply);
  uint64_t ticks;
  if (uid != task->uid || !pid || pid > INT_MAX || !process_ticks(task, (pid_t)pid, uid, &ticks)) return fail(task, "platform_service_identity");
  if (expected->unique[0]) {
    if (strcmp(expected->unique, owner) || expected->uid != uid || expected->pid != (pid_t)pid || expected->ticks != ticks)
      return fail(task, "platform_service_changed");
  } else { copy_text(expected->unique, sizeof(expected->unique), owner); expected->uid = uid; expected->pid = (pid_t)pid; expected->ticks = ticks; }
  return true;
}
static bool bus_current(struct task *task) {
  struct stat held, named; uint64_t ticks;
  char directory[64]; snprintf(directory, sizeof(directory), "/run/user/%lu", (unsigned long)task->uid);
  return (!g_dbus_connection_is_closed(task->bus) && fstat(task->runtime_fd, &held) == 0 && same_stat(&held, &task->runtime_identity) &&
    lstat(directory, &named) == 0 && same_stat(&named, &task->runtime_identity) &&
    fstatat(task->runtime_fd, "bus", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_stat(&named, &task->socket_identity) &&
    process_ticks(task, task->observed.pid, task->uid, &ticks) && ticks == task->observed.ticks) || fail(task, "platform_bus_changed");
}
static bool unlocked(struct task *task, const char *path, const char *interface) {
  GVariant *value = property(task, task->observed.service.unique, path, interface, "Locked", "b");
  if (!value) return false;
  bool valid = !g_variant_get_boolean(value); g_variant_unref(value);
  return valid || fail(task, "platform_store_locked");
}
static bool default_collection(struct task *task) {
  const char *destination = task->observed.service.unique;
  GVariant *reply = call(task, destination, SECRET_ROOT, SECRET_INTERFACE "Service", "ReadAlias", g_variant_new("(s)", "default"), "(o)");
  if (!reply) return false;
  const char *path; g_variant_get(reply, "(&o)", &path); char actual[TEXT_CAP];
  bool valid = copy_text(actual, sizeof(actual), path) && strcmp(actual, "/") && strcmp(actual, SECRET_ROOT "/collection/session");
  g_variant_unref(reply);
  reply = call(task, destination, SECRET_ROOT, SECRET_INTERFACE "Service", "ReadAlias", g_variant_new("(s)", "session"), "(o)");
  if (!reply) return false;
  g_variant_get(reply, "(&o)", &path); valid = valid && strcmp(actual, path); g_variant_unref(reply);
  if (!valid || (task->observed.collection[0] && strcmp(task->observed.collection, actual))) return fail(task, "platform_collection_changed");
  copy_text(task->observed.collection, sizeof(task->observed.collection), actual);
  GVariant *collections = property(task, destination, SECRET_ROOT, SECRET_INTERFACE "Service", "Collections", "ao");
  if (!collections) return false;
  size_t count = g_variant_n_children(collections), matches = 0;
  if (count > 1024) { g_variant_unref(collections); return fail(task, "platform_inventory_bound"); }
  for (size_t i = 0; i < count; i++) { g_variant_get_child(collections, i, "&o", &path); if (!strcmp(path, actual)) matches++; }
  g_variant_unref(collections);
  return (matches == 1 || fail(task, "platform_collection_identity")) && unlocked(task, actual, SECRET_INTERFACE "Collection");
}
static const char *attribute_keys[] = {"xdg:schema", "cliq:namespace", "cliq:item-id", "cliq:principal-id", "cliq:state-root",
  "cliq:operation-id", "cliq:grant-id", "cliq:secret-generation", "cliq:target-digest"};
static void attribute_values(struct task *task, const char *values[9], char generation[32]) {
  snprintf(generation, 32, "%llu", (unsigned long long)task->selector.generation);
  values[0] = "org.freedesktop.Secret.Generic"; values[1] = "ai.cogine.cliq.credentials.v1";
  values[2] = task->selector.item_id; values[3] = task->selector.principal; values[4] = task->selector.root;
  values[5] = task->selector.operation; values[6] = task->selector.grant; values[7] = generation; values[8] = task->selector.target;
}
static GVariant *attributes(struct task *task) {
  GVariantBuilder builder; g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));
  const char *values[9]; char generation[32]; attribute_values(task, values, generation);
  for (size_t i = 0; i < 9; i++) g_variant_builder_add(&builder, "{ss}", attribute_keys[i], values[i]);
  return g_variant_builder_end(&builder);
}
static bool search_item(struct task *task, bool *found) {
  GVariant *reply = call(task, task->observed.service.unique, SECRET_ROOT, SECRET_INTERFACE "Service", "SearchItems",
    g_variant_new("(@a{ss})", attributes(task)), "(aoao)");
  if (!reply) return false;
  GVariant *unlocked_items = g_variant_get_child_value(reply, 0), *locked_items = g_variant_get_child_value(reply, 1);
  size_t count = g_variant_n_children(unlocked_items), locked_count = g_variant_n_children(locked_items);
  bool valid = !locked_count && count <= 1; *found = count == 1;
  if (valid && *found) { const char *path; g_variant_get_child(unlocked_items, 0, "&o", &path); valid = copy_text(task->observed.item, sizeof(task->observed.item), path); }
  if (valid && !*found) task->observed.item[0] = '\0';
  g_variant_unref(unlocked_items); g_variant_unref(locked_items); g_variant_unref(reply);
  return valid || fail(task, locked_count ? "platform_store_locked" : "platform_item_ambiguous");
}
static bool verify_item(struct task *task) {
  const char *destination = task->observed.service.unique;
  GVariant *actual = property(task, destination, task->observed.item, SECRET_INTERFACE "Item", "Attributes", "a{ss}");
  if (!actual) return false;
  const char *values[9]; char generation[32]; attribute_values(task, values, generation);
  bool valid = g_variant_n_children(actual) == 9;
  for (size_t i = 0; valid && i < 9; i++) { const char *value; valid = g_variant_lookup(actual, attribute_keys[i], "&s", &value) && !strcmp(value, values[i]); }
  g_variant_unref(actual);
  GVariant *items = property(task, destination, task->observed.collection, SECRET_INTERFACE "Collection", "Items", "ao");
  if (!items) return false;
  size_t count = g_variant_n_children(items), matches = 0;
  if (count > 4096) { g_variant_unref(items); return fail(task, "platform_inventory_bound"); }
  for (size_t i = 0; i < count; i++) { const char *path; g_variant_get_child(items, i, "&o", &path); if (!strcmp(path, task->observed.item)) matches++; }
  g_variant_unref(items);
  return ((valid && matches == 1) || fail(task, "platform_item_binding")) && unlocked(task, task->observed.item, SECRET_INTERFACE "Item");
}
static bool open_session(struct task *task) {
  GVariant *reply = call(task, task->observed.service.unique, SECRET_ROOT, SECRET_INTERFACE "Service", "OpenSession",
    g_variant_new("(sv)", "plain", g_variant_new_string("")), "(vo)");
  if (!reply) return false;
  GVariant *box = g_variant_get_child_value(reply, 0), *value = g_variant_get_variant(box);
  const char *session; g_variant_get_child(reply, 1, "&o", &session);
  bool valid = g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) && !strcmp(g_variant_get_string(value, NULL), "") &&
    strcmp(session, "/") && copy_text(task->session, sizeof(task->session), session);
  g_variant_unref(value); g_variant_unref(box); g_variant_unref(reply);
  return valid || fail(task, "platform_session_identity");
}
static bool create_compare(struct task *task) {
  bool found; if (!search_item(task, &found)) return false;
  if (found) return fail(task, "platform_item_exists");
  if (!open_session(task)) return false;
  GVariantBuilder properties; g_variant_builder_init(&properties, G_VARIANT_TYPE("a{sv}"));
  g_variant_builder_add(&properties, "{sv}", SECRET_INTERFACE "Item.Label", g_variant_new_string("Cliq credential"));
  g_variant_builder_add(&properties, "{sv}", SECRET_INTERFACE "Item.Attributes", attributes(task));
  GVariant *reply = call(task, task->observed.service.unique, task->observed.collection, SECRET_INTERFACE "Collection", "CreateItem",
    g_variant_new("(@a{sv}(o@ay@ays)b)", g_variant_builder_end(&properties), task->session,
      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1),
      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, task->secret, task->secret_size, 1), "application/octet-stream", FALSE), "(oo)");
  if (!reply) return false;
  const char *item, *prompt; g_variant_get(reply, "(&o&o)", &item, &prompt); char named[TEXT_CAP];
  bool valid = strcmp(item, "/") && !strcmp(prompt, "/") && copy_text(named, sizeof(named), item);
  g_variant_unref(reply);
  if (!valid) return fail(task, "platform_prompt_required");
  if (!search_item(task, &found) || !found || strcmp(named, task->observed.item) || !verify_item(task)) return fail(task, "platform_item_binding");
  reply = call(task, task->observed.service.unique, task->observed.item, SECRET_INTERFACE "Item", "GetSecret", g_variant_new("(o)", task->session), "((oayays))");
  if (!reply) return false;
  GVariant *parameters, *bytes; const char *session, *content_type;
  g_variant_get(reply, "((&o@ay@ay&s))", &session, &parameters, &bytes, &content_type);
  gsize count = 0; const unsigned char *actual = g_variant_get_fixed_array(bytes, &count, 1);
  valid = !strcmp(session, task->session) && !g_variant_n_children(parameters) && count == task->secret_size &&
    (!strcmp(content_type, "application/octet-stream") || !strcmp(content_type, "text/plain"));
  unsigned char different = 0;
  if (valid) for (size_t i = 0; i < count; i++) different |= actual[i] ^ task->secret[i];
  g_variant_unref(parameters); g_variant_unref(bytes); g_variant_unref(reply);
  return (valid && !different) || fail(task, "platform_secret_roundtrip_failed");
}
static bool expected_platform(struct task *task) {
  const struct platform_observation *a = &task->expected, *b = &task->observed;
  return (!strcmp(a->guid, b->guid) && a->runtime.device == b->runtime.device && a->runtime.inode == b->runtime.inode &&
    a->socket.device == b->socket.device && a->socket.inode == b->socket.inode && a->uid == b->uid && a->pid == b->pid && a->ticks == b->ticks &&
    !strcmp(a->service.unique, b->service.unique) && a->service.uid == b->service.uid && a->service.pid == b->service.pid &&
    a->service.ticks == b->service.ticks && !strcmp(a->collection, b->collection) && !strcmp(a->item, b->item)) || fail(task, "platform_observation_changed");
}
static bool secret_operation(struct task *task) {
  if (!observe_owner(task, SECRET_NAME, &task->observed.service) || !default_collection(task)) return false;
  if (task->operation == CREATE_COMPARE) {
    if (!create_compare(task)) return false;
    task->result_kind = "stored";
  } else {
    bool found; if (!search_item(task, &found)) return false;
    if (found && !verify_item(task)) return false;
    if (task->operation == INSPECT_SECRET) {
      if (!found || !expected_platform(task)) return fail(task, "platform_observation_changed");
      task->result_kind = "present";
    } else if (found) {
      GVariant *reply = call(task, task->observed.service.unique, task->observed.item, SECRET_INTERFACE "Item", "Delete", NULL, "(o)");
      if (!reply) return false;
      const char *prompt; g_variant_get(reply, "(&o)", &prompt); bool valid = !strcmp(prompt, "/"); g_variant_unref(reply);
      if (!valid) return fail(task, "delete_denied");
      if (!search_item(task, &found) || found) return fail(task, "delete_failed");
      task->result_kind = "deleted";
    } else task->result_kind = "absent";
  }
  return default_collection(task) && observe_owner(task, SECRET_NAME, &task->observed.service) && bus_current(task);
}

static GVariant *get_all(struct task *task, const char *path, const char *interface) {
  GVariant *reply = call(task, task->observed.service.unique, path, "org.freedesktop.DBus.Properties", "GetAll", g_variant_new("(s)", interface), "(a{sv})");
  if (!reply) return NULL;
  GVariant *value = g_variant_get_child_value(reply, 0); g_variant_unref(reply);
  if (g_variant_n_children(value) > 1024) { g_variant_unref(value); fail(task, "platform_inventory_bound"); return NULL; }
  return value;
}
static bool manager_operation(struct task *task) {
  if (!observe_owner(task, MANAGER_NAME, &task->observed.service)) return false;
  const char *destination = task->observed.service.unique;
  if (task->operation == RELOAD_MANAGER) {
    GVariant *reply = call(task, destination, MANAGER_PATH, MANAGER_INTERFACE, "Reload", NULL, "()");
    if (!reply) return false;
    g_variant_unref(reply);
  } else {
    if (task->operation == START_UNIT) {
      GVariant *reply = call(task, destination, MANAGER_PATH, MANAGER_INTERFACE, "StartUnit", g_variant_new("(ss)", task->unit, "fail"), "(o)");
      if (!reply) return false;
      const char *job; g_variant_get(reply, "(&o)", &job); bool valid = copy_text(task->job, sizeof(task->job), job); g_variant_unref(reply);
      if (!valid) return fail(task, "platform_shape_mismatch");
    }
    /* LoadUnit only loads an existing fixed profile into the manager. It does
     * not start it; GetUnit alone rejects a valid inactive newly installed
     * profile, before the client can inspect that profile safely. */
    GVariant *reply = call(task, destination, MANAGER_PATH, MANAGER_INTERFACE,
      task->operation == INSPECT_UNIT ? "LoadUnit" : "GetUnit", g_variant_new("(s)", task->unit), "(o)");
    if (!reply) return false;
    const char *unit; g_variant_get(reply, "(&o)", &unit); char locator[TEXT_CAP]; bool valid = copy_text(locator, sizeof(locator), unit); g_variant_unref(reply);
    if (!valid) return fail(task, "platform_shape_mismatch");
    task->unit_properties = get_all(task, locator, "org.freedesktop.systemd1.Unit");
    task->service_properties = get_all(task, locator, "org.freedesktop.systemd1.Service");
    if (!task->unit_properties || !task->service_properties || !manager_shape(task)) return false;
  }
  return observe_owner(task, MANAGER_NAME, &task->observed.service) && bus_current(task);
}
static void *watchdog(void *data) {
  struct task *task = data;
  if (pthread_mutex_lock(&task->mutex)) {
    atomic_store(&retirement_failed, true); g_cancellable_cancel(task->cancel); return NULL;
  }
  int status = 0;
  while (!task->finished && !status) status = pthread_cond_timedwait(&task->condition, &task->mutex, &task->deadline);
  bool expired = !task->finished;
  int unlocked = pthread_mutex_unlock(&task->mutex);
  if ((status && status != ETIMEDOUT) || unlocked) {
    atomic_store(&retirement_failed, true); expired = true;
  }
  if (expired) g_cancellable_cancel(task->cancel);
  return NULL;
}
static void execute(napi_env env, void *data) {
  (void)env; struct task *task = data;
  if (atomic_load(&retirement_failed) || !remaining(task)) { fail(task, "platform_timeout"); goto done; }
  if (pthread_create(&task->watchdog, NULL, watchdog, task)) { fail(task, "platform_worker_unavailable"); goto done; }
  task->watchdog_started = true;
  if (connect_bus(task)) {
    if (task->operation <= DELETE_KNOWN) (void)secret_operation(task);
    else (void)manager_operation(task);
  }
done:
  if (task->secret) { wipe(task->secret, task->secret_size); free(task->secret); task->secret = NULL; }
  /* A positive client disconnect closes its connection-bound Secret Service
   * session. No remote Close failure can justify keeping the bus unowned. */
  if (task->bus) {
    GError *error = NULL;
    if (!g_dbus_connection_is_closed(task->bus) && !g_dbus_connection_close_sync(task->bus, task->cancel, &error)) {
      task->unsafe = true; atomic_store(&retirement_failed, true); fail(task, "resource_retirement");
    }
    g_clear_error(&error);
    if (!task->unsafe) { g_object_unref(task->bus); task->bus = NULL; }
  }
  (void)retired_close(task, &task->runtime_fd);
  if (task->watchdog_started) {
    int locked = pthread_mutex_lock(&task->mutex), signalled = 0, unlocked = 0;
    if (!locked) {
      task->finished = true;
      signalled = pthread_cond_signal(&task->condition);
      unlocked = pthread_mutex_unlock(&task->mutex);
    }
    if (locked || signalled || unlocked) {
      task->unsafe = true; atomic_store(&retirement_failed, true); g_cancellable_cancel(task->cancel); fail(task, "resource_retirement");
    }
    if (pthread_join(task->watchdog, NULL)) { task->unsafe = true; atomic_store(&retirement_failed, true); fail(task, "resource_retirement"); }
  }
  if (atomic_load(&retirement_failed)) { task->unsafe = true; fail(task, "resource_retirement"); }
}

static bool member(napi_env env, napi_value value, const char *key, napi_value *result) {
  return napi_get_named_property(env, value, key, result) == napi_ok;
}
static bool field_text(napi_env env, napi_value value, const char *key, char *output, size_t capacity) {
  napi_value property; size_t length;
  return member(env, value, key, &property) && napi_get_value_string_utf8(env, property, NULL, 0, &length) == napi_ok &&
    length > 0 && length < capacity && napi_get_value_string_utf8(env, property, output, capacity, &length) == napi_ok &&
    strlen(output) == length && g_utf8_validate(output, -1, NULL);
}
static bool field_u32(napi_env env, napi_value value, const char *key, uint32_t *output) {
  napi_value property; double number;
  if (!member(env, value, key, &property) || napi_get_value_double(env, property, &number) != napi_ok ||
      !isfinite(number) || number < 1 || number > UINT32_MAX || number != (uint32_t)number) return false;
  *output = (uint32_t)number; return true;
}
static bool fields(napi_env env, napi_value value, const char *const *keys, size_t count) {
  napi_value names; uint32_t length; bool array;
  if (napi_is_array(env, value, &array) != napi_ok || array ||
      napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
      napi_get_array_length(env, names, &length) != napi_ok || length != count) return false;
  for (size_t i = 0; i < count; i++) {
    bool present; napi_value key;
    if (napi_create_string_utf8(env, keys[i], NAPI_AUTO_LENGTH, &key) != napi_ok ||
        napi_has_own_property(env, value, key, &present) != napi_ok || !present) return false;
  }
  return true;
}
static bool field_generation(napi_env env, napi_value value, uint64_t *output) {
  napi_value property; double number;
  if (!member(env, value, "secretGeneration", &property) || napi_get_value_double(env, property, &number) != napi_ok ||
      !isfinite(number) || number < 1 || number > 9007199254740991.0 || number != (uint64_t)number) return false;
  *output = (uint64_t)number; return true;
}
static bool parse_selector(napi_env env, napi_value value, struct selector *selector) {
  const char *keys[] = {"itemId", "ownerPrincipalId", "stateRootIdentityDigest", "creatingOperationId", "credentialGrantId", "secretGeneration", "credentialTargetDigest"};
  return fields(env, value, keys, 7) && field_text(env, value, "itemId", selector->item_id, sizeof(selector->item_id)) &&
    field_text(env, value, "ownerPrincipalId", selector->principal, sizeof(selector->principal)) &&
    field_text(env, value, "stateRootIdentityDigest", selector->root, sizeof(selector->root)) &&
    strlen(selector->root) == 64 && strspn(selector->root, "0123456789abcdef") == 64 &&
    field_text(env, value, "creatingOperationId", selector->operation, sizeof(selector->operation)) &&
    field_text(env, value, "credentialGrantId", selector->grant, sizeof(selector->grant)) &&
    field_generation(env, value, &selector->generation) &&
    field_text(env, value, "credentialTargetDigest", selector->target, sizeof(selector->target)) &&
    strlen(selector->target) == 64 && strspn(selector->target, "0123456789abcdef") == 64;
}
static bool field_decimal(napi_env env, napi_value value, const char *key, uint64_t *output) {
  char text[32], *end; if (!field_text(env, value, key, text, sizeof(text)) || strspn(text, "0123456789") != strlen(text) ||
      (text[0] == '0' && text[1])) return false;
  errno = 0; *output = strtoull(text, &end, 10); return !errno && !*end;
}
static bool field_ticks(napi_env env, napi_value value, uint64_t *output) {
  char text[128], *end; const char *prefix = "linux-proc-start-ticks:";
  if (!field_text(env, value, "processStartToken", text, sizeof(text)) || strncmp(text, prefix, strlen(prefix))) return false;
  const char *digits = text + strlen(prefix); errno = 0; *output = strtoull(digits, &end, 10);
  return !errno && *output && !*end && strspn(digits, "0123456789") == strlen(digits) && digits[0] != '0';
}
static bool same_selector(const struct selector *left, const struct selector *right) {
  return left->generation == right->generation && !strcmp(left->item_id, right->item_id) &&
    !strcmp(left->principal, right->principal) && !strcmp(left->root, right->root) &&
    !strcmp(left->operation, right->operation) && !strcmp(left->grant, right->grant) && !strcmp(left->target, right->target);
}
static bool parse_expected(napi_env env, napi_value value, struct task *task) {
  napi_value bus, service, runtime, socket, selector; uint32_t uid, pid; struct selector original = {0};
  if (!member(env, value, "selector", &selector) || !parse_selector(env, selector, &original) || !same_selector(&original, &task->selector) ||
      !member(env, value, "bus", &bus) || !member(env, value, "service", &service) ||
      !member(env, bus, "runtime", &runtime) || !member(env, bus, "socket", &socket)) return false;
  struct platform_observation *expected = &task->expected;
  if (!field_text(env, bus, "guid", expected->guid, sizeof(expected->guid)) || strlen(expected->guid) != 32 ||
      !field_decimal(env, runtime, "deviceId", &expected->runtime.device) || !field_decimal(env, runtime, "fileId", &expected->runtime.inode) ||
      !field_decimal(env, socket, "deviceId", &expected->socket.device) || !field_decimal(env, socket, "fileId", &expected->socket.inode) ||
      !field_u32(env, bus, "uid", &uid) || !field_u32(env, bus, "pid", &pid) || pid > INT_MAX || !field_ticks(env, bus, &expected->ticks)) return false;
  expected->uid = uid; expected->pid = (pid_t)pid;
  if (!field_text(env, service, "uniqueName", expected->service.unique, sizeof(expected->service.unique)) ||
      !field_u32(env, service, "uid", &uid) || !field_u32(env, service, "pid", &pid) || pid > INT_MAX || !field_ticks(env, service, &expected->service.ticks) ||
      !field_text(env, value, "collectionPath", expected->collection, sizeof(expected->collection)) ||
      !field_text(env, value, "itemPath", expected->item, sizeof(expected->item))) return false;
  expected->service.uid = uid; expected->service.pid = (pid_t)pid; return true;
}
static void set_string(napi_env env, napi_value object, const char *key, const char *value) {
  napi_value property; napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &property); napi_set_named_property(env, object, key, property);
}
static void set_number(napi_env env, napi_value object, const char *key, double value) {
  napi_value property; napi_create_double(env, value, &property); napi_set_named_property(env, object, key, property);
}
static void set_boolean(napi_env env, napi_value object, const char *key, bool value) {
  napi_value property; napi_get_boolean(env, value, &property); napi_set_named_property(env, object, key, property);
}
static void set_ticks(napi_env env, napi_value object, uint64_t ticks) {
  char value[128]; snprintf(value, sizeof(value), "linux-proc-start-ticks:%llu", (unsigned long long)ticks); set_string(env, object, "processStartToken", value);
}
static napi_value identity_value(napi_env env, struct identity identity) {
  napi_value value; napi_create_object(env, &value); char number[32];
  snprintf(number, sizeof(number), "%llu", (unsigned long long)identity.device); set_string(env, value, "deviceId", number);
  snprintf(number, sizeof(number), "%llu", (unsigned long long)identity.inode); set_string(env, value, "fileId", number); return value;
}
static napi_value service_value(napi_env env, struct service service) {
  napi_value value; napi_create_object(env, &value); set_string(env, value, "uniqueName", service.unique);
  set_number(env, value, "uid", service.uid); set_number(env, value, "pid", service.pid); set_ticks(env, value, service.ticks); return value;
}
static napi_value bus_value(napi_env env, const struct platform_observation *observation) {
  napi_value value; napi_create_object(env, &value); set_string(env, value, "guid", observation->guid);
  napi_set_named_property(env, value, "runtime", identity_value(env, observation->runtime));
  napi_set_named_property(env, value, "socket", identity_value(env, observation->socket));
  set_number(env, value, "uid", observation->uid); set_number(env, value, "pid", observation->pid); set_ticks(env, value, observation->ticks); return value;
}
static napi_value selector_value(napi_env env, const struct selector *selector) {
  napi_value value; napi_create_object(env, &value); set_string(env, value, "itemId", selector->item_id);
  set_string(env, value, "ownerPrincipalId", selector->principal); set_string(env, value, "stateRootIdentityDigest", selector->root);
  set_string(env, value, "creatingOperationId", selector->operation); set_string(env, value, "credentialGrantId", selector->grant);
  set_number(env, value, "secretGeneration", selector->generation); set_string(env, value, "credentialTargetDigest", selector->target); return value;
}

struct manager_field { const char *name, *native_name, *type; bool service; };
static const struct manager_field manager_fields[] = {
  {"Id", "Id", "s", false}, {"Names", "Names", "as", false}, {"Following", "Following", "s", false},
  {"LoadState", "LoadState", "s", false}, {"ActiveState", "ActiveState", "s", false}, {"SubState", "SubState", "s", false},
  {"FragmentPath", "FragmentPath", "s", false}, {"SourcePath", "SourcePath", "s", false}, {"DropInPaths", "DropInPaths", "as", false},
  {"NeedDaemonReload", "NeedDaemonReload", "b", false}, {"Transient", "Transient", "b", false},
  {"Requires", "Requires", "as", false}, {"Requisite", "Requisite", "as", false}, {"Wants", "Wants", "as", false},
  {"BindsTo", "BindsTo", "as", false}, {"PartOf", "PartOf", "as", false}, {"Conflicts", "Conflicts", "as", false},
  {"Before", "Before", "as", false}, {"After", "After", "as", false}, {"OnFailure", "OnFailure", "as", false}, {"OnSuccess", "OnSuccess", "as", false},
  {"Type", "Type", "s", true},
  {"ExecStart", "ExecStartEx", "a(sasasttttuii)", true}, {"ExecCondition", "ExecConditionEx", "a(sasasttttuii)", true},
  {"ExecStartPre", "ExecStartPreEx", "a(sasasttttuii)", true}, {"ExecStartPost", "ExecStartPostEx", "a(sasasttttuii)", true},
  {"ExecReload", "ExecReloadEx", "a(sasasttttuii)", true}, {"ExecStop", "ExecStopEx", "a(sasasttttuii)", true}, {"ExecStopPost", "ExecStopPostEx", "a(sasasttttuii)", true},
  {"Environment", "Environment", "as", true}, {"EnvironmentFiles", "EnvironmentFiles", "a(sb)", true},
  {"PassEnvironment", "PassEnvironment", "as", true}, {"UnsetEnvironment", "UnsetEnvironment", "as", true},
  {"User", "User", "s", true}, {"Group", "Group", "s", true}, {"DynamicUser", "DynamicUser", "b", true}, {"PAMName", "PAMName", "s", true},
  {"WorkingDirectory", "WorkingDirectory", "s", true}, {"RootDirectory", "RootDirectory", "s", true}, {"RootImage", "RootImage", "s", true},
  {"UMask", "UMask", "u", true}, {"Delegate", "Delegate", "b", true}, {"DelegateControllers", "DelegateControllers", "as", true},
  {"KillMode", "KillMode", "s", true}, {"KillSignal", "KillSignal", "i", true}, {"SendSIGKILL", "SendSIGKILL", "b", true},
  {"Restart", "Restart", "s", true}, {"RestartUSec", "RestartUSec", "t", true}, {"TimeoutStartUSec", "TimeoutStartUSec", "t", true},
  {"TimeoutStopUSec", "TimeoutStopUSec", "t", true}, {"MainPID", "MainPID", "u", true}, {"ExecMainPID", "ExecMainPID", "u", true},
  {"ControlPID", "ControlPID", "u", true}, {"InvocationID", "InvocationID", "ay", false}, {"ControlGroup", "ControlGroup", "s", true},
  {"Result", "Result", "s", true}, {"NRestarts", "NRestarts", "u", true},
};
static bool bounded_variant(GVariant *value, unsigned int depth) {
  if (depth > 4 || g_variant_get_size(value) > 65536) return false;
  if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) return strlen(g_variant_get_string(value, NULL)) < TEXT_CAP;
  if (g_variant_is_container(value)) {
    size_t count = g_variant_n_children(value); if (count > 256) return false;
    for (size_t i = 0; i < count; i++) {
      GVariant *child = g_variant_get_child_value(value, i); bool valid = bounded_variant(child, depth + 1); g_variant_unref(child);
      if (!valid) return false;
    }
  }
  return true;
}
static bool manager_shape(struct task *task) {
  if (task->operation == RELOAD_MANAGER) return true;
  for (size_t i = 0; i < sizeof(manager_fields) / sizeof(*manager_fields); i++) {
    const struct manager_field *field = &manager_fields[i];
    GVariant *value = g_variant_lookup_value(field->service ? task->service_properties : task->unit_properties,
      field->native_name, G_VARIANT_TYPE(field->type));
    if (!value) return fail(task, "manager_profile_unsupported");
    bool valid = bounded_variant(value, 0);
    if (valid && !strcmp(field->type, "ay")) {
      size_t count = g_variant_n_children(value); valid = count == 0 || count == 16;
    }
    g_variant_unref(value);
    if (!valid) return fail(task, "manager_profile_bound");
  }
  return true;
}
static napi_value string_array(napi_env env, GVariant *value) {
  napi_value result; size_t count = g_variant_n_children(value); napi_create_array_with_length(env, count, &result);
  for (size_t i = 0; i < count; i++) {
    GVariant *child = g_variant_get_child_value(value, i); napi_value entry;
    napi_create_string_utf8(env, g_variant_get_string(child, NULL), NAPI_AUTO_LENGTH, &entry); napi_set_element(env, result, i, entry); g_variant_unref(child);
  }
  return result;
}
static napi_value command_array(napi_env env, GVariant *value) {
  napi_value result; size_t count = g_variant_n_children(value); napi_create_array_with_length(env, count, &result);
  for (size_t i = 0; i < count; i++) {
    GVariant *command = g_variant_get_child_value(value, i), *path = g_variant_get_child_value(command, 0),
      *argv = g_variant_get_child_value(command, 1), *flags = g_variant_get_child_value(command, 2);
    napi_value entry; napi_create_object(env, &entry); set_string(env, entry, "path", g_variant_get_string(path, NULL));
    napi_set_named_property(env, entry, "argv", string_array(env, argv)); napi_set_named_property(env, entry, "flags", string_array(env, flags));
    napi_set_element(env, result, i, entry); g_variant_unref(path); g_variant_unref(argv); g_variant_unref(flags); g_variant_unref(command);
  }
  return result;
}
static napi_value manager_unit_value(napi_env env, struct task *task) {
  napi_value result; napi_create_object(env, &result);
  for (size_t i = 0; i < sizeof(manager_fields) / sizeof(*manager_fields); i++) {
    const struct manager_field *field = &manager_fields[i];
    GVariant *value = g_variant_lookup_value(field->service ? task->service_properties : task->unit_properties,
      field->native_name, G_VARIANT_TYPE(field->type));
    if (!strcmp(field->type, "s")) set_string(env, result, field->name, g_variant_get_string(value, NULL));
    else if (!strcmp(field->type, "b")) set_boolean(env, result, field->name, g_variant_get_boolean(value));
    else if (!strcmp(field->type, "u")) set_number(env, result, field->name, g_variant_get_uint32(value));
    else if (!strcmp(field->type, "i")) set_number(env, result, field->name, g_variant_get_int32(value));
    else if (!strcmp(field->type, "t")) {
      char number[32]; snprintf(number, sizeof(number), "%llu", (unsigned long long)g_variant_get_uint64(value)); set_string(env, result, field->name, number);
    } else if (!strcmp(field->type, "as")) napi_set_named_property(env, result, field->name, string_array(env, value));
    else if (!strcmp(field->type, "a(sasasttttuii)")) napi_set_named_property(env, result, field->name, command_array(env, value));
    else if (!strcmp(field->type, "ay")) {
      gsize count; const unsigned char *bytes = g_variant_get_fixed_array(value, &count, 1); char encoded[33] = {0};
      if (count == 16) for (size_t j = 0; j < count; j++) snprintf(encoded + j * 2, 3, "%02x", bytes[j]);
      set_string(env, result, field->name, encoded);
    } else if (!strcmp(field->type, "a(sb)")) {
      napi_value list; size_t count = g_variant_n_children(value); napi_create_array_with_length(env, count, &list);
      for (size_t j = 0; j < count; j++) {
        const char *path; gboolean optional; g_variant_get_child(value, j, "(&sb)", &path, &optional);
        napi_value entry; napi_create_object(env, &entry); set_string(env, entry, "path", path); set_boolean(env, entry, "optional", optional); napi_set_element(env, list, j, entry);
      }
      napi_set_named_property(env, result, field->name, list);
    }
    g_variant_unref(value);
  }
  return result;
}
static napi_value result_value(napi_env env, struct task *task) {
  napi_value result; napi_create_object(env, &result); set_number(env, result, "schemaVersion", 1);
  napi_set_named_property(env, result, "bus", bus_value(env, &task->observed));
  if (task->operation <= DELETE_KNOWN) {
    set_string(env, result, "kind", task->result_kind); napi_set_named_property(env, result, "selector", selector_value(env, &task->selector));
    napi_set_named_property(env, result, "service", service_value(env, task->observed.service));
    set_string(env, result, "collectionPath", task->observed.collection);
    if (task->observed.item[0]) set_string(env, result, "itemPath", task->observed.item);
  } else {
    set_string(env, result, "kind", task->operation == RELOAD_MANAGER ? "reload" : task->operation == START_UNIT ? "start" : "inspect");
    set_number(env, result, "uid", task->uid); set_number(env, result, "gid", task->gid); set_string(env, result, "home", task->home);
    napi_set_named_property(env, result, "manager", service_value(env, task->observed.service));
    if (task->operation != RELOAD_MANAGER) napi_set_named_property(env, result, "unit", manager_unit_value(env, task));
    if (task->operation == START_UNIT) set_string(env, result, "jobPath", task->job);
  }
  return result;
}
static napi_value error_value(napi_env env, bool unsafe, const char *code) {
  napi_value message, result;
  napi_create_string_utf8(env, unsafe ? "Linux credential platform resources did not retire" : "Linux credential platform operation refused", NAPI_AUTO_LENGTH, &message);
  napi_create_error(env, NULL, message, &result);
  set_string(env, result, "code", unsafe ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_CREDENTIAL_PLATFORM");
  set_string(env, result, "platformCode", code ? code : "platform_worker_unavailable"); return result;
}
static void retire_main_handles(struct task *task) {
  bool valid = true;
  if (task->cleanup_hook) {
    if (napi_remove_async_cleanup_hook(task->cleanup_hook) != napi_ok) valid = false;
    else task->cleanup_hook = NULL;
  }
  if (task->work) {
    if (napi_delete_async_work(task->env, task->work) != napi_ok) valid = false;
    else task->work = NULL;
  }
  if (!task->unsafe && task->condition_ready) {
    if (pthread_cond_destroy(&task->condition)) valid = false;
    else task->condition_ready = false;
  }
  if (!task->unsafe && task->mutex_ready) {
    if (pthread_mutex_destroy(&task->mutex)) valid = false;
    else task->mutex_ready = false;
  }
  if (!valid) { task->unsafe = true; atomic_store(&retirement_failed, true); fail(task, "resource_retirement"); }
  /* Its optional wakeup FD belongs to the cancellable too. Once every worker
   * and callback is joined, retire that owner before a successful reply. */
  if (!task->unsafe && task->cancel) { g_object_unref(task->cancel); task->cancel = NULL; }
}
static void release_task(struct task *task) {
  if (task->secret) { wipe(task->secret, task->secret_size); free(task->secret); task->secret = NULL; }
  if (task->unit_properties) { g_variant_unref(task->unit_properties); task->unit_properties = NULL; }
  if (task->service_properties) { g_variant_unref(task->service_properties); task->service_properties = NULL; }
  if (task->unsafe) {
    /* A possibly owning bus or watchdog must stay strongly retained until
     * process death. This is resource ownership, not a recovery ledger. */
    task->unretired_next = unretired_tasks; unretired_tasks = task; return;
  }
  if (task->cancel) g_object_unref(task->cancel);
  free(task);
}
static void finish_task(struct task *task) {
  if (!task->work_complete || (task->timer_initialized && !task->timer_closed)) return;
  /* Neither the async worker nor the timer can still access the task. The
   * queued-cancel path never ran execute, so retire its copied input here. */
  if (task->secret) { wipe(task->secret, task->secret_size); free(task->secret); task->secret = NULL; }
  if (task->expired || !remaining(task)) task->error = "platform_timeout";
  if (task->main_retirement_failed) {
    task->unsafe = true; task->error = "resource_retirement"; atomic_store(&retirement_failed, true);
  }
  retire_main_handles(task);
  if (!task->env_closing && task->deferred) {
    /* A uv_close callback has no implicit Node-API handle scope. A broken
     * environment cannot safely publish a reply or continue this producer. */
    napi_handle_scope scope;
    if (napi_open_handle_scope(task->env, &scope) != napi_ok)
      napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "platform completion scope unavailable", NAPI_AUTO_LENGTH);
    napi_value result = NULL;
    if (!task->error) result = result_value(task->env, task);
    napi_status settled = task->error || task->unsafe
      ? napi_reject_deferred(task->env, task->deferred, error_value(task->env, task->unsafe, task->error))
      : napi_resolve_deferred(task->env, task->deferred, result);
    if (settled != napi_ok || napi_close_handle_scope(task->env, scope) != napi_ok)
      napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "platform completion unavailable", NAPI_AUTO_LENGTH);
    task->deferred = NULL;
  }
  atomic_store(&job_in_flight, false); release_task(task);
}
static void timer_closed(uv_handle_t *handle) {
  struct task *task = handle->data; task->timer_closed = true; finish_task(task);
}
static void close_timer(struct task *task) {
  if (task->timer_initialized && !task->timer_closing) {
    task->timer_closing = true;
    uv_close((uv_handle_t *)&task->deadline_timer, timer_closed);
  }
}
static void cancel_task(struct task *task) {
  g_cancellable_cancel(task->cancel);
  if (!task->work_complete && !task->cancel_requested) {
    task->cancel_requested = true;
    napi_status status = napi_cancel_async_work(task->env, task->work);
    /* generic_failure is the documented race with work already executing.
     * Both that case and successful queued cancellation still require complete. */
    if (status != napi_ok && status != napi_generic_failure) {
      task->main_retirement_failed = true; atomic_store(&retirement_failed, true);
    }
  }
}
static void deadline_expired(uv_timer_t *timer) {
  struct task *task = timer->data; task->expired = true;
  cancel_task(task); close_timer(task);
}
static void complete(napi_env env, napi_status status, void *data) {
  (void)env; struct task *task = data; task->work_complete = true;
  /* Worker-owned fields are now joined. Even a positive result must not be
   * published after expiry; cancellation never waives either ownership gate. */
  if (status != napi_ok) fail(task, "platform_worker_unavailable");
  close_timer(task); finish_task(task);
}
static void cleanup_task(napi_async_cleanup_hook_handle handle, void *data) {
  (void)handle; struct task *task = data; task->env_closing = true;
  cancel_task(task); close_timer(task);
}
static napi_value submit(napi_env env, napi_callback_info info, bool manager) {
  if (atomic_load(&retirement_failed)) { napi_throw(env, error_value(env, true, "resource_retirement")); return NULL; }
  if (syscall(SYS_gettid) != getpid()) { napi_throw(env, error_value(env, false, "platform_main_thread_required")); return NULL; }
  size_t argc = 2; napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1) {
    napi_throw(env, error_value(env, false, "invalid_platform_request")); return NULL;
  }
  struct task *task = calloc(1, sizeof(*task));
  if (!task) { napi_throw(env, error_value(env, false, "platform_worker_unavailable")); return NULL; }
  task->env = env; task->runtime_fd = -1; char kind[32];
  bool valid = current_user(&task->uid, &task->gid, task->home) && field_text(env, args[0], "kind", kind, sizeof(kind));
  if (valid && manager) {
    if (!strcmp(kind, "reload")) { const char *keys[] = {"kind"}; valid = fields(env, args[0], keys, 1); task->operation = RELOAD_MANAGER; }
    else if (!strcmp(kind, "start") || !strcmp(kind, "inspect")) {
      const char *keys[] = {"kind", "unit"}; valid = fields(env, args[0], keys, 2) && field_text(env, args[0], "unit", task->unit, sizeof(task->unit));
      size_t length = strlen(task->unit);
      valid = valid && length > 13 && !strncmp(task->unit, "cliq-", 5) &&
        strspn(task->unit, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == length &&
        !strcmp(task->unit + length - 8, ".service");
      task->operation = !strcmp(kind, "start") ? START_UNIT : INSPECT_UNIT;
    } else valid = false;
  } else if (valid) {
    napi_value selector;
    valid = member(env, args[0], "selector", &selector) && parse_selector(env, selector, &task->selector);
    if (!strcmp(kind, "create_compare")) {
      const char *keys[] = {"kind", "selector", "secret"}; napi_value input; bool buffer; void *bytes; size_t count;
      valid = valid && fields(env, args[0], keys, 3) && member(env, args[0], "secret", &input) &&
        napi_is_buffer(env, input, &buffer) == napi_ok && buffer && napi_get_buffer_info(env, input, &bytes, &count) == napi_ok && count > 0 && count <= MAX_SECRET;
      if (valid) { task->secret = malloc(count); valid = task->secret != NULL; if (valid) { memcpy(task->secret, bytes, count); task->secret_size = count; } }
      task->operation = CREATE_COMPARE;
    } else if (!strcmp(kind, "inspect")) {
      const char *keys[] = {"kind", "selector", "expectedObservation"}; napi_value expected;
      valid = valid && fields(env, args[0], keys, 3) && member(env, args[0], "expectedObservation", &expected) && parse_expected(env, expected, task);
      task->operation = INSPECT_SECRET;
    } else if (!strcmp(kind, "delete_known")) { const char *keys[] = {"kind", "selector"}; valid = valid && fields(env, args[0], keys, 2); task->operation = DELETE_KNOWN; }
    else valid = false;
  }
  bool occupied = false;
  if (!valid || !atomic_compare_exchange_strong(&job_in_flight, &occupied, true)) {
    release_task(task); napi_throw(env, error_value(env, false, valid ? "platform_busy" : "invalid_platform_request")); return NULL;
  }
  napi_value promise = NULL, resource;
  if (clock_gettime(CLOCK_MONOTONIC, &task->deadline)) goto failed;
  task->deadline.tv_sec += DEADLINE_SECONDS;
  task->cancel = g_cancellable_new();
  if (pthread_mutex_init(&task->mutex, NULL)) goto failed;
  task->mutex_ready = true;
  pthread_condattr_t attributes;
  if (pthread_condattr_init(&attributes)) goto failed;
  int condition = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
  if (!condition) condition = pthread_cond_init(&task->condition, &attributes);
  pthread_condattr_destroy(&attributes);
  if (condition) goto failed;
  task->condition_ready = true;
  if (napi_create_promise(env, &task->deferred, &promise) != napi_ok ||
      napi_create_string_utf8(env, "cliq-linux-credential-platform", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
      napi_create_async_work(env, NULL, resource, execute, complete, task, &task->work) != napi_ok ||
      napi_add_async_cleanup_hook(env, cleanup_task, task, &task->cleanup_hook) != napi_ok) goto failed;
  uv_loop_t *loop;
  if (napi_get_uv_event_loop(env, &loop) != napi_ok || uv_timer_init(loop, &task->deadline_timer)) goto failed;
  task->timer_initialized = true; task->deadline_timer.data = task;
  uv_update_time(loop);
  if (uv_timer_start(&task->deadline_timer, deadline_expired, (uint64_t)remaining(task), 0) ||
      napi_queue_async_work(env, task->work) != napi_ok) goto failed;
  return promise;
failed:
  task->work_complete = true; fail(task, "platform_worker_unavailable");
  if (promise) {
    /* A timer initialized during failed setup still owns the task. Return
     * the refusal only after its real close callback and all other owners. */
    close_timer(task); finish_task(task); return promise;
  }
  retire_main_handles(task);
  bool unsafe = task->unsafe;
  atomic_store(&job_in_flight, false); release_task(task);
  napi_throw(env, error_value(env, unsafe, unsafe ? "resource_retirement" : "platform_worker_unavailable")); return NULL;
}
static napi_value secret_service(napi_env env, napi_callback_info info) { return submit(env, info, false); }
static napi_value user_manager(napi_env env, napi_callback_info info) { return submit(env, info, true); }
static napi_value user(napi_env env, napi_callback_info info) {
  (void)info; uid_t uid; gid_t gid; char home[PATH_MAX];
  if (atomic_load(&retirement_failed) || syscall(SYS_gettid) != getpid() || !current_user(&uid, &gid, home)) {
    napi_throw(env, error_value(env, atomic_load(&retirement_failed), "platform_user_unavailable")); return NULL;
  }
  napi_value result; napi_create_object(env, &result); set_number(env, result, "uid", uid); set_number(env, result, "gid", gid); set_string(env, result, "home", home); return result;
}
static napi_value initialize(napi_env env, napi_value exports) {
  const napi_property_descriptor methods[] = {
    {"currentUser", NULL, user, NULL, NULL, NULL, napi_default, NULL},
    {"secretService", NULL, secret_service, NULL, NULL, NULL, napi_default, NULL},
    {"userManager", NULL, user_manager, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_define_properties(env, exports, sizeof(methods) / sizeof(*methods), methods) != napi_ok) return NULL;
  set_number(env, exports, "interfaceVersion", 1); return exports;
}
NAPI_MODULE(cliq_linux_credential_platform, initialize)
