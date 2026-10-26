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
#ifdef CLIQ_MODEL_BROKER_MODULE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <strings.h>
#endif

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

enum operation { CREATE_COMPARE, INSPECT_SECRET, DELETE_KNOWN, RELOAD_MANAGER, START_UNIT, INSPECT_UNIT, STOP_INSTALLED_UPGRADE };
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
struct task;
struct inspection_owner {
  napi_env env;
  struct task *task;
  napi_ref handle, join_promise;
  napi_deferred join_deferred;
  bool retained, finalized, joined, unsafe;
};
struct task {
  napi_env env; napi_async_work work; napi_deferred deferred; napi_async_cleanup_hook_handle cleanup_hook;
  enum operation operation; uid_t uid; gid_t gid; char home[PATH_MAX], unit[256], job[TEXT_CAP];
  uint32_t upgrade_pid; uint64_t upgrade_ticks; unsigned char upgrade_invocation[16];
  struct selector selector; struct platform_observation expected, observed;
  unsigned char *secret; size_t secret_size;
  struct timespec deadline; pthread_t watchdog; pthread_mutex_t mutex; pthread_cond_t condition;
  bool mutex_ready, condition_ready, watchdog_started, finished, unsafe, env_closing;
  /* Only the main loop reads/writes these timer/completion flags. In
   * particular, expiry never races a worker write to error, unsafe or secret. */
  uv_timer_t deadline_timer;
  bool timer_initialized, timer_closing, timer_closed, work_complete, expired, cancel_requested, caller_cancelled, main_retirement_failed;
  GCancellable *cancel; GDBusConnection *bus; int runtime_fd;
  char session[TEXT_CAP]; struct stat runtime_identity, socket_identity;
  GVariant *unit_properties, *service_properties;
  const char *error; const char *result_kind;
  struct inspection_owner *inspection;
  struct task *unretired_next;
};
static atomic_bool retirement_failed;
static atomic_bool job_in_flight;
static struct task *unretired_tasks;
static const napi_type_tag inspection_tag = { UINT64_C(0x7145d66c9a4a4718), UINT64_C(0x8d01e244ace23b91) };
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
static bool manager_read_unit(struct task *task, bool allow_load) {
  GVariant *reply = call(task, task->observed.service.unique, MANAGER_PATH, MANAGER_INTERFACE,
    allow_load ? "LoadUnit" : "GetUnit", g_variant_new("(s)", task->unit), "(o)");
  if (!reply) return false;
  const char *unit; g_variant_get(reply, "(&o)", &unit); char locator[TEXT_CAP];
  bool valid = copy_text(locator, sizeof(locator), unit); g_variant_unref(reply);
  if (!valid) return fail(task, "platform_shape_mismatch");
  task->unit_properties = get_all(task, locator, "org.freedesktop.systemd1.Unit");
  task->service_properties = get_all(task, locator, "org.freedesktop.systemd1.Service");
  return task->unit_properties && task->service_properties && manager_shape(task);
}
static bool manager_original_upgrade_process(struct task *task) {
  uint32_t pid = 0; uint64_t ticks = 0;
  GVariant *invocation = g_variant_lookup_value(task->unit_properties, "InvocationID", G_VARIANT_TYPE("ay"));
  if (!invocation) return fail(task, "platform_shape_mismatch");
  gsize count = 0; const unsigned char *bytes = g_variant_get_fixed_array(invocation, &count, 1);
  bool valid = count == 16 && !memcmp(bytes, task->upgrade_invocation, 16) &&
    g_variant_lookup(task->service_properties, "MainPID", "u", &pid) && pid == task->upgrade_pid &&
    process_ticks(task, (pid_t)pid, task->uid, &ticks) && ticks == task->upgrade_ticks;
  g_variant_unref(invocation);
  return valid || fail(task, "platform_observation_changed");
}
static bool manager_operation(struct task *task) {
  if (!observe_owner(task, MANAGER_NAME, &task->observed.service)) return false;
  const char *destination = task->observed.service.unique;
  if (task->operation == RELOAD_MANAGER) {
    GVariant *reply = call(task, destination, MANAGER_PATH, MANAGER_INTERFACE, "Reload", NULL, "()");
    if (!reply) return false;
    g_variant_unref(reply);
  } else {
    if (task->operation == STOP_INSTALLED_UPGRADE) {
      // Administrative Stop of this installation's two fixed units only.
      // The captured invocation and real same-user PID/start are preconditions,
      // not an atomic StopUnit selector: systemd may restart between calls.
      // The caller independently requires its exact original owner/death cut.
      if (!manager_read_unit(task, false) || !manager_original_upgrade_process(task)) return false;
      g_variant_unref(task->unit_properties); task->unit_properties = NULL;
      g_variant_unref(task->service_properties); task->service_properties = NULL;
    }
    if (task->operation == START_UNIT || task->operation == STOP_INSTALLED_UPGRADE) {
      GVariant *reply = call(task, destination, MANAGER_PATH, MANAGER_INTERFACE,
        task->operation == START_UNIT ? "StartUnit" : "StopUnit", g_variant_new("(ss)", task->unit, "fail"), "(o)");
      if (!reply) return false;
      const char *job; g_variant_get(reply, "(&o)", &job); bool valid = copy_text(task->job, sizeof(task->job), job); g_variant_unref(reply);
      if (!valid) return fail(task, "platform_shape_mismatch");
    }
    // LoadUnit never starts the original inspector's fixed service profile.
    if (!manager_read_unit(task, task->operation == INSPECT_UNIT)) return false;
    if (task->operation == STOP_INSTALLED_UPGRADE) {
      for (;;) {
        const char *active = NULL, *sub = NULL; uint32_t main_pid = UINT32_MAX, control_pid = UINT32_MAX;
        if (!g_variant_lookup(task->unit_properties, "ActiveState", "&s", &active) ||
            !g_variant_lookup(task->unit_properties, "SubState", "&s", &sub) ||
            !g_variant_lookup(task->service_properties, "MainPID", "u", &main_pid) ||
            !g_variant_lookup(task->service_properties, "ControlPID", "u", &control_pid)) return fail(task, "platform_shape_mismatch");
        if (!strcmp(active, "inactive") && !strcmp(sub, "dead") && !main_pid && !control_pid) break;
        if (!remaining(task)) return fail(task, "platform_timeout");
        g_variant_unref(task->unit_properties); task->unit_properties = NULL;
        g_variant_unref(task->service_properties); task->service_properties = NULL;
        g_usleep(10000);
        if (!manager_read_unit(task, false)) return false;
      }
    }
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
    /* Operation cancellation must not turn a completed local disconnect into
     * G_IO_ERROR_CANCELLED. Still join the close; actual retirement failures
     * remain sticky, and expiry can never publish an operation success. */
    if (!g_dbus_connection_is_closed(task->bus) && !g_dbus_connection_close_sync(task->bus, NULL, &error)) {
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
    set_string(env, result, "kind", task->operation == RELOAD_MANAGER ? "reload" : task->operation == START_UNIT ? "start" : task->operation == STOP_INSTALLED_UPGRADE ? "stop_installed_upgrade" : "inspect");
    set_number(env, result, "uid", task->uid); set_number(env, result, "gid", task->gid); set_string(env, result, "home", task->home);
    napi_set_named_property(env, result, "manager", service_value(env, task->observed.service));
    if (task->operation != RELOAD_MANAGER) napi_set_named_property(env, result, "unit", manager_unit_value(env, task));
    if (task->operation == START_UNIT || task->operation == STOP_INSTALLED_UPGRADE) set_string(env, result, "jobPath", task->job);
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
static void release_inspection_owner(struct inspection_owner *owner) {
  if (owner->join_promise && napi_delete_reference(owner->env, owner->join_promise) != napi_ok)
    atomic_store(&retirement_failed, true);
  if (owner->handle && napi_delete_reference(owner->env, owner->handle) != napi_ok)
    atomic_store(&retirement_failed, true);
  free(owner);
}
static void finish_task(struct task *task) {
  if (!task->work_complete || (task->timer_initialized && !task->timer_closed)) return;
  /* Neither the async worker nor the timer can still access the task. The
   * queued-cancel path never ran execute, so retire its copied input here. */
  if (task->secret) { wipe(task->secret, task->secret_size); free(task->secret); task->secret = NULL; }
  if (task->caller_cancelled) task->error = "platform_cancelled";
  if (task->expired || !remaining(task)) task->error = "platform_timeout";
  if (task->main_retirement_failed) {
    task->unsafe = true; task->error = "resource_retirement"; atomic_store(&retirement_failed, true);
  }
  retire_main_handles(task);
  const bool env_closing = task->env_closing;
  struct inspection_owner *owner = task->inspection;
  napi_env env = task->env;
  napi_handle_scope scope = NULL;
  if (!env_closing) {
    /* A uv_close callback has no implicit Node-API handle scope. A broken
     * environment cannot safely publish a reply or continue this producer. */
    if (napi_open_handle_scope(env, &scope) != napi_ok)
      napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "platform completion scope unavailable", NAPI_AUTO_LENGTH);
  }
  if (owner && owner->retained && !owner->finalized) {
    // Keep a local handle while dropping the task's strong reference. A live
    // JS owner may then outlive this task, but can never retain its freed pointer.
    napi_value held; uint32_t references;
    if ((!env_closing && napi_get_reference_value(env, owner->handle, &held) != napi_ok) ||
        napi_reference_unref(env, owner->handle, &references) != napi_ok) {
      task->unsafe = true; task->error = "resource_retirement"; atomic_store(&retirement_failed, true);
    } else owner->retained = false;
  }
  if (!env_closing && task->deferred) {
    napi_value result = NULL;
    if (!task->error) result = result_value(task->env, task);
    napi_status settled = task->error || task->unsafe
      ? napi_reject_deferred(task->env, task->deferred, error_value(task->env, task->unsafe, task->error))
      : napi_resolve_deferred(task->env, task->deferred, result);
    if (settled != napi_ok)
      napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "platform completion unavailable", NAPI_AUTO_LENGTH);
    task->deferred = NULL;
  }
  if (owner) {
    owner->task = NULL; owner->joined = true; owner->unsafe = task->unsafe;
    task->inspection = NULL;
  }
  atomic_store(&job_in_flight, false); release_task(task);
  // release_task also retires variant/input storage. A positive cancellation
  // join is published only after every worker, watchdog, bus, FD and timer gate.
  if (owner && !env_closing && owner->join_deferred) {
    napi_value value;
    napi_status settled = owner->unsafe
      ? napi_reject_deferred(env, owner->join_deferred, error_value(env, true, "resource_retirement"))
      : napi_get_undefined(env, &value);
    if (!owner->unsafe && settled == napi_ok) settled = napi_resolve_deferred(env, owner->join_deferred, value);
    if (settled != napi_ok)
      napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "inspection join unavailable", NAPI_AUTO_LENGTH);
    owner->join_deferred = NULL;
  }
  if (owner && owner->finalized) release_inspection_owner(owner);
  if (scope && napi_close_handle_scope(env, scope) != napi_ok)
    napi_fatal_error("cliq-credential-platform", NAPI_AUTO_LENGTH, "platform completion scope did not retire", NAPI_AUTO_LENGTH);
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
static void finalize_inspection(napi_env env, void *data, void *hint) {
  (void)env; (void)hint; struct inspection_owner *owner = data; owner->finalized = true;
  if (owner->task) {
    // Strong task ownership normally prevents GC here. Environment teardown
    // can finalize first; retain this owner until the same task's complete gate.
    owner->task->env_closing = true;
    cancel_task(owner->task); close_timer(owner->task);
  } else release_inspection_owner(owner);
}
static napi_value cancel_inspection(napi_env env, napi_callback_info info) {
  size_t argc = 1; napi_value args[1], receiver; bool tagged = false; struct inspection_owner *owner = NULL;
  if (napi_get_cb_info(env, info, &argc, args, &receiver, NULL) != napi_ok || argc ||
      napi_check_object_type_tag(env, receiver, &inspection_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, receiver, (void **)&owner) != napi_ok || !owner || owner->env != env || owner->finalized) {
    napi_throw_type_error(env, NULL, "Credential inspection cancellation requires its original owner and no fields"); return NULL;
  }
  napi_value promise;
  if (owner->join_promise) {
    if (napi_get_reference_value(env, owner->join_promise, &promise) != napi_ok) return NULL;
    return promise;
  }
  if (napi_create_promise(env, &owner->join_deferred, &promise) != napi_ok ||
      napi_create_reference(env, promise, 1, &owner->join_promise) != napi_ok) return NULL;
  if (owner->task) {
    owner->task->caller_cancelled = true;
    cancel_task(owner->task); close_timer(owner->task);
  } else if (owner->joined) {
    napi_value value; napi_status settled = owner->unsafe
      ? napi_reject_deferred(env, owner->join_deferred, error_value(env, true, "resource_retirement"))
      : napi_get_undefined(env, &value);
    if (!owner->unsafe && settled == napi_ok) settled = napi_resolve_deferred(env, owner->join_deferred, value);
    if (settled != napi_ok) return NULL;
    owner->join_deferred = NULL;
  }
  return promise;
}
static bool own_inspection(struct task *task, napi_value promise) {
  struct inspection_owner *owner = calloc(1, sizeof(*owner));
  if (!owner) return false;
  owner->env = task->env; owner->task = task;
  if (napi_type_tag_object(task->env, promise, &inspection_tag) != napi_ok ||
      napi_wrap(task->env, promise, owner, finalize_inspection, NULL, &owner->handle) != napi_ok) {
    free(owner); return false;
  }
  task->inspection = owner;
  uint32_t references;
  if (napi_reference_ref(task->env, owner->handle, &references) != napi_ok) return false;
  owner->retained = true;
  const napi_property_descriptor method = {"cancelAndJoin", NULL, cancel_inspection, NULL, NULL, NULL, napi_default, NULL};
  return napi_define_properties(task->env, promise, 1, &method) == napi_ok;
}
static napi_value submit(napi_env env, napi_callback_info info, bool manager, bool upgrade) {
  if (atomic_load(&retirement_failed)) { napi_throw(env, error_value(env, true, "resource_retirement")); return NULL; }
  if (syscall(SYS_gettid) != getpid()) { napi_throw(env, error_value(env, false, "platform_main_thread_required")); return NULL; }
  size_t argc = 2; napi_value args[2];
  if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1) {
    napi_throw(env, error_value(env, false, "invalid_platform_request")); return NULL;
  }
  struct task *task = calloc(1, sizeof(*task));
  if (!task) { napi_throw(env, error_value(env, false, "platform_worker_unavailable")); return NULL; }
  task->env = env; task->runtime_fd = -1; char kind[32];
  bool valid = current_user(&task->uid, &task->gid, task->home);
  if (valid && upgrade) {
    const char *keys[] = {"rootIdentityDigest", "role", "pid", "processStartToken", "invocationId"};
    char root[65], role[16], invocation[33];
    valid = fields(env, args[0], keys, 5) && field_text(env, args[0], "rootIdentityDigest", root, sizeof(root)) &&
      strlen(root) == 64 && strspn(root, "0123456789abcdef") == 64 &&
      field_text(env, args[0], "role", role, sizeof(role)) && (!strcmp(role, "supervisor") || !strcmp(role, "keeper")) &&
      field_u32(env, args[0], "pid", &task->upgrade_pid) && task->upgrade_pid > 0 && task->upgrade_pid <= INT_MAX &&
      field_ticks(env, args[0], &task->upgrade_ticks) && field_text(env, args[0], "invocationId", invocation, sizeof(invocation)) &&
      strlen(invocation) == 32 && strspn(invocation, "0123456789abcdef") == 32;
    bool nonzero = false;
    if (valid) for (size_t i = 0; i < 16; i++) {
      unsigned int byte = 0; if (sscanf(invocation + i * 2, "%2x", &byte) != 1) valid = false;
      task->upgrade_invocation[i] = (unsigned char)byte; nonzero |= byte != 0;
    }
    valid = valid && nonzero;
    if (valid) valid = snprintf(task->unit, sizeof(task->unit), "cliq-%s-%s.service", root, role) > 0;
    task->operation = STOP_INSTALLED_UPGRADE;
  } else if (valid && !field_text(env, args[0], "kind", kind, sizeof(kind))) valid = false;
  if (valid && !upgrade && manager) {
    if (!strcmp(kind, "reload")) { const char *keys[] = {"kind"}; valid = fields(env, args[0], keys, 1); task->operation = RELOAD_MANAGER; }
    else if (!strcmp(kind, "start") || !strcmp(kind, "inspect")) {
      const char *keys[] = {"kind", "unit"}; valid = fields(env, args[0], keys, 2) && field_text(env, args[0], "unit", task->unit, sizeof(task->unit));
      size_t length = strlen(task->unit);
      valid = valid && length > 13 && !strncmp(task->unit, "cliq-", 5) &&
        strspn(task->unit, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == length &&
        !strcmp(task->unit + length - 8, ".service");
      task->operation = !strcmp(kind, "start") ? START_UNIT : INSPECT_UNIT;
    } else valid = false;
  } else if (valid && !upgrade) {
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
  task->deadline.tv_sec += upgrade ? 1 : DEADLINE_SECONDS;
  if (upgrade) {
    task->deadline.tv_nsec += 750000000;
    if (task->deadline.tv_nsec >= 1000000000) { task->deadline.tv_sec++; task->deadline.tv_nsec -= 1000000000; }
  }
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
      ((task->operation == INSPECT_SECRET || task->operation == STOP_INSTALLED_UPGRADE) && !own_inspection(task, promise)) ||
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
static napi_value secret_service(napi_env env, napi_callback_info info) { return submit(env, info, false, false); }
static napi_value user_manager(napi_env env, napi_callback_info info) { return submit(env, info, true, false); }
static napi_value stop_installed_upgrade(napi_env env, napi_callback_info info) { return submit(env, info, true, true); }
static napi_value user(napi_env env, napi_callback_info info) {
  (void)info; uid_t uid; gid_t gid; char home[PATH_MAX];
  if (atomic_load(&retirement_failed) || syscall(SYS_gettid) != getpid() || !current_user(&uid, &gid, home)) {
    napi_throw(env, error_value(env, atomic_load(&retirement_failed), "platform_user_unavailable")); return NULL;
  }
  napi_value result; napi_create_object(env, &result); set_number(env, result, "uid", uid); set_number(env, result, "gid", gid); set_string(env, result, "home", home); return result;
}
#ifndef CLIQ_MODEL_BROKER_MODULE
static napi_value initialize(napi_env env, napi_value exports) {
  const napi_property_descriptor methods[] = {
    {"currentUser", NULL, user, NULL, NULL, NULL, napi_default, NULL},
    {"secretService", NULL, secret_service, NULL, NULL, NULL, napi_default, NULL},
    {"userManager", NULL, user_manager, NULL, NULL, NULL, napi_default, NULL},
    {"stopInstalledUpgradeUnit", NULL, stop_installed_upgrade, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_define_properties(env, exports, sizeof(methods) / sizeof(*methods), methods) != napi_ok) return NULL;
  set_number(env, exports, "interfaceVersion", 2); set_number(env, exports, "installedUpgradeInterfaceVersion", 1); return exports;
}
NAPI_MODULE(cliq_linux_credential_platform, initialize)
#else
/* A distinct signed provider image. Its private handle owns the token, key,
 * copied request, connection and cancellation. No native call selects SQL
 * authority: the installed Supervisor performs both committed release gates. */
#define BROKER_BODY_CAP 1048576
#define BROKER_HEADER_CAP 65536
#define BROKER_TRUST_CAP (16 * 1048576)
#define BROKER_PIN_CAP 64
#define BROKER_ID_CAP 257
enum broker_stage { BROKER_PREPARE, BROKER_CONNECT, BROKER_EXCHANGE, BROKER_RETIRE };
struct broker_binding {
  char run[BROKER_ID_CAP], op[BROKER_ID_CAP], dispatch[BROKER_ID_CAP], supervisor[BROKER_ID_CAP];
  char request_ref[65], request_digest[65], target_ref[65], target_digest[65], grant_ref[65], token_digest[65];
  uint64_t attempt, sequence, owner_epoch, lease_epoch;
};
struct broker {
  struct task platform;
  napi_env env;
  napi_async_work work;
  napi_async_work unretired_work[4];
  size_t unretired_work_count;
  napi_deferred ready_deferred, phase_deferred, close_deferred;
  napi_ref handle, close_promise;
  napi_async_cleanup_hook_handle cleanup_hook;
  uv_timer_t timer;
  bool timer_ready, timer_closing, timer_closed, working, prepared, connected, exchanged;
  bool closing, retired, env_closing, network_started, request_started, bound, close_finished;
  atomic_bool cancelled, unsafe;
  pthread_mutex_t release_mutex;
  bool mutex_ready, token_revoked, fence_locked, finalize_requested;
  atomic_bool fence_retained;
  unsigned active_releases, fence_borrows;
  pid_t creator_pid;
  enum broker_stage stage;
  struct broker_binding binding;
  char host[TEXT_CAP], server_name[TEXT_CAP], path[TEXT_CAP * 2], body_digest[65], trust_digest[65], token_digest[65];
  uint32_t port;
  unsigned char token[32], pins[BROKER_PIN_CAP][32];
  size_t pin_count, body_size, trust_size, response_size;
  unsigned char *body, *trust, *response;
  GSocketConnection *connection;
  GSocket *socket;
  SSL_CTX *tls_context;
  SSL *tls;
  unsigned status;
  bool response_over_limit;
  const char *media_type;
  _Atomic(const char *) error;
  struct broker *unretired_next;
};
/* struct task is embedded in broker. Its upgrade fields change the private
 * native layout, so old-image owners/fences cannot borrow this image's methods.
 * Public transport semantics and retained evidence formats are unchanged. */
static const napi_type_tag broker_tag = { UINT64_C(0x613929b5e6bd4b03), UINT64_C(0xaac5c25e66e15d24) };
static const napi_type_tag broker_fence_tag = { UINT64_C(0x935ea37257e14d06), UINT64_C(0x89351effd851e41b) };
struct broker_fence {
  struct broker *broker; napi_env env; napi_ref original; struct broker_binding binding; pid_t creator_pid; bool active;
};
static struct broker *unretired_brokers;
static void broker_begin_close(struct broker *broker);
static bool broker_queue(struct broker *broker, enum broker_stage stage);
static void broker_finish_close(struct broker *broker);

static bool broker_fail(struct broker *broker, const char *code) {
  const char *expected = NULL;
  atomic_compare_exchange_strong(&broker->error, &expected, code);
  return false;
}
static bool digest_hex(const unsigned char *bytes, size_t size, char result[65]) {
  unsigned char digest[32];
  if (!SHA256(bytes, size, digest)) { wipe(digest, sizeof(digest)); return false; }
  for (size_t index = 0; index < 32; index++) snprintf(result + index * 2, 3, "%02x", digest[index]);
  wipe(digest, sizeof(digest)); return true;
}
static bool broker_digest(napi_env env, napi_value value, const char *field, char output[65]) {
  return field_text(env, value, field, output, 65) && strlen(output) == 64 && strspn(output, "0123456789abcdef") == 64;
}
static bool broker_integer(napi_env env, napi_value value, const char *field, uint64_t minimum, uint64_t *output) {
  napi_value member_value; double number;
  if (!member(env, value, field, &member_value) || napi_get_value_double(env, member_value, &number) != napi_ok ||
      !isfinite(number) || number < minimum || number > 9007199254740991.0 || number != (uint64_t)number) return false;
  *output = (uint64_t)number; return true;
}
static bool broker_buffer(napi_env env, napi_value value, const char *field, size_t maximum,
  unsigned char **output, size_t *size) {
  napi_value property; bool buffer; void *bytes;
  if (!member(env, value, field, &property) || napi_is_buffer(env, property, &buffer) != napi_ok || !buffer ||
      napi_get_buffer_info(env, property, &bytes, size) != napi_ok || !*size || *size > maximum) return false;
  *output = malloc(*size);
  if (!*output) return false;
  memcpy(*output, bytes, *size); return true;
}
static bool broker_host(const char *value) {
  size_t length = strlen(value);
  if (!length || length > 253 || value[0] == '.' || value[length - 1] == '.' ||
      strspn(value, "abcdefghijklmnopqrstuvwxyz0123456789.-") != length) return false;
  const char *label = value;
  while (*label) {
    const char *end = strchr(label, '.'); size_t count = end ? (size_t)(end - label) : strlen(label);
    if (!count || count > 63 || label[0] == '-' || label[count - 1] == '-') return false;
    if (!end) break;
    label = end + 1;
  }
  return true;
}
static bool broker_path(const char *value) {
  if (value[0] != '/' || strchr(value, '?') || strchr(value, '#') || strchr(value, '\\') ||
      strchr(value, '%') || strspn(value, "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-+") != strlen(value)) return false;
  const char *cursor = value + 1;
  while (*cursor) {
    const char *end = strchr(cursor, '/'); size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
    if (!length || (length == 1 && cursor[0] == '.') || (length == 2 && !memcmp(cursor, "..", 2))) return false;
    if (!end) return true;
    cursor = end + 1;
  }
  return true;
}
static bool broker_binding_value(napi_env env, napi_value value, struct broker_binding *binding) {
  const char *keys[] = {"runId", "opId", "attempt", "dispatchId", "dispatchJournalSeq", "requestRef", "requestDigest",
    "targetRef", "targetDigest", "grantRef", "supervisorInstanceId", "stateOwnerEpoch", "leaseEpoch", "brokerFenceTokenDigest"};
  return fields(env, value, keys, 14) && field_text(env, value, "runId", binding->run, sizeof(binding->run)) &&
    field_text(env, value, "opId", binding->op, sizeof(binding->op)) && field_text(env, value, "dispatchId", binding->dispatch, sizeof(binding->dispatch)) &&
    field_text(env, value, "supervisorInstanceId", binding->supervisor, sizeof(binding->supervisor)) &&
    broker_digest(env, value, "requestRef", binding->request_ref) && broker_digest(env, value, "requestDigest", binding->request_digest) &&
    broker_digest(env, value, "targetRef", binding->target_ref) && broker_digest(env, value, "targetDigest", binding->target_digest) &&
    broker_digest(env, value, "grantRef", binding->grant_ref) && broker_digest(env, value, "brokerFenceTokenDigest", binding->token_digest) &&
    broker_integer(env, value, "attempt", 0, &binding->attempt) && broker_integer(env, value, "dispatchJournalSeq", 1, &binding->sequence) &&
    broker_integer(env, value, "stateOwnerEpoch", 1, &binding->owner_epoch) && broker_integer(env, value, "leaseEpoch", 1, &binding->lease_epoch);
}
static bool broker_live(struct broker *broker) {
  return (!atomic_load(&broker->cancelled) && !atomic_load(&retirement_failed) && remaining(&broker->platform) > 0) ||
    broker_fail(broker, "broker_cancelled_or_expired");
}
static bool broker_platform_retire(struct broker *broker) {
  struct task *task = &broker->platform;
  if (task->bus) {
    GError *error = NULL;
    if (!g_dbus_connection_is_closed(task->bus) && !g_dbus_connection_close_sync(task->bus, NULL, &error)) {
      task->unsafe = true; atomic_store(&retirement_failed, true); fail(task, "resource_retirement");
    }
    g_clear_error(&error);
    if (!task->unsafe) { g_object_unref(task->bus); task->bus = NULL; }
  }
  if (!retired_close(task, &task->runtime_fd)) task->unsafe = true;
  if (task->unsafe) { broker->unsafe = true; return broker_fail(broker, "resource_retirement"); }
  return true;
}
static bool broker_read_key(struct broker *broker) {
  struct task *task = &broker->platform; bool found = false;
  if (!connect_bus(task) || !observe_owner(task, SECRET_NAME, &task->observed.service) || !default_collection(task) ||
      !search_item(task, &found) || !found || !verify_item(task) || !expected_platform(task) || !open_session(task))
    return broker_fail(broker, "credential_redemption_refused");
  GVariant *reply = call(task, task->observed.service.unique, task->observed.item, SECRET_INTERFACE "Item", "GetSecret",
    g_variant_new("(o)", task->session), "((oayays))");
  if (!reply) return broker_fail(broker, "credential_redemption_refused");
  GVariant *parameters, *bytes; const char *session, *content_type;
  g_variant_get(reply, "((&o@ay@ay&s))", &session, &parameters, &bytes, &content_type);
  gsize size = 0; const unsigned char *secret = g_variant_get_fixed_array(bytes, &size, 1);
  bool valid = !strcmp(session, task->session) && !g_variant_n_children(parameters) && size > 0 && size <= MAX_SECRET &&
    (!strcmp(content_type, "application/octet-stream") || !strcmp(content_type, "text/plain"));
  for (size_t index = 0; valid && index < size; index++) valid = secret[index] >= 0x21 && secret[index] <= 0x7e;
  static const char *const protocol_literals[] = {"{", "}", "[", "]", "\"", ":", "application/json"};
  for (size_t index = 0; valid && index < sizeof(protocol_literals) / sizeof(protocol_literals[0]); index++) {
    const char *literal = protocol_literals[index];
    if (memmem(literal, strlen(literal), secret, size) != NULL) valid = false;
  }
  if (valid) {
    task->secret = malloc(size);
    valid = task->secret != NULL;
    if (valid) { memcpy(task->secret, secret, size); task->secret_size = size; }
  }
  /* Secret Service's immutable reply storage is never exported or persisted.
   * Only our owned copy survives the immediate reply retirement. */
  g_variant_unref(parameters); g_variant_unref(bytes); g_variant_unref(reply);
  if (!valid || !verify_item(task) || !default_collection(task) || !observe_owner(task, SECRET_NAME, &task->observed.service) ||
      !expected_platform(task) || !bus_current(task)) return broker_fail(broker, "credential_redemption_refused");
  return broker_live(broker);
}
static bool broker_tls_wait(struct broker *broker, int error) {
  if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return broker_fail(broker, "broker_transport_interrupted");
  if (!broker_live(broker)) return false;
  struct pollfd descriptor = { .fd = g_socket_get_fd(broker->socket), .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT };
  int result;
  do { result = poll(&descriptor, 1, 50); } while (result < 0 && errno == EINTR && broker_live(broker));
  return (result >= 0 || broker_fail(broker, "broker_transport_interrupted")) && broker_live(broker);
}
static bool broker_load_ca(struct broker *broker) {
  broker->tls_context = SSL_CTX_new(TLS_client_method());
  if (!broker->tls_context || !SSL_CTX_set_min_proto_version(broker->tls_context, TLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(broker->tls_context, TLS1_3_VERSION)) return broker_fail(broker, "broker_tls_refused");
  SSL_CTX_set_verify(broker->tls_context, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_options(broker->tls_context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  BIO *input = BIO_new_mem_buf(broker->trust, (int)broker->trust_size);
  if (!input) return broker_fail(broker, "broker_tls_refused");
  unsigned count = 0; X509 *certificate;
  while ((certificate = PEM_read_bio_X509(input, NULL, NULL, NULL))) {
    bool added = X509_STORE_add_cert(SSL_CTX_get_cert_store(broker->tls_context), certificate) == 1;
    X509_free(certificate);
    if (!added || ++count > 4096) { BIO_free(input); ERR_clear_error(); return broker_fail(broker, "broker_tls_refused"); }
  }
  BIO_free(input); ERR_clear_error();
  return count > 0 || broker_fail(broker, "broker_tls_refused");
}
static bool broker_pin(struct broker *broker) {
  X509 *certificate = SSL_get1_peer_certificate(broker->tls);
  if (!certificate) return broker_fail(broker, "broker_tls_refused");
  X509_PUBKEY *key = X509_get_X509_PUBKEY(certificate); unsigned char *encoded = NULL;
  int count = i2d_X509_PUBKEY(key, &encoded); unsigned char digest[32];
  bool valid = count > 0 && encoded != NULL && SHA256(encoded, (size_t)count, digest) != NULL, matched = false;
  for (size_t index = 0; valid && index < broker->pin_count; index++) matched |= CRYPTO_memcmp(digest, broker->pins[index], 32) == 0;
  wipe(digest, sizeof(digest)); OPENSSL_free(encoded); X509_free(certificate);
  return (valid && matched) || broker_fail(broker, "broker_tls_refused");
}
static bool broker_connect(struct broker *broker) {
  GSocketClient *client = g_socket_client_new();
  g_socket_client_set_enable_proxy(client, FALSE);
  g_socket_client_set_tls(client, FALSE);
  g_socket_client_set_timeout(client, DEADLINE_SECONDS);
  GError *error = NULL;
  broker->connection = g_socket_client_connect_to_host(client, broker->host, (guint16)broker->port, broker->platform.cancel, &error);
  g_object_unref(client); g_clear_error(&error);
  if (!broker->connection || !broker_live(broker)) return broker_fail(broker, "broker_transport_interrupted");
  broker->socket = g_socket_connection_get_socket(broker->connection);
  g_socket_set_blocking(broker->socket, FALSE);
  if (!broker_load_ca(broker)) return false;
  broker->tls = SSL_new(broker->tls_context);
  if (!broker->tls || !SSL_set_fd(broker->tls, g_socket_get_fd(broker->socket)) ||
      !SSL_set_tlsext_host_name(broker->tls, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  X509_VERIFY_PARAM *parameters = SSL_get0_param(broker->tls);
  X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (g_hostname_is_ip_address(broker->server_name)) {
    if (!X509_VERIFY_PARAM_set1_ip_asc(parameters, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  } else if (!SSL_set1_host(broker->tls, broker->server_name)) return broker_fail(broker, "broker_tls_refused");
  for (;;) {
    if (!broker_live(broker)) return false;
    int result = SSL_connect(broker->tls);
    if (result == 1) break;
    if (!broker_tls_wait(broker, SSL_get_error(broker->tls, result))) return false;
  }
  if (SSL_version(broker->tls) != TLS1_3_VERSION || SSL_get_verify_result(broker->tls) != X509_V_OK || !broker_pin(broker))
    return broker_fail(broker, "broker_tls_refused");
  /* Ready means native platform identities remained original after the slow
   * handshake. Root still supplies the final fresh SQL/credential release cut. */
  struct task *task = &broker->platform;
  return verify_item(task) && default_collection(task) && observe_owner(task, SECRET_NAME, &task->observed.service) &&
    expected_platform(task) && bus_current(task) && broker_live(broker);
}
static bool broker_write(struct broker *broker, const unsigned char *bytes, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    if (!broker_live(broker)) return false;
    size_t written = 0; int result = SSL_write_ex(broker->tls, bytes + offset, size - offset, &written);
    if (result == 1) { if (!written) return broker_fail(broker, "broker_transport_interrupted"); offset += written; }
    else if (!broker_tls_wait(broker, SSL_get_error(broker->tls, result))) return false;
  }
  return true;
}
/* Reads are never retried as requests. A short/failed response remains an
 * ambiguous transport outcome after release, not a no-effect assertion. */
static ssize_t broker_read(struct broker *broker, unsigned char *bytes, size_t size) {
  for (;;) {
    if (!broker_live(broker)) return -1;
    size_t received = 0; int result = SSL_read_ex(broker->tls, bytes, size, &received);
    if (result == 1) return received ? (ssize_t)received : -1;
    int error = SSL_get_error(broker->tls, result);
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (!broker_tls_wait(broker, error)) return -1;
  }
}
static bool broker_line(struct broker *broker, char *line, size_t capacity, size_t *total) {
  size_t length = 0;
  while (length + 1 < capacity) {
    unsigned char byte;
    if (broker_read(broker, &byte, 1) != 1 || ++*total > BROKER_HEADER_CAP) return broker_fail(broker, "broker_response_refused");
    if (byte == '\r') {
      if (broker_read(broker, &byte, 1) != 1 || ++*total > BROKER_HEADER_CAP || byte != '\n')
        return broker_fail(broker, "broker_response_refused");
      line[length] = '\0'; return true;
    }
    if (byte == '\n' || byte == 0 || (byte < 0x20 && byte != '\t') || byte > 0x7e) return broker_fail(broker, "broker_response_refused");
    line[length++] = (char)byte;
  }
  return broker_fail(broker, "broker_response_refused");
}
static bool broker_contains(const unsigned char *bytes, size_t size, const unsigned char *needle, size_t needle_size) {
  return needle_size && size >= needle_size && memmem(bytes, size, needle, needle_size) != NULL;
}
static bool broker_no_echo_plain(struct broker *broker, const unsigned char *bytes, size_t size) {
  const unsigned char *secret = broker->platform.secret; size_t count = broker->platform.secret_size;
  if (broker_contains(bytes, size, secret, count)) return broker_fail(broker, "broker_response_refused");
  gchar *base64 = g_base64_encode(secret, count);
  bool echoed = base64 && broker_contains(bytes, size, (const unsigned char *)base64, strlen(base64));
  if (base64 && !echoed) {
    size_t length = strlen(base64);
    for (size_t index = 0; index < length; index++) {
      if (base64[index] == '+') base64[index] = '-';
      else if (base64[index] == '/') base64[index] = '_';
    }
    while (length && base64[length - 1] == '=') length--;
    echoed = broker_contains(bytes, size, (const unsigned char *)base64, length);
  }
  if (base64) { wipe(base64, strlen(base64)); g_free(base64); }
  unsigned char *encoded = malloc(count * 2 + 1);
  if (!encoded) return broker_fail(broker, "broker_worker_unavailable");
  if (!echoed) {
    for (size_t index = 0; index < count; index++) snprintf((char *)encoded + index * 2, 3, "%02x", secret[index]);
    echoed = broker_contains(bytes, size, encoded, count * 2);
    for (size_t index = 0; index < count * 2; index++) if (encoded[index] >= 'a' && encoded[index] <= 'f') encoded[index] -= 'a' - 'A';
    echoed |= broker_contains(bytes, size, encoded, count * 2);
  }
  if (!echoed) {
    size_t length = 0;
    for (size_t index = 0; index < count; index++) {
      if (secret[index] == '"' || secret[index] == '\\') encoded[length++] = '\\';
      encoded[length++] = secret[index];
    }
    echoed = broker_contains(bytes, size, encoded, length);
  }
  wipe(encoded, count * 2 + 1); free(encoded);
  if (echoed) return broker_fail(broker, "broker_response_refused");
  return true;
}
static int broker_hex_digit(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}
static bool broker_unicode_hex(const unsigned char *bytes, size_t size, size_t at, unsigned *point) {
  if (at >= size || size - at <= 4) return false;
  *point = 0;
  for (size_t digit = 1; digit <= 4; digit++) {
    int value = broker_hex_digit(bytes[at + digit]);
    if (value < 0) return false;
    *point = *point * 16 + (unsigned)value;
  }
  return true;
}
static bool broker_no_echo_normalized(struct broker *broker, const unsigned char *bytes, size_t size) {
  if (!broker_no_echo_plain(broker, bytes, size)) return false;
  /* NUL separates string projections and cannot occur in the Bearer key.
   * Normalize only valid UTF-8 segments; invalid JSON/UTF-8 still belongs to
   * the closed production provider decoder, not this leak screen. */
  for (size_t start = 0; start < size;) {
    size_t end = start; while (end < size && bytes[end]) end++;
    if (end > start && g_utf8_validate((const char *)bytes + start, (gssize)(end - start), NULL)) {
      gchar *normalized = g_utf8_normalize((const char *)bytes + start, (gssize)(end - start), G_NORMALIZE_NFC);
      if (!normalized) return broker_fail(broker, "broker_worker_unavailable");
      size_t count = strlen(normalized); bool valid = broker_no_echo_plain(broker, (const unsigned char *)normalized, count);
      wipe(normalized, count); g_free(normalized); if (!valid) return false;
    }
    start = end + 1;
  }
  return true;
}
static bool broker_no_echo(struct broker *broker, const unsigned char *bytes, size_t size) {
  /* OpenAI arguments are themselves JSON strings. A single unescape pass
   * would let a later provider/schema parse recover the key in JavaScript.
   * Two bounded native buffers screen up to 64 string-projection layers,
   * including Unicode/NFC, without ever rewriting the original response.
   * This finite guard is not arbitrary malicious-transform confidentiality. */
  unsigned char *first = malloc(size + 1), *second = malloc(size + 1);
  if (!first || !second) { free(first); free(second); return broker_fail(broker, "broker_worker_unavailable"); }
  const unsigned char *current = bytes; size_t current_size = size; bool valid = true;
  for (unsigned depth = 0;; depth++) {
    if (!broker_live(broker) || !broker_no_echo_normalized(broker, current, current_size)) { valid = false; break; }
    unsigned char *decoded = current == first ? second : first;
    size_t count = 0; bool escaped = false;
    for (size_t index = 0; index < current_size; index++) {
      if (current[index] != '"') continue;
      while (++index < current_size && current[index] != '"') {
        unsigned char byte = current[index];
        if (byte == '\\') {
          escaped = true; if (++index == current_size) break;
          byte = current[index];
          if (byte == 'u') {
            unsigned point;
            if (broker_unicode_hex(current, current_size, index, &point)) {
              index += 4;
              if (point >= 0xd800 && point <= 0xdbff) {
                unsigned low;
                if (current_size - index > 6 && current[index + 1] == '\\' && current[index + 2] == 'u' &&
                    broker_unicode_hex(current, current_size, index + 2, &low) && low >= 0xdc00 && low <= 0xdfff) {
                  point = 0x10000 + (point - 0xd800) * 1024 + low - 0xdc00; index += 6;
                }
              }
              if (g_unichar_validate(point)) { count += (size_t)g_unichar_to_utf8(point, (char *)decoded + count); continue; }
            }
            byte = 0;
          } else if (byte == 'b') byte = '\b';
          else if (byte == 'f') byte = '\f';
          else if (byte == 'n') byte = '\n';
          else if (byte == 'r') byte = '\r';
          else if (byte == 't') byte = '\t';
          else if (byte != '"' && byte != '\\' && byte != '/') byte = 0;
        }
        decoded[count++] = byte;
      }
      decoded[count++] = 0;
    }
    if (!escaped) break;
    if (depth == 64) { valid = broker_fail(broker, "broker_response_refused"); break; }
    current = decoded; current_size = count;
  }
  wipe(first, size + 1); wipe(second, size + 1); free(first); free(second); return valid;
}
static bool broker_append_response(struct broker *broker, const unsigned char *bytes, size_t size) {
  size_t count = size;
  if (count > BROKER_BODY_CAP + 1 - broker->response_size) count = BROKER_BODY_CAP + 1 - broker->response_size;
  memcpy(broker->response + broker->response_size, bytes, count); broker->response_size += count;
  broker->response_over_limit = broker->response_size > BROKER_BODY_CAP;
  return true;
}
static bool broker_exact_response(struct broker *broker, uint64_t size) {
  unsigned char bytes[8192];
  while (size && !broker->response_over_limit) {
    size_t count = size > sizeof(bytes) ? sizeof(bytes) : (size_t)size;
    ssize_t received = broker_read(broker, bytes, count);
    if (received <= 0) return broker_fail(broker, "broker_transport_interrupted");
    broker_append_response(broker, bytes, (size_t)received); size -= (size_t)received;
  }
  wipe(bytes, sizeof(bytes)); return true;
}
static bool broker_response(struct broker *broker) {
  char line[8193]; size_t header_bytes = 0; unsigned informational = 0;
  uint64_t content_length = 0; bool length_present = false, chunked = false, media_present = false;
  for (;;) {
    if (!broker_line(broker, line, sizeof(line), &header_bytes) || strlen(line) < 12 || strncmp(line, "HTTP/1.1 ", 9) ||
        line[9] < '1' || line[9] > '5' || line[10] < '0' || line[10] > '9' || line[11] < '0' || line[11] > '9' ||
        (line[12] && line[12] != ' ')) return broker_fail(broker, "broker_response_refused");
    broker->status = (unsigned)(line[9] - '0') * 100 + (unsigned)(line[10] - '0') * 10 + (unsigned)(line[11] - '0');
    length_present = false; chunked = false; media_present = false; broker->media_type = "unknown";
    unsigned header_count = 0;
    while (broker_line(broker, line, sizeof(line), &header_bytes) && line[0]) {
      if (++header_count > 128 || line[0] == ' ' || line[0] == '\t') return broker_fail(broker, "broker_response_refused");
      char *colon = strchr(line, ':');
      if (!colon || colon == line) return broker_fail(broker, "broker_response_refused");
      *colon = '\0';
      if (strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~") != strlen(line))
        return broker_fail(broker, "broker_response_refused");
      char *value = colon + 1; while (*value == ' ' || *value == '\t') value++;
      size_t value_size = strlen(value); while (value_size && (value[value_size - 1] == ' ' || value[value_size - 1] == '\t')) value[--value_size] = '\0';
      if (!broker_no_echo(broker, (const unsigned char *)value, value_size)) return false;
      if (!strcasecmp(line, "content-length")) {
        if (length_present || !value_size || strspn(value, "0123456789") != value_size || value_size > 20)
          return broker_fail(broker, "broker_response_refused");
        errno = 0; char *end; content_length = strtoull(value, &end, 10);
        if (errno || *end) return broker_fail(broker, "broker_response_refused");
        length_present = true;
      } else if (!strcasecmp(line, "transfer-encoding")) {
        if (chunked || strcasecmp(value, "chunked")) return broker_fail(broker, "broker_response_refused");
        chunked = true;
      } else if (!strcasecmp(line, "content-encoding") && strcasecmp(value, "identity")) return broker_fail(broker, "broker_response_refused");
      else if (!strcasecmp(line, "content-type")) {
        if (media_present) return broker_fail(broker, "broker_response_refused");
        media_present = true; char *semicolon = strchr(value, ';'); if (semicolon) *semicolon = '\0';
        if (!strcasecmp(value, "application/json")) broker->media_type = "application/json";
        else if (!strcasecmp(value, "text/event-stream")) broker->media_type = "text/event-stream";
        else if (!strcasecmp(value, "application/x-ndjson") || !strcasecmp(value, "application/ndjson")) broker->media_type = "application/x-ndjson";
      }
    }
    if (broker->error || (chunked && length_present)) return broker_fail(broker, "broker_response_refused");
    if (broker->status >= 200) break;
    if (broker->status == 101 || ++informational > 8 || chunked || (length_present && content_length)) return broker_fail(broker, "broker_response_refused");
  }
  /* This initial installed recipe is non-streaming Chat Completions. The
   * streaming decoder joins deltas, which needs its own native secret screen;
   * a signed capability flag cannot turn an unimplemented path into safety. */
  if (strcmp(broker->media_type, "application/json")) return broker_fail(broker, "broker_response_refused");
  broker->response = calloc(1, BROKER_BODY_CAP + 1);
  if (!broker->response) return broker_fail(broker, "broker_worker_unavailable");
  if (broker->status == 204 || broker->status == 304) {
    if (chunked || (length_present && content_length)) return broker_fail(broker, "broker_response_refused");
  } else if (chunked) {
    for (;;) {
      if (!broker_line(broker, line, sizeof(line), &header_bytes) || !line[0] || strlen(line) > 16 || strspn(line, "0123456789abcdefABCDEF") != strlen(line))
        return broker_fail(broker, "broker_response_refused");
      errno = 0; char *end; uint64_t count = strtoull(line, &end, 16);
      if (errno || *end) return broker_fail(broker, "broker_response_refused");
      if (!count) {
        /* No untrusted trailer state survives or mutates the typed response. */
        if (!broker_line(broker, line, sizeof(line), &header_bytes) || line[0]) return broker_fail(broker, "broker_response_refused");
        break;
      }
      if (!broker_exact_response(broker, count)) return false;
      if (broker->response_over_limit) break;
      unsigned char terminator[2];
      for (size_t index = 0; index < 2; index++) if (broker_read(broker, terminator + index, 1) != 1) return broker_fail(broker, "broker_transport_interrupted");
      if (terminator[0] != '\r' || terminator[1] != '\n') return broker_fail(broker, "broker_response_refused");
    }
  } else if (length_present) {
    if (!broker_exact_response(broker, content_length)) return false;
  } else {
    unsigned char bytes[8192];
    while (!broker->response_over_limit) {
      ssize_t count = broker_read(broker, bytes, sizeof(bytes));
      if (count < 0) return false;
      if (!count) break;
      broker_append_response(broker, bytes, (size_t)count);
    }
    wipe(bytes, sizeof(bytes));
  }
  wipe(line, sizeof(line));
  return broker_no_echo(broker, broker->response, broker->response_size) && broker_live(broker);
}
static bool broker_exchange(struct broker *broker) {
  size_t capacity = strlen(broker->path) + strlen(broker->host) + broker->platform.secret_size + 512;
  unsigned char *headers = malloc(capacity);
  if (!headers) return broker_fail(broker, "broker_worker_unavailable");
  int prefix = snprintf((char *)headers, capacity, "POST %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: %zu\r\nAuthorization: Bearer ",
    broker->path, broker->host, broker->port, broker->body_size);
  bool valid = prefix > 0 && (size_t)prefix + broker->platform.secret_size + 4 <= capacity;
  size_t size = valid ? (size_t)prefix : 0;
  if (valid) { memcpy(headers + size, broker->platform.secret, broker->platform.secret_size); size += broker->platform.secret_size; memcpy(headers + size, "\r\n\r\n", 4); size += 4; }
  valid = valid && broker_write(broker, headers, size) && broker_write(broker, broker->body, broker->body_size);
  wipe(headers, capacity); free(headers);
  return valid && broker_response(broker);
}
static void broker_retire(struct broker *broker) {
  if (broker->tls) { SSL_free(broker->tls); broker->tls = NULL; }
  if (broker->tls_context) { SSL_CTX_free(broker->tls_context); broker->tls_context = NULL; }
  if (broker->connection) {
    GError *error = NULL;
    if (!g_io_stream_close(G_IO_STREAM(broker->connection), NULL, &error)) { broker->unsafe = true; atomic_store(&retirement_failed, true); broker_fail(broker, "resource_retirement"); }
    g_clear_error(&error);
    if (!broker->unsafe) { g_object_unref(broker->connection); broker->connection = NULL; broker->socket = NULL; }
  }
  (void)broker_platform_retire(broker);
  if (broker->platform.secret) { wipe(broker->platform.secret, broker->platform.secret_size); free(broker->platform.secret); broker->platform.secret = NULL; }
  if (broker->body) { wipe(broker->body, broker->body_size); free(broker->body); broker->body = NULL; }
  if (broker->trust) { wipe(broker->trust, broker->trust_size); free(broker->trust); broker->trust = NULL; }
  ERR_clear_error();
}

static napi_value broker_error_value(struct broker *broker) {
  napi_value message, result;
  napi_create_string_utf8(broker->env, broker->unsafe ? "Installed model broker resources did not retire" : "Installed model broker operation refused", NAPI_AUTO_LENGTH, &message);
  napi_create_error(broker->env, NULL, message, &result);
  set_string(broker->env, result, "code", broker->unsafe ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_MODEL_BROKER");
  set_string(broker->env, result, "brokerCode", broker->unsafe ? "resource_retirement" : broker->error ? broker->error : "broker_operation_refused");
  return result;
}
static napi_value broker_closed_value(struct broker *broker) {
  napi_value result; napi_create_object(broker->env, &result);
  set_string(broker->env, result, "kind", "broker_transport_closed");
  set_string(broker->env, result, "brokerFenceTokenDigest", broker->token_digest);
  set_string(broker->env, result, "bodyBytesDigest", broker->body_digest);
  set_boolean(broker->env, result, "networkStarted", broker->network_started);
  set_boolean(broker->env, result, "requestStarted", broker->request_started);
  set_boolean(broker->env, result, "tokenRevoked", true);
  set_number(broker->env, result, "matchingActiveReleaseCount", 0);
  napi_object_freeze(broker->env, result); return result;
}
static void broker_free(napi_env env, struct broker *broker) {
  /* A referenced handle cannot finalize before retirement. Uncertainty keeps
   * its owning C allocation until process death rather than forgetting it. */
  if (!broker->retired || broker->unsafe) return;
  if (broker->close_promise && !broker->env_closing) napi_delete_reference(env, broker->close_promise);
  if (broker->response) { wipe(broker->response, BROKER_BODY_CAP + 1); free(broker->response); }
  if (broker->mutex_ready && pthread_mutex_destroy(&broker->release_mutex)) {
    atomic_store(&retirement_failed, true); broker->unsafe = true;
    broker->unretired_next = unretired_brokers; unretired_brokers = broker; return;
  }
  wipe(broker, sizeof(*broker)); free(broker);
}
static void broker_finalize(napi_env env, void *data, void *hint) {
  (void)hint; struct broker *broker = data; broker->finalize_requested = true;
  /* N-API teardown does not promise reference/finalizer ordering. The native
   * allocation outlives every actual guard borrow, even after JS is gone. */
  if (!broker->fence_borrows) broker_free(env, broker);
}
static struct broker *broker_receiver(napi_env env, napi_callback_info info, size_t *argc, napi_value *args) {
  napi_value receiver; bool tagged = false; struct broker *broker = NULL;
  if (napi_get_cb_info(env, info, argc, args, &receiver, NULL) != napi_ok ||
      napi_check_object_type_tag(env, receiver, &broker_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, receiver, (void **)&broker) != napi_ok || !broker || broker->env != env ||
      broker->creator_pid != getpid() || syscall(SYS_gettid) != getpid()) {
    napi_value text, error; napi_create_string_utf8(env, "Invalid installed model broker owner", NAPI_AUTO_LENGTH, &text);
    napi_create_type_error(env, NULL, text, &error); napi_throw(env, error); return NULL;
  }
  return broker;
}
static napi_value broker_stage_call(napi_env env, napi_callback_info info, enum broker_stage stage) {
  napi_value args[2]; size_t argc = 2; struct broker_binding binding = {0};
  struct broker *broker = broker_receiver(env, info, &argc, args);
  if (!broker) return NULL;
  bool valid = argc == 1 && !broker->working && !broker->closing && !broker->retired && !broker->error && broker->prepared &&
    broker_binding_value(env, args[0], &binding) && !strcmp(binding.token_digest, broker->token_digest) && broker_live(broker);
  if (stage == BROKER_CONNECT) valid = valid && !broker->bound && !broker->connected;
  else valid = valid && broker->bound && broker->connected && !broker->exchanged && !memcmp(&binding, &broker->binding, sizeof(binding));
  if (!valid) {
    napi_value text, error; napi_create_string_utf8(env, "Installed model broker release is unavailable or mismatched", NAPI_AUTO_LENGTH, &text);
    napi_create_type_error(env, NULL, text, &error); napi_throw(env, error); return NULL;
  }
  napi_value promise;
  if (napi_create_promise(env, &broker->phase_deferred, &promise) != napi_ok) return NULL;
  if (pthread_mutex_lock(&broker->release_mutex)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); broker_fail(broker, "resource_retirement");
  } else {
    if (broker->token_revoked || (stage == BROKER_CONNECT && broker->active_releases)) broker_fail(broker, "broker_release_fenced");
    else if (stage == BROKER_CONNECT) {
      broker->binding = binding; broker->bound = true;
      /* Conservative by construction: after this point even a queue/network
       * refusal cannot produce a claim refund or a never-started assertion. */
      broker->network_started = true; broker->active_releases = 1;
    } else { broker->request_started = true; broker->exchanged = true; }
    if (pthread_mutex_unlock(&broker->release_mutex)) {
      broker->unsafe = true; atomic_store(&retirement_failed, true); broker_fail(broker, "resource_retirement");
    }
  }
  if (broker->error || !broker_queue(broker, stage)) {
    napi_reject_deferred(env, broker->phase_deferred, broker_error_value(broker)); broker->phase_deferred = NULL;
    broker_begin_close(broker);
  }
  return promise;
}
static napi_value broker_connect_call(napi_env env, napi_callback_info info) { return broker_stage_call(env, info, BROKER_CONNECT); }
static napi_value broker_release_call(napi_env env, napi_callback_info info) { return broker_stage_call(env, info, BROKER_EXCHANGE); }
static napi_value broker_close_call(napi_env env, napi_callback_info info) {
  napi_value args[1]; size_t argc = 1; struct broker *broker = broker_receiver(env, info, &argc, args);
  if (!broker) return NULL;
  if (argc) { napi_throw_type_error(env, NULL, "Installed model broker close accepts no fields"); return NULL; }
  napi_value promise;
  if (broker->close_promise) { napi_get_reference_value(env, broker->close_promise, &promise); return promise; }
  if (napi_create_promise(env, &broker->close_deferred, &promise) != napi_ok ||
      napi_create_reference(env, promise, 1, &broker->close_promise) != napi_ok) return NULL;
  if (broker->close_finished) {
    if (broker->unsafe) napi_reject_deferred(env, broker->close_deferred, broker_error_value(broker));
    else napi_resolve_deferred(env, broker->close_deferred, broker_closed_value(broker));
    broker->close_deferred = NULL;
  } else broker_begin_close(broker);
  return promise;
}
static napi_value broker_retain_fence_call(napi_env env, napi_callback_info info) {
  napi_value args[1]; size_t argc = 1; struct broker *broker = broker_receiver(env, info, &argc, args);
  if (!broker) return NULL;
  if (argc || !broker->prepared || broker->working || broker->closing || broker->retired || broker->unsafe ||
      !broker->mutex_ready || atomic_load(&broker->fence_retained) || broker->fence_locked || !broker_live(broker)) {
    napi_throw_type_error(env, NULL, "Installed model broker original fence cannot be retained"); return NULL;
  }
  if (pthread_mutex_lock(&broker->release_mutex)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); napi_throw(env, broker_error_value(broker)); return NULL;
  }
  bool valid = !broker->token_revoked && !broker->active_releases && !broker->network_started && !broker->request_started;
  if (valid) atomic_store(&broker->fence_retained, true);
  if (pthread_mutex_unlock(&broker->release_mutex)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); napi_throw(env, broker_error_value(broker)); return NULL;
  }
  if (!valid) { napi_throw_type_error(env, NULL, "Installed model broker original fence is already released"); return NULL; }
  napi_value result; napi_get_undefined(env, &result); return result;
}
static bool broker_fence_live(struct broker_fence *fence) {
  struct broker *broker = fence->broker; char digest[65];
  bool valid = fence->active && broker && fence->creator_pid == getpid() && syscall(SYS_gettid) == getpid() &&
    !broker->unsafe && !broker->env_closing && !atomic_load(&retirement_failed) && broker->creator_pid == getpid() &&
    broker->retired && broker->close_finished && !broker->working && broker->mutex_ready && broker->fence_locked &&
    atomic_load(&broker->fence_retained) && broker->token_revoked && !broker->active_releases &&
    !broker->network_started && !broker->request_started && broker->bound &&
    !memcmp(&broker->binding, &fence->binding, sizeof(fence->binding)) &&
    digest_hex(broker->token, sizeof(broker->token), digest) && !strcmp(digest, fence->binding.token_digest);
  if (!valid) return false;
  int locked = pthread_mutex_trylock(&broker->release_mutex);
  if (locked == EBUSY) return true;
  if (!locked) (void)pthread_mutex_unlock(&broker->release_mutex);
  broker->unsafe = true; atomic_store(&retirement_failed, true); return false;
}
static bool broker_fence_drop(struct broker_fence *fence) {
  if (!fence->active) return true;
  struct broker *broker = fence->broker;
  if (!broker || fence->creator_pid != getpid() || syscall(SYS_gettid) != getpid() ||
      (!(broker->env_closing && !broker->fence_locked) &&
        (!broker->fence_locked || pthread_mutex_unlock(&broker->release_mutex)))) {
    if (broker) broker->unsafe = true;
    atomic_store(&retirement_failed, true); return false;
  }
  broker->fence_locked = false;
  if (fence->original && !broker->env_closing && napi_delete_reference(fence->env, fence->original) != napi_ok) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); return false;
  }
  fence->original = NULL; fence->active = false; fence->broker = NULL;
  if (!broker->fence_borrows) { broker->unsafe = true; atomic_store(&retirement_failed, true); return false; }
  broker->fence_borrows--;
  if (broker->finalize_requested && !broker->fence_borrows) broker_free(fence->env, broker);
  return true;
}
static void broker_fence_finalize(napi_env env, void *data, void *hint) {
  (void)env; (void)hint; struct broker_fence *fence = data;
  if (!broker_fence_drop(fence)) return; /* uncertainty retains its native owner */
  wipe(fence, sizeof(*fence)); free(fence);
}
static struct broker_fence *broker_fence_receiver(napi_env env, napi_callback_info info) {
  napi_value receiver; size_t argc = 1; napi_value args[1]; bool tagged = false; struct broker_fence *fence = NULL;
  if (napi_get_cb_info(env, info, &argc, args, &receiver, NULL) != napi_ok || argc ||
      napi_check_object_type_tag(env, receiver, &broker_fence_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, receiver, (void **)&fence) != napi_ok || !fence || fence->env != env ||
      fence->creator_pid != getpid() || syscall(SYS_gettid) != getpid()) {
    napi_throw_type_error(env, NULL, "Invalid installed model no-release fence owner"); return NULL;
  }
  return fence;
}
static napi_value broker_fence_assert_call(napi_env env, napi_callback_info info) {
  struct broker_fence *fence = broker_fence_receiver(env, info); if (!fence) return NULL;
  if (fence->broker && (fence->broker->unsafe || atomic_load(&retirement_failed))) {
    fence->broker->unsafe = true; napi_throw(env, broker_error_value(fence->broker)); return NULL;
  }
  if (!broker_fence_live(fence)) {
    if (fence->broker && fence->broker->unsafe) napi_throw(env, broker_error_value(fence->broker));
    else napi_throw_type_error(env, NULL, "Installed model no-release fence is not held");
    return NULL;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
}
static napi_value broker_fence_close_call(napi_env env, napi_callback_info info) {
  struct broker_fence *fence = broker_fence_receiver(env, info); if (!fence) return NULL;
  if (!broker_fence_drop(fence)) {
    napi_value text, error; napi_create_string_utf8(env, "Installed model no-release fence did not retire", NAPI_AUTO_LENGTH, &text);
    napi_create_error(env, NULL, text, &error); set_string(env, error, "code", "ERR_CLIQ_RESOURCE_RETIREMENT"); napi_throw(env, error); return NULL;
  }
  napi_value result; napi_get_undefined(env, &result); return result;
}
static napi_value broker_acquire_fence_call(napi_env env, napi_callback_info info) {
  napi_value args[2]; size_t argc = 2; struct broker_binding binding = {0};
  struct broker *broker = broker_receiver(env, info, &argc, args); if (!broker) return NULL;
  if (argc != 1 || !broker->retired || !broker->close_finished || broker->working || broker->unsafe || broker->env_closing || atomic_load(&retirement_failed) ||
      !broker->mutex_ready || !atomic_load(&broker->fence_retained) || broker->fence_locked ||
      broker->network_started || broker->request_started || !broker_binding_value(env, args[0], &binding) ||
      strcmp(binding.token_digest, broker->token_digest)) {
    napi_throw_type_error(env, NULL, "Installed model no-release fence is unavailable or mismatched"); return NULL;
  }
  if (pthread_mutex_lock(&broker->release_mutex)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); napi_throw(env, broker_error_value(broker)); return NULL;
  }
  char digest[65];
  bool valid = broker->token_revoked && !broker->active_releases && !broker->network_started && !broker->request_started &&
    digest_hex(broker->token, sizeof(broker->token), digest) && !strcmp(digest, binding.token_digest) &&
    (!broker->bound || !memcmp(&binding, &broker->binding, sizeof(binding)));
  struct broker_fence *fence = valid ? calloc(1, sizeof(*fence)) : NULL; napi_value value = NULL, original;
  if (fence) {
    broker->fence_locked = true; broker->bound = true; broker->binding = binding; broker->fence_borrows++;
    fence->broker = broker; fence->env = env; fence->binding = binding; fence->creator_pid = getpid(); fence->active = true;
    const napi_property_descriptor methods[] = {
      {"assertHeld", NULL, broker_fence_assert_call, NULL, NULL, NULL, napi_default, NULL},
      {"close", NULL, broker_fence_close_call, NULL, NULL, NULL, napi_default, NULL},
    };
    if (napi_get_reference_value(env, broker->handle, &original) != napi_ok || napi_create_reference(env, original, 1, &fence->original) != napi_ok ||
        napi_create_object(env, &value) != napi_ok || napi_type_tag_object(env, value, &broker_fence_tag) != napi_ok ||
        napi_wrap(env, value, fence, broker_fence_finalize, NULL, NULL) != napi_ok ||
        napi_define_properties(env, value, sizeof(methods) / sizeof(*methods), methods) != napi_ok || napi_object_freeze(env, value) != napi_ok) {
      if (!broker_fence_drop(fence)) { napi_throw(env, broker_error_value(broker)); return NULL; }
      /* A successfully wrapped allocation is owned by its finalizer. */
      void *wrapped = NULL;
      if (!value || napi_unwrap(env, value, &wrapped) != napi_ok || wrapped != fence) { wipe(fence, sizeof(*fence)); free(fence); }
      value = NULL;
    }
  } else if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
  if (!value) { napi_throw_type_error(env, NULL, "Installed model no-release fence could not be acquired"); return NULL; }
  return value;
}
static napi_value broker_release_fence_call(napi_env env, napi_callback_info info) {
  napi_value args[1]; size_t argc = 1; struct broker *broker = broker_receiver(env, info, &argc, args); if (!broker) return NULL;
  if (argc || !broker->retired || !broker->close_finished || broker->fence_locked) {
    napi_throw_type_error(env, NULL, "Installed model original fence still has an owning guard or unfinished join"); return NULL;
  }
  if (broker->unsafe) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); napi_throw(env, broker_error_value(broker)); return NULL;
  }
  atomic_store(&broker->fence_retained, false); broker_finish_close(broker);
  if (broker->unsafe) { napi_throw(env, broker_error_value(broker)); return NULL; }
  napi_value result; napi_get_undefined(env, &result); return result;
}
static napi_value broker_handle_value(struct broker *broker, napi_value ready) {
  napi_value handle;
  if (napi_create_object(broker->env, &handle) != napi_ok ||
      napi_type_tag_object(broker->env, handle, &broker_tag) != napi_ok ||
      napi_wrap(broker->env, handle, broker, broker_finalize, NULL, NULL) != napi_ok) return NULL;
  const napi_property_descriptor methods[] = {
    {"connect", NULL, broker_connect_call, NULL, NULL, NULL, napi_default, NULL},
    {"releaseBody", NULL, broker_release_call, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, broker_close_call, NULL, NULL, NULL, napi_default, NULL},
    {"retainDispatchFence", NULL, broker_retain_fence_call, NULL, NULL, NULL, napi_default, NULL},
    {"acquireNoReleaseFence", NULL, broker_acquire_fence_call, NULL, NULL, NULL, napi_default, NULL},
    {"releaseDispatchFence", NULL, broker_release_fence_call, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_define_properties(broker->env, handle, sizeof(methods) / sizeof(*methods), methods) != napi_ok ||
      napi_set_named_property(broker->env, handle, "ready", ready) != napi_ok) return NULL;
  set_string(broker->env, handle, "brokerFenceTokenDigest", broker->token_digest);
  if (napi_create_reference(broker->env, handle, 1, &broker->handle) != napi_ok || napi_object_freeze(broker->env, handle) != napi_ok) return NULL;
  return handle;
}
static void broker_timer_closed(uv_handle_t *timer) {
  struct broker *broker = timer->data; broker->timer_closed = true; broker_finish_close(broker);
}
static void broker_finish_close(struct broker *broker) {
  if (!broker->retired || (broker->timer_ready && !broker->timer_closed)) return;
  bool retained = atomic_load(&broker->fence_retained);
  if (broker->env_closing && !broker->fence_locked) { atomic_store(&broker->fence_retained, false); retained = false; }
  if (!retained && broker->mutex_ready) {
    wipe(broker->token, sizeof(broker->token));
    if (pthread_mutex_destroy(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
    else broker->mutex_ready = false;
  }
  if (!retained && broker->cleanup_hook) {
    if (napi_remove_async_cleanup_hook(broker->cleanup_hook) != napi_ok) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
    else broker->cleanup_hook = NULL;
  }
  if (broker->close_finished) {
    if (!retained && !broker->unsafe && broker->handle) {
      if (broker->env_closing) broker->handle = NULL; /* environment owns reference teardown */
      else if (napi_delete_reference(broker->env, broker->handle) != napi_ok) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
      else broker->handle = NULL;
    }
    return;
  }
  broker->close_finished = true;
  /* No worker can still borrow the cancellable. Its wakeup owner is retired
   * on this main-thread cut, never concurrently with a later close call. */
  if (broker->platform.cancel && !broker->unsafe) { g_object_unref(broker->platform.cancel); broker->platform.cancel = NULL; }
  if (!broker->env_closing && (broker->ready_deferred || broker->phase_deferred || broker->close_deferred)) {
    napi_handle_scope scope;
    if (napi_open_handle_scope(broker->env, &scope) != napi_ok) napi_fatal_error("cliq-model-broker", NAPI_AUTO_LENGTH, "broker close scope unavailable", NAPI_AUTO_LENGTH);
    /* Preparation refusal/cancellation is not a free-failure cut until its
     * original worker, connection, timer and cleanup-hook owners have joined.
     * Keep this deferred separate from both later release phases. */
    if (broker->ready_deferred) {
      napi_reject_deferred(broker->env, broker->ready_deferred, broker_error_value(broker));
      broker->ready_deferred = NULL;
    }
    if (broker->phase_deferred) {
      napi_value result = NULL;
      if (!broker->error && !broker->unsafe && broker->exchanged && broker->response) {
        napi_create_object(broker->env, &result);
        set_string(broker->env, result, "kind", broker->response_over_limit ? "prefix_over_limit" : "complete");
        set_number(broker->env, result, "status", broker->status); set_string(broker->env, result, "mediaType", broker->media_type);
        napi_value bytes;
        if (napi_create_buffer_copy(broker->env, broker->response_size, broker->response, NULL, &bytes) != napi_ok ||
            napi_set_named_property(broker->env, result, "bodyBytes", bytes) != napi_ok) broker_fail(broker, "broker_worker_unavailable");
      }
      if (broker->error || broker->unsafe || !result) napi_reject_deferred(broker->env, broker->phase_deferred, broker_error_value(broker));
      else napi_resolve_deferred(broker->env, broker->phase_deferred, result);
      broker->phase_deferred = NULL;
    }
    if (broker->close_deferred) {
      if (broker->unsafe) napi_reject_deferred(broker->env, broker->close_deferred, broker_error_value(broker));
      else napi_resolve_deferred(broker->env, broker->close_deferred, broker_closed_value(broker));
      broker->close_deferred = NULL;
    }
    napi_close_handle_scope(broker->env, scope);
  }
  if (broker->response) { wipe(broker->response, BROKER_BODY_CAP + 1); free(broker->response); broker->response = NULL; }
  if (broker->unsafe) {
    broker->unretired_next = unretired_brokers; unretired_brokers = broker;
  } else if (!retained && broker->handle) {
    if (!broker->env_closing) napi_delete_reference(broker->env, broker->handle);
    broker->handle = NULL;
  }
}
static void broker_close_timer(struct broker *broker) {
  if (broker->timer_ready && !broker->timer_closing) {
    broker->timer_closing = true; uv_close((uv_handle_t *)&broker->timer, broker_timer_closed);
  }
}
static void broker_worker(napi_env env, void *data) {
  (void)env; struct broker *broker = data;
  if (broker->stage == BROKER_RETIRE) broker_retire(broker);
  else if (!broker_live(broker)) return;
  else if (broker->stage == BROKER_PREPARE) (void)broker_read_key(broker);
  else if (broker->stage == BROKER_CONNECT) (void)broker_connect(broker);
  else (void)broker_exchange(broker);
  if (broker->stage != BROKER_RETIRE && broker->platform.error && !broker->error) broker_fail(broker, "credential_redemption_refused");
  if (broker->platform.unsafe || atomic_load(&retirement_failed)) { broker->unsafe = true; broker_fail(broker, "resource_retirement"); }
  ERR_clear_error();
}
static void broker_complete(napi_env env, napi_status status, void *data) {
  struct broker *broker = data; broker->working = false;
  if (broker->work && napi_delete_async_work(env, broker->work) != napi_ok) {
    broker->unsafe = true; atomic_store(&retirement_failed, true);
    if (broker->unretired_work_count < 4) broker->unretired_work[broker->unretired_work_count++] = broker->work;
  }
  broker->work = NULL;
  if (status != napi_ok) broker_fail(broker, "broker_worker_unavailable");
  if (broker->stage == BROKER_RETIRE) {
    if (pthread_mutex_lock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
    else {
      broker->token_revoked = true; broker->active_releases = 0;
      if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
    }
    broker->retired = true; broker_close_timer(broker); broker_finish_close(broker); return;
  }
  if (!broker_live(broker) || broker->closing) broker_fail(broker, "broker_cancelled_or_expired");
  if (!broker->error && !broker->closing && broker->stage == BROKER_PREPARE && !broker->env_closing && broker->ready_deferred) {
    napi_value result = NULL;
    napi_get_undefined(env, &result);
    if (!result) broker_fail(broker, "broker_worker_unavailable");
    else {
      broker->prepared = true;
      napi_resolve_deferred(env, broker->ready_deferred, result); broker->ready_deferred = NULL;
    }
  }
  if (!broker->error && !broker->closing && broker->stage == BROKER_CONNECT && !broker->env_closing && broker->phase_deferred) {
    napi_value result = NULL;
    broker->connected = true; napi_get_undefined(env, &result);
    if (broker->error || !result) napi_reject_deferred(env, broker->phase_deferred, broker_error_value(broker));
    else napi_resolve_deferred(env, broker->phase_deferred, result);
    broker->phase_deferred = NULL;
  }
  if (broker->error || broker->closing || broker->stage == BROKER_EXCHANGE) broker_begin_close(broker);
}
static bool broker_queue(struct broker *broker, enum broker_stage stage) {
  napi_value resource;
  broker->stage = stage;
  if (napi_create_string_utf8(broker->env, "cliq-installed-model-broker", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
      napi_create_async_work(broker->env, NULL, resource, broker_worker, broker_complete, broker, &broker->work) != napi_ok)
    return broker_fail(broker, "broker_worker_unavailable");
  if (napi_queue_async_work(broker->env, broker->work) != napi_ok) {
    if (napi_delete_async_work(broker->env, broker->work) != napi_ok) {
      broker->unsafe = true; atomic_store(&retirement_failed, true);
      if (broker->unretired_work_count < 4) broker->unretired_work[broker->unretired_work_count++] = broker->work;
    }
    broker->work = NULL; return broker_fail(broker, "broker_worker_unavailable");
  }
  broker->working = true; return true;
}
static void broker_begin_close(struct broker *broker) {
  if (broker->retired) return;
  broker->closing = true; atomic_store(&broker->cancelled, true);
  if (broker->platform.cancel) g_cancellable_cancel(broker->platform.cancel);
  if (pthread_mutex_lock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
  else {
    broker->token_revoked = true;
    if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
  }
  /* No descriptor is closed concurrently with a native worker. Cancellable
   * DNS/TCP and short monotonic TLS polls wake, then the sole retire worker
   * consumes descriptors only after the preceding worker has completed. */
  if (!broker->working && !broker->retired && !broker_queue(broker, BROKER_RETIRE)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); broker->retired = true;
    if (broker->platform.secret) { wipe(broker->platform.secret, broker->platform.secret_size); free(broker->platform.secret); broker->platform.secret = NULL; }
    broker_close_timer(broker); broker_finish_close(broker);
  }
}
static void broker_deadline(uv_timer_t *timer) { broker_begin_close(timer->data); }
static void broker_cleanup(napi_async_cleanup_hook_handle handle, void *data) {
  (void)handle; struct broker *broker = data; broker->env_closing = true;
  /* No JavaScript continuation can commit after environment teardown. Retire
   * this original mutex without inventing a no-release database fact. */
  if (broker->fence_locked) {
    if (pthread_mutex_unlock(&broker->release_mutex)) { broker->unsafe = true; atomic_store(&retirement_failed, true); }
    else broker->fence_locked = false;
  }
  atomic_store(&broker->fence_retained, false); broker_begin_close(broker); broker_finish_close(broker);
}
static bool broker_input(napi_env env, napi_value input, struct broker *broker) {
  const char *keys[] = {"provider", "selector", "expectedObservation", "target", "trustStoreBytes", "trustStoreDigest", "requestPath", "bodyBytes", "bodyBytesDigest"};
  char provider[64], request_path[64], base_path[TEXT_CAP]; napi_value selector, expected, target, pins;
  const char *target_keys[] = {"hostAscii", "port", "basePath", "serverNameAscii", "spkiSha256Pins"};
  bool array; uint32_t count;
  if (!fields(env, input, keys, 9) || !field_text(env, input, "provider", provider, sizeof(provider)) || strcmp(provider, "openai-compatible") ||
      !member(env, input, "selector", &selector) || !parse_selector(env, selector, &broker->platform.selector) ||
      !member(env, input, "expectedObservation", &expected) || !parse_expected(env, expected, &broker->platform) ||
      !member(env, input, "target", &target) || !fields(env, target, target_keys, 5) ||
      !field_text(env, target, "hostAscii", broker->host, sizeof(broker->host)) || !broker_host(broker->host) ||
      !field_text(env, target, "serverNameAscii", broker->server_name, sizeof(broker->server_name)) || !broker_host(broker->server_name) ||
      !field_u32(env, target, "port", &broker->port) || broker->port > 65535 ||
      !field_text(env, target, "basePath", base_path, sizeof(base_path)) || !broker_path(base_path) ||
      !field_text(env, input, "requestPath", request_path, sizeof(request_path)) || strcmp(request_path, "/chat/completions") ||
      !member(env, target, "spkiSha256Pins", &pins) || napi_is_array(env, pins, &array) != napi_ok || !array ||
      napi_get_array_length(env, pins, &count) != napi_ok || !count || count > BROKER_PIN_CAP) return false;
  char previous[65] = {0};
  for (uint32_t index = 0; index < count; index++) {
    napi_value pin; char text[65]; size_t size;
    if (napi_get_element(env, pins, index, &pin) != napi_ok || napi_get_value_string_utf8(env, pin, text, sizeof(text), &size) != napi_ok ||
        size != 64 || strspn(text, "0123456789abcdef") != 64 || (index && strcmp(previous, text) >= 0)) return false;
    for (size_t byte = 0; byte < 32; byte++) { char pair[3] = {text[byte * 2], text[byte * 2 + 1], 0}; broker->pins[index][byte] = (unsigned char)strtoul(pair, NULL, 16); }
    memcpy(previous, text, sizeof(previous));
  }
  broker->pin_count = count;
  size_t base_size = strlen(base_path); while (base_size && base_path[base_size - 1] == '/') base_path[--base_size] = '\0';
  if (snprintf(broker->path, sizeof(broker->path), "%s%s", base_path, request_path) < 1) return false;
  if (!broker_buffer(env, input, "trustStoreBytes", BROKER_TRUST_CAP, &broker->trust, &broker->trust_size) ||
      !broker_buffer(env, input, "bodyBytes", BROKER_BODY_CAP, &broker->body, &broker->body_size) ||
      !broker_digest(env, input, "trustStoreDigest", broker->trust_digest) || !broker_digest(env, input, "bodyBytesDigest", broker->body_digest)) return false;
  char digest[65];
  if (!digest_hex(broker->trust, broker->trust_size, digest) || strcmp(digest, broker->trust_digest)) return false;
  return digest_hex(broker->body, broker->body_size, digest) && !strcmp(digest, broker->body_digest);
}
static napi_value broker_prepare_call(napi_env env, napi_callback_info info) {
  size_t argc = 2; napi_value args[2];
  if (atomic_load(&retirement_failed) || syscall(SYS_gettid) != getpid() ||
      napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 1) {
    napi_throw_type_error(env, NULL, "Installed model broker preparation is unavailable"); return NULL;
  }
  struct broker *broker = calloc(1, sizeof(*broker));
  if (!broker) { napi_throw_error(env, NULL, "Installed model broker preparation is unavailable"); return NULL; }
  broker->env = env; broker->creator_pid = getpid(); broker->platform.runtime_fd = -1;
  atomic_init(&broker->cancelled, false); atomic_init(&broker->unsafe, false); atomic_init(&broker->error, NULL);
  atomic_init(&broker->fence_retained, false);
  bool valid = current_user(&broker->platform.uid, &broker->platform.gid, broker->platform.home) &&
    broker_input(env, args[0], broker) && RAND_bytes(broker->token, sizeof(broker->token)) == 1 &&
    clock_gettime(CLOCK_MONOTONIC, &broker->platform.deadline) == 0;
  if (valid) {
    broker->platform.deadline.tv_sec += DEADLINE_SECONDS;
    valid = digest_hex(broker->token, sizeof(broker->token), broker->token_digest) && pthread_mutex_init(&broker->release_mutex, NULL) == 0;
    broker->mutex_ready = valid;
  }
  if (!valid) {
    if (broker->body) { wipe(broker->body, broker->body_size); free(broker->body); }
    if (broker->trust) { wipe(broker->trust, broker->trust_size); free(broker->trust); }
    wipe(broker, sizeof(*broker)); free(broker);
    napi_throw_type_error(env, NULL, "Invalid installed model broker preparation"); return NULL;
  }
  broker->platform.cancel = g_cancellable_new();
  napi_value ready, handle = NULL; uv_loop_t *loop;
  if (napi_create_promise(env, &broker->ready_deferred, &ready) == napi_ok) handle = broker_handle_value(broker, ready);
  if (!handle ||
      napi_add_async_cleanup_hook(env, broker_cleanup, broker, &broker->cleanup_hook) != napi_ok ||
      napi_get_uv_event_loop(env, &loop) != napi_ok || uv_timer_init(loop, &broker->timer)) {
    broker->unsafe = true; atomic_store(&retirement_failed, true); broker_fail(broker, "resource_retirement");
    broker->unretired_next = unretired_brokers; unretired_brokers = broker;
    napi_throw(env, broker_error_value(broker)); return NULL;
  }
  broker->timer_ready = true; broker->timer.data = broker; uv_update_time(loop);
  if (uv_timer_start(&broker->timer, broker_deadline, (uint64_t)remaining(&broker->platform), 0) || !broker_queue(broker, BROKER_PREPARE)) {
    broker_fail(broker, "broker_worker_unavailable");
    broker_begin_close(broker);
  }
  /* Publish the actual closeable owner synchronously, before the caller can
   * await credential I/O. Even queued/executing preparation can now be closed. */
  return handle;
}
static napi_value initialize_broker(napi_env env, napi_value exports) {
  if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) { napi_throw_error(env, NULL, "Installed model broker TLS initialization unavailable"); return NULL; }
  const napi_property_descriptor methods[] = {
    {"prepareModelTransport", NULL, broker_prepare_call, NULL, NULL, NULL, napi_default, NULL},
  };
  if (napi_define_properties(env, exports, sizeof(methods) / sizeof(*methods), methods) != napi_ok) return NULL;
  set_number(env, exports, "interfaceVersion", 3); return exports;
}
NAPI_MODULE(cliq_linux_model_broker, initialize_broker)
#endif
