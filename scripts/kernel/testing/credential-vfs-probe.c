/* Closed test-only HOME adapter. Production and these probes execute the
 * same fixed descriptor I/O, inode guards and resource consumption code. */
#define _GNU_SOURCE
#include <node_api.h>
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1
#include "../../../native/state-owner/credential-vfs.h"

#define PROBE_EXPORT __attribute__((visibility("default")))
#define ROOT CREDENTIAL_ROOT
#define CREDENTIALS CREDENTIAL_CREDENTIALS
#define LOCK CREDENTIAL_LOCK
#define MAIN CREDENTIAL_MAIN
#define WAL CREDENTIAL_WAL
#define JOURNAL CREDENTIAL_JOURNAL
#define ROLE_COUNT CREDENTIAL_RUNTIME
static const char *const roles[] = {"root", "credentials", "lock", "main", "wal", "journal"};
static credential_context probe_context;
static char home_path[PATH_MAX];
static struct stat home_identity, probe_identity;
#define descriptors probe_context.descriptors
#define identities probe_context.identities
#define prepared probe_context.prepared
#define fenced probe_context.fenced
#define uncertain probe_context.uncertain
#define retired probe_context.retired
#define live_files probe_context.live_files
#define counts probe_context.counts
#define owner_env probe_context.owner_env
#define registered credential_process.registered
#define original_default credential_process.original_default
#define same_object credential_same_object
static int owner_context(void) { return credential_owner_context(&probe_context); }

static int credential_visible_root(credential_context *ctx, int capture) {
  int home = credential_walk_path(ctx, home_path), probe = -1, root = -1;
  struct stat info;
  if (home < 0) return -1;
  if (fstat(home, &info) != 0 || !credential_valid_directory(&info) ||
      (!capture && !same_object(&info, &home_identity))) goto failed;
  if (capture) home_identity = info;
  probe = openat(home, "probe", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (probe < 0 || fstat(probe, &info) != 0 || !credential_valid_directory(&info) ||
      (!capture && !same_object(&info, &probe_identity))) goto failed;
  if (capture) probe_identity = info;
  root = openat(probe, "credential-vfs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root < 0 || fstat(root, &info) != 0 || !credential_valid_directory(&info) ||
      (!capture && !same_object(&info, &identities[ROOT]))) goto failed;
  if (capture) identities[ROOT] = info;
  if (credential_checked_close(ctx, &probe) != 0 || credential_checked_close(ctx, &home) != 0) return -1;
  return root;
failed:
  if (credential_checked_close(ctx, &root) != 0) return -1;
  if (credential_checked_close(ctx, &probe) != 0) return -1;
  credential_checked_close(ctx, &home);
  return -1;
}
static int prepare_fixed(void) {
  const char *home = getenv("HOME");
  credential_context *ctx = &probe_context;
  if (!owner_context() || home == NULL || home[0] != '/' || strlen(home) >= sizeof(home_path) ||
      getuid() != geteuid() || getgid() != getegid()) return -1;
  memcpy(home_path, home, strlen(home) + 1);
  descriptors[ROOT] = credential_visible_root(ctx, 1);
  if (descriptors[ROOT] < 0) return -1;
  int created = mkdirat(descriptors[ROOT], "credentials", 0700) == 0;
  if (!created && errno != EEXIST) return -1;
  if (credential_hold_directory(ctx, descriptors[ROOT], "credentials", CREDENTIALS) != 0) return -1;
  if (created && fsync(descriptors[ROOT]) != 0) return -1;
  if (created) counts.syncs++;
  if (credential_hold_file(ctx, LOCK) != 0 || flock(descriptors[LOCK], LOCK_EX | LOCK_NB) != 0) return -1;
  counts.locks++;
  if (credential_hold_file(ctx, MAIN) != 0 || credential_guard_data_inode(ctx, MAIN) != 0 ||
      credential_hold_file(ctx, WAL) != 0 || credential_guard_data_inode(ctx, WAL) != 0 ||
      credential_hold_file(ctx, JOURNAL) != 0 || credential_guard_data_inode(ctx, JOURNAL) != 0) return -1;
  if (identities[MAIN].st_size == 0 && identities[WAL].st_size != 0) return -1;
  prepared = 1;
  atomic_store(&credential_process.active, ctx);
  return credential_check_bindings(ctx);
}

static napi_value failure(napi_env env, const char *message) {
  napi_throw_error(env, "ERR_CLIQ_CREDENTIAL_VFS_PROBE", message);
  return NULL;
}

static int no_arguments(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value argument;
  return napi_get_cb_info(env, info, &count, &argument, NULL, NULL) == napi_ok && count == 0;
}

static napi_status boolean_property(napi_env env, napi_value object, const char *name, int value) {
  napi_value property;
  napi_status result = napi_get_boolean(env, value != 0, &property);
  return result == napi_ok ? napi_set_named_property(env, object, name, property) : result;
}

static napi_status number_property(napi_env env, napi_value object, const char *name, double value) {
  napi_value property;
  napi_status result = napi_create_double(env, value, &property);
  return result == napi_ok ? napi_set_named_property(env, object, name, property) : result;
}

static napi_status decimal_property(napi_env env, napi_value object, const char *name, uintmax_t value) {
  char text[64];
  napi_value property;
  int length = snprintf(text, sizeof(text), "%ju", value);
  if (length <= 0 || (size_t)length >= sizeof(text)) return napi_generic_failure;
  napi_status result = napi_create_string_utf8(env, text, (size_t)length, &property);
  return result == napi_ok ? napi_set_named_property(env, object, name, property) : result;
}

static napi_status descriptor_property(napi_env env, napi_value object, enum credential_role role) {
  napi_value property;
  struct stat info;
  napi_status result;
  if (descriptors[role] < 0) {
    result = napi_get_null(env, &property);
  } else {
    if (fstat(descriptors[role], &info) != 0) return napi_generic_failure;
    result = napi_create_object(env, &property);
    if (result == napi_ok) result = number_property(env, property, "fd", descriptors[role]);
    if (result == napi_ok) result = decimal_property(env, property, "dev", (uintmax_t)info.st_dev);
    if (result == napi_ok) result = decimal_property(env, property, "ino", (uintmax_t)info.st_ino);
    if (result == napi_ok) result = decimal_property(env, property, "size", (uintmax_t)info.st_size);
    if (result == napi_ok) result = decimal_property(env, property, "uid", (uintmax_t)info.st_uid);
    if (result == napi_ok) result = decimal_property(env, property, "gid", (uintmax_t)info.st_gid);
    if (result == napi_ok) result = decimal_property(env, property, "mode", (uintmax_t)info.st_mode);
    if (result == napi_ok) result = decimal_property(env, property, "nlink", (uintmax_t)info.st_nlink);
  }
  return result == napi_ok ? napi_set_named_property(env, object, roles[role], property) : result;
}

static napi_value snapshot(napi_env env) {
  napi_value result, files, observed_counts, source_id;
  if (napi_create_object(env, &result) != napi_ok || napi_create_object(env, &files) != napi_ok ||
      napi_create_object(env, &observed_counts) != napi_ok) return NULL;
  for (int role = ROOT; role < ROLE_COUNT; ++role) {
    if (descriptor_property(env, files, (enum credential_role)role) != napi_ok) return NULL;
  }
  if (boolean_property(env, result, "prepared", prepared) != napi_ok ||
      boolean_property(env, result, "registered", registered) != napi_ok ||
      boolean_property(env, result, "fenced", fenced) != napi_ok ||
      boolean_property(env, result, "uncertain", uncertain) != napi_ok ||
      boolean_property(env, result, "retired", retired) != napi_ok ||
      number_property(env, result, "liveFiles", live_files) != napi_ok ||
      boolean_property(env, result, "defaultUnchanged", sqlite3_api == NULL ||
                        sqlite3_vfs_find(NULL) == original_default) != napi_ok ||
      number_property(env, observed_counts, "reads", counts.reads) != napi_ok ||
      number_property(env, observed_counts, "writes", counts.writes) != napi_ok ||
      number_property(env, observed_counts, "truncates", counts.truncates) != napi_ok ||
      number_property(env, observed_counts, "syncs", counts.syncs) != napi_ok ||
      number_property(env, observed_counts, "locks", counts.locks) != napi_ok ||
      number_property(env, observed_counts, "opens", counts.opens) != napi_ok ||
      number_property(env, observed_counts, "closes", counts.closes) != napi_ok ||
      number_property(env, observed_counts, "fenceChecks", counts.fence_checks) != napi_ok ||
      number_property(env, observed_counts, "journalRetirements", counts.journal_retirements) != napi_ok ||
      napi_set_named_property(env, result, "descriptors", files) != napi_ok ||
      napi_set_named_property(env, result, "counts", observed_counts) != napi_ok) return NULL;
  if ((sqlite3_api == NULL ? napi_get_null(env, &source_id) :
       napi_create_string_utf8(env, sqlite3_sourceid(), NAPI_AUTO_LENGTH, &source_id)) != napi_ok ||
      napi_set_named_property(env, result, "sourceId", source_id) != napi_ok) return NULL;
  return result;
}

static napi_value prepare(napi_env env, napi_callback_info info) {
  if (!no_arguments(env, info)) return failure(env, "prepare takes no arguments");
  if (env != owner_env || !owner_context()) return failure(env, "probe belongs to another context");
  if (prepared || retired || uncertain) return failure(env, "probe cannot prepare twice");
  if (prepare_fixed() != 0) { uncertain = 1; return failure(env, "fixed credential prerequisites refused"); }
  return snapshot(env);
}

static napi_value observe(napi_env env, napi_callback_info info) {
  if (env != owner_env || !owner_context()) return failure(env, "probe belongs to another context");
  return no_arguments(env, info) ? snapshot(env) : failure(env, "observe takes no arguments");
}

static napi_value retire(napi_env env, napi_callback_info info) {
  if (!no_arguments(env, info)) return failure(env, "retire takes no arguments");
  if (env != owner_env || !owner_context()) return failure(env, "probe belongs to another context");
  if (live_files != 0) return failure(env, "live SQLite file leases cannot be retired");
  if (uncertain || fenced) return failure(env, "native resources cannot be retired");
  if (prepared && credential_check_bindings(&probe_context) != 0)
    return failure(env, "native bindings changed; resources retained");
  if (credential_retire_resources(&probe_context) != 0)
    return failure(env, "native close is uncertain; later resources retained");
  return snapshot(env);
}
PROBE_EXPORT int sqlite3_cliqcredentialvfsprobe_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  (void)database; (void)error;
  return credential_register_vfs("cliq-credential-vfs-probe-v1", api);
}
static napi_value initialize_napi(napi_env env, napi_value exports) {
  if (owner_env != NULL && (owner_env != env || !owner_context()))
    return failure(env, "probe belongs to another context");
  if (owner_env == NULL) {
    credential_initialize_context(&probe_context, env);
    probe_context.generation = 1;
  }
  napi_property_descriptor methods[] = {
    {"prepare", NULL, prepare, NULL, NULL, NULL, napi_default, NULL},
    {"observe", NULL, observe, NULL, NULL, NULL, napi_default, NULL},
    {"retire", NULL, retire, NULL, NULL, NULL, napi_default, NULL},
  };
  return napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) == napi_ok ? exports : NULL;
}

NAPI_MODULE(cliq_credential_vfs_probe, initialize_napi)
