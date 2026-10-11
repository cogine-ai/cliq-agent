/* Same signed StateOwner image; ordinary credentials do not acquire its
 * StateOwner lock or keeper/anchor. Only the trusted installed-root bridge
 * calls this private original-directory-FD borrowing interface. */
#include <sqlite3ext.h>
__attribute__((visibility("hidden"))) SQLITE_EXTENSION_INIT1
#include "credential-vfs.h"

static const napi_type_tag credential_scope_tag = {0xac39560d186ee994ULL, 0x9406d9dd4b936d89ULL};
static const char credential_vfs_name[] = "cliq-credential-vfs-v1";

static napi_value credential_error(napi_env env, const char *code, const char *message) {
  napi_throw_error(env, code, message);
  return NULL;
}
static int credential_visible_root(credential_context *ctx, int capture) {
  int visible = credential_walk_path(ctx, ctx->root_path);
  struct stat info;
  (void)capture;
  if (visible < 0) return -1;
  if (fstat(visible, &info) == 0 && credential_valid_directory(&info) &&
      credential_same_object(&info, &ctx->identities[CREDENTIAL_ROOT])) return visible;
  credential_checked_close(ctx, &visible);
  return -1;
}
static int credential_no_arguments(napi_env env, napi_callback_info info, napi_value *self) {
  size_t count = 1;
  napi_value argument;
  return napi_get_cb_info(env, info, &count, &argument, self, NULL) == napi_ok && count == 0;
}
static credential_context *credential_unwrap_scope(napi_env env, napi_callback_info info) {
  napi_value self;
  bool tagged = false;
  credential_context *ctx = NULL;
  if (!credential_no_arguments(env, info, &self) ||
      napi_check_object_type_tag(env, self, &credential_scope_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&ctx) != napi_ok || ctx == NULL ||
      !credential_owner_context(ctx) || env != ctx->owner_env) {
    credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "invalid credential scope or owner context");
    return NULL;
  }
  if (ctx->retired || atomic_load(&credential_process.active) != ctx) {
    credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential scope is closed or inactive");
    return NULL;
  }
  return ctx;
}
static napi_value credential_assert_scope(napi_env env, napi_callback_info info) {
  credential_context *ctx = credential_unwrap_scope(env, info);
  if (ctx == NULL) return NULL;
  if (credential_check_bindings(ctx) != 0)
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential authority bindings changed or native resources are uncertain");
  napi_value result;
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void credential_finalize_scope(napi_env env, void *data, void *hint) {
  (void)env; (void)hint;
  credential_context *ctx = data;
  /* GC is not retirement. A live/uncertain scope is permanently retained by
   * the manager; SQLite file leases can still reference this exact context. */
  if (ctx->retired && ctx->live_files == 0 && ctx->owner_reference == NULL &&
      atomic_load(&credential_process.active) != ctx) free(ctx);
}
static napi_value credential_close_scope(napi_env env, napi_callback_info info) {
  credential_context *ctx = credential_unwrap_scope(env, info);
  if (ctx == NULL) return NULL;
  if (ctx->live_files != 0)
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "live SQLite file leases cannot be retired");
  if (credential_check_bindings(ctx) != 0 || credential_retire_resources(ctx) != 0)
    return credential_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "credential close is uncertain or fenced; later resources retained");
  napi_ref reference = ctx->owner_reference;
  ctx->owner_reference = NULL;
  if (napi_delete_reference(env, reference) != napi_ok) {
    credential_poison(ctx);
    return credential_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "credential owner reference retirement failed");
  }
  atomic_store(&credential_process.active, NULL);
  napi_value result;
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static int credential_lock_file(credential_context *ctx, enum credential_role role, int mode) {
  int result;
  do {
    ctx->counts.locks++;
    result = flock(ctx->descriptors[role], mode | LOCK_NB);
  } while (result < 0 && errno == EINTR);
  return result;
}
static int credential_is_busy(int error) {
  return error == EWOULDBLOCK || error == EAGAIN || error == EACCES;
}
static napi_value acquire_credential_scope(napi_env env, napi_callback_info info) {
  /* This process-wide gate precedes every borrowed-root check/open and every
   * data open, including calls through another JS factory. A duplicate data
   * FD close in this process would otherwise drop its existing POSIX guard. */
  int expected = 0;
  if (!atomic_compare_exchange_strong(&credential_process.acquiring, &expected, 1))
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential scope acquisition is already active");
  if (atomic_load(&credential_process.poisoned) || atomic_load(&credential_process.active) != NULL) {
    atomic_store(&credential_process.acquiring, 0);
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential scope is active or process authority is uncertain");
  }
  int main_thread = credential_process_main_thread();
  if (!main_thread || getuid() != geteuid() || getgid() != getegid() ||
      (credential_process.owner_env != NULL &&
       (credential_process.owner_env != env || credential_process.owner_pid != getpid() ||
        !pthread_equal(credential_process.owner_thread, pthread_self())))) {
    atomic_store(&credential_process.acquiring, 0);
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential scope requires its original process main-thread context");
  }
  credential_context *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    atomic_store(&credential_process.acquiring, 0);
    return credential_error(env, "ERR_CLIQ_CREDENTIAL_SCOPE", "credential scope allocation failed");
  }
  credential_initialize_context(ctx, env);
  size_t count = 4, length;
  napi_value arguments[4];
  double descriptor;
  bool array = false, lossless;
  uint32_t tuple_length;
  uint64_t tuple[5];
  const char *error = "invalid original credential StateRoot identity";
  const char *error_code = "ERR_CLIQ_CREDENTIAL_SCOPE";
  int busy = 0, wrapped = 0;
  if (napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 3 ||
      napi_get_value_double(env, arguments[0], &descriptor) != napi_ok ||
      !(descriptor >= 0 && descriptor <= INT_MAX) || descriptor != (int)descriptor ||
      napi_get_value_string_utf8(env, arguments[1], NULL, 0, &length) != napi_ok ||
      length < 2 || length >= sizeof(ctx->root_path) ||
      napi_get_value_string_utf8(env, arguments[1], ctx->root_path, sizeof(ctx->root_path), &length) != napi_ok ||
      strlen(ctx->root_path) != length || ctx->root_path[0] != '/' ||
      napi_is_array(env, arguments[2], &array) != napi_ok || !array ||
      napi_get_array_length(env, arguments[2], &tuple_length) != napi_ok || tuple_length != 5) goto failed;
  for (uint32_t index = 0; index < 5; ++index) {
    napi_value item;
    if (napi_get_element(env, arguments[2], index, &item) != napi_ok ||
        napi_get_value_bigint_uint64(env, item, &tuple[index], &lossless) != napi_ok || !lossless) goto failed;
  }
  struct stat original;
  if (fstat((int)descriptor, &original) != 0 || !credential_valid_directory(&original) ||
      (uint64_t)original.st_dev != tuple[0] || (uint64_t)original.st_ino != tuple[1] ||
      (uint64_t)original.st_uid != tuple[2] || (uint64_t)original.st_gid != tuple[3] ||
      (uint64_t)original.st_mode != tuple[4]) goto failed;
  ctx->identities[CREDENTIAL_ROOT] = original;
  ctx->descriptors[CREDENTIAL_ROOT] = fcntl((int)descriptor, F_DUPFD_CLOEXEC, 0);
  if (ctx->descriptors[CREDENTIAL_ROOT] < 0) goto failed;
  struct stat duplicate;
  if (fstat(ctx->descriptors[CREDENTIAL_ROOT], &duplicate) != 0 ||
      !credential_valid_directory(&duplicate) || !credential_same_object(&original, &duplicate)) goto failed;
  int visible = credential_visible_root(ctx, 0);
  if (visible < 0) goto failed;
  if (credential_checked_close(ctx, &visible) != 0) goto failed;
  int retirement_failed = 0;
  if (observe_process_with_retirement(getpid(), ctx->process_start, &retirement_failed) != 1 || retirement_failed) {
    if (retirement_failed) credential_poison(ctx);
    goto failed;
  }
  error = "credential global gate prerequisites refused";
  if (credential_hold_directory(ctx, ctx->descriptors[CREDENTIAL_ROOT], "runtime", CREDENTIAL_RUNTIME) != 0 ||
      credential_hold_file(ctx, CREDENTIAL_GLOBAL) != 0) goto failed;
  if (credential_lock_file(ctx, CREDENTIAL_GLOBAL, LOCK_SH) != 0) {
    busy = credential_is_busy(errno); goto failed;
  }
  error = "credential authority prerequisites refused";
  int created = mkdirat(ctx->descriptors[CREDENTIAL_ROOT], "credentials", 0700) == 0;
  if (!created && errno != EEXIST) goto failed;
  if (credential_hold_directory(ctx, ctx->descriptors[CREDENTIAL_ROOT], "credentials", CREDENTIAL_CREDENTIALS) != 0 ||
      (created && fsync(ctx->descriptors[CREDENTIAL_ROOT]) != 0) ||
      credential_hold_file(ctx, CREDENTIAL_LOCK) != 0) goto failed;
  if (credential_lock_file(ctx, CREDENTIAL_LOCK, LOCK_EX) != 0) {
    busy = credential_is_busy(errno); goto failed;
  }
  static const enum credential_role data_roles[] = {CREDENTIAL_MAIN, CREDENTIAL_WAL, CREDENTIAL_JOURNAL};
  for (size_t index = 0; index < sizeof(data_roles) / sizeof(data_roles[0]); ++index) {
    if (credential_hold_file(ctx, data_roles[index]) != 0) goto failed;
    if (credential_guard_data_inode(ctx, data_roles[index]) != 0) {
      busy = credential_is_busy(errno); goto failed;
    }
  }
  if (ctx->identities[CREDENTIAL_MAIN].st_size == 0 && ctx->identities[CREDENTIAL_WAL].st_size != 0) goto failed;
  ctx->prepared = 1;
  if (credential_check_bindings(ctx) != 0) goto failed;
  if (credential_process.next_generation == UINT64_MAX) { credential_poison(ctx); goto failed; }
  ctx->generation = ++credential_process.next_generation;
  napi_value result, generation;
  char text[64];
  int text_length = snprintf(text, sizeof(text), "%ju:%ju", (uintmax_t)ctx->owner_pid, (uintmax_t)ctx->generation);
  const napi_property_descriptor methods[] = {
    {"assertHeld", NULL, credential_assert_scope, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, credential_close_scope, NULL, NULL, NULL, napi_default, NULL}
  };
  error = "credential token construction failed";
  if (text_length <= 0 || (size_t)text_length >= sizeof(text) ||
      napi_create_object(env, &result) != napi_ok ||
      napi_type_tag_object(env, result, &credential_scope_tag) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_create_string_utf8(env, text, (size_t)text_length, &generation) != napi_ok) goto failed;
  napi_property_descriptor identity = {"generation", NULL, NULL, NULL, NULL, generation, napi_default, NULL};
  if (napi_define_properties(env, result, 1, &identity) != napi_ok ||
      napi_wrap(env, result, ctx, credential_finalize_scope, NULL, NULL) != napi_ok) goto failed;
  wrapped = 1;
  if (napi_create_reference(env, result, 1, &ctx->owner_reference) != napi_ok) goto failed;
  credential_process.owner_env = env;
  credential_process.owner_pid = getpid();
  credential_process.owner_thread = pthread_self();
  atomic_store(&credential_process.active, ctx);
  atomic_store(&credential_process.acquiring, 0);
  return result;
failed:
  /* Ordinary contention is retryable only after every owned resource has
   * been successfully consumed. An uncertain close is never retried and
   * never treated as proof that any physical lock survived. */
  if (!ctx->uncertain && !ctx->fenced && credential_retire_resources(ctx) == 0) {
    if (!wrapped) free(ctx);
  } else {
    credential_poison(ctx);
    atomic_store(&credential_process.active, ctx);
    error = "credential acquisition cleanup is uncertain; fresh process required";
    error_code = "ERR_CLIQ_RESOURCE_RETIREMENT";
    busy = 0;
  }
  atomic_store(&credential_process.acquiring, 0);
  return credential_error(env, busy ? "ERR_CLIQ_CREDENTIAL_BUSY" : error_code,
                          busy ? "credential authority or global gate is busy" : error);
}

/* The loader keeps this one image and API table resident for process life.
 * No unregister/auto-extension hook or second SQLite engine is introduced. */
__attribute__((visibility("default"))) int sqlite3_cliqcredentialvfs_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  (void)database; (void)error;
  return credential_register_vfs(credential_vfs_name, api);
}
