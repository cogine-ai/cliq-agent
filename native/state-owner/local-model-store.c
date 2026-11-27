/* Fixed managed-model data store. This owner has no Run, credential, tool,
 * network, process-spawn or StateOwner authority. Global SH precedes the
 * original store EX lock; both remain held until every pager/source closes. */
#include "fixed-fd-sqlite-io.h"

enum lms_role { LMS_ROOT, LMS_STORE, LMS_OBJECTS, LMS_LOCK, LMS_MAIN, LMS_JOURNAL, LMS_ROLES };
static const char *const lms_leaves[LMS_ROLES] = {
  NULL, "local-models", "objects", "registry.lock", "registry.sqlite3", "registry.sqlite3-journal"
};
typedef struct lms_package lms_package;
typedef struct {
  napi_env env; pid_t pid; pthread_t thread;
  migration_credential_gate *original;
  napi_ref original_reference, self_reference;
  unsigned borrowers;
  int closed, uncertain, finalized;
} lms_exclusive_binding;
typedef struct lms_context {
  int fd[LMS_ROLES];
  struct stat identity[LMS_ROLES];
  kernel_global_gate *global;
  lms_exclusive_binding *exclusive;
  napi_ref exclusive_reference;
  napi_env env;
  pid_t pid;
  uid_t uid;
  gid_t gid;
  pthread_t thread;
  uint64_t generation;
  unsigned leases[LMS_ROLES], live_files, package_handles;
  int prepared, retired, finalized, archive_cancelled;
  atomic_int uncertain, archive_held;
  napi_ref reference;
  lms_package *package;
  char root_path[PATH_MAX];
  int existing_only;
} lms_context;
static struct {
  _Atomic(lms_context *) active;
  atomic_int acquiring, poisoned;
  uint64_t generation;
  int registered;
  sqlite3_vfs *base;
  sqlite3_vfs vfs;
} lms_process;
static const napi_type_tag lms_tag = {0xdcf6f655dca1400cULL, 0xbad76882225b79f9ULL};
static const napi_type_tag lms_package_tag = {0x78c3ff0740d04e98ULL, 0xb4a471d015554412ULL};
static const napi_type_tag lms_object_source_tag = {0xbfdc193841024832ULL, 0x99b34c958c22045aULL};
static const napi_type_tag lms_exclusive_tag = {0x47af7abda9f14539ULL, 0x9235d10d8401db85ULL};
static const char lms_vfs_name[] = "cliq-local-model-store-v1";
static const char lms_main_name[] = "/cliq-local-model-registry";
static int lms_package_join(lms_package *package);

/* The original migration binding proves only the already-held same Root,
 * StateOwner and global EX. This distinct derived tag grants no credential
 * methods or SecretService authority and cannot be passed to that family. */
static int lms_exclusive_check(lms_exclusive_binding *held, napi_env env) {
  if (!kernel_global_main_thread() || !held || held->env != env || held->pid != getpid() ||
      !pthread_equal(held->thread, pthread_self()) || held->closed || held->uncertain ||
      !held->original || !held->original_reference || !held->self_reference) return -1;
  return migration_credential_check(held->original, env);
}
static void lms_exclusive_poison(lms_exclusive_binding *held) {
  if (!held) return;
  held->uncertain = 1;
  if (held->original) {
    held->original->uncertain = 1;
    held->original->owner->migration_retirement_error = 1;
  }
}
static napi_value lms_exclusive_error(napi_env env, const char *message) {
  napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", message); return NULL;
}
static lms_exclusive_binding *lms_exclusive_receiver(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self; bool tagged = false; lms_exclusive_binding *held = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
      napi_check_object_type_tag(env, self, &lms_exclusive_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&held) != napi_ok || !held || !kernel_global_main_thread() ||
      held->env != env || held->pid != getpid() || !pthread_equal(held->thread, pthread_self())) {
    napi_throw_type_error(env, NULL, "invalid original model-store EX binding"); return NULL;
  }
  return held;
}
static napi_value lms_exclusive_assert(napi_env env, napi_callback_info info) {
  lms_exclusive_binding *held = lms_exclusive_receiver(env, info); if (!held) return NULL;
  if (lms_exclusive_check(held, env) != 0) return lms_exclusive_error(env, "original model-store EX binding changed or ended");
  napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value lms_exclusive_close(napi_env env, napi_callback_info info) {
  lms_exclusive_binding *held = lms_exclusive_receiver(env, info); if (!held) return NULL;
  if (!held->closed) {
    if (held->borrowers || lms_exclusive_check(held, env) != 0 || !held->original->borrowers)
      return lms_exclusive_error(env, "model-store EX binding has live or uncertain original borrowers");
    napi_ref original = held->original_reference; held->original_reference = NULL;
    if (napi_delete_reference(env, original) != napi_ok) { lms_exclusive_poison(held); return lms_exclusive_error(env, "original model-store EX source did not retire"); }
    --held->original->borrowers; held->closed = 1;
    napi_ref self = held->self_reference; held->self_reference = NULL;
    if (napi_delete_reference(env, self) != napi_ok) { lms_exclusive_poison(held); return lms_exclusive_error(env, "model-store EX binding reference did not retire"); }
  }
  napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void lms_exclusive_finalize(napi_env env, void *data, void *hint) {
  (void)hint; lms_exclusive_binding *held = data;
  if (!kernel_global_main_thread() || held->env != env || held->pid != getpid() || !pthread_equal(held->thread, pthread_self())) return;
  held->finalized = 1;
  if (held->closed && !held->uncertain && !held->borrowers) free(held);
}
static napi_value derive_local_model_store_gate(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, result; bool tagged = false; migration_credential_gate *original = NULL;
  if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, &argument, NULL, NULL) != napi_ok || count != 1 ||
      napi_check_object_type_tag(env, argument, &migration_credential_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, argument, (void **)&original) != napi_ok || migration_credential_check(original, env) != 0 || original->borrowers == UINT_MAX) {
    napi_throw_type_error(env, NULL, "model-store EX derivation requires the genuine original migration root binding"); return NULL;
  }
  lms_exclusive_binding *held = calloc(1, sizeof(*held));
  if (!held) { napi_throw_error(env, NULL, "model-store EX binding allocation failed"); return NULL; }
  held->env = env; held->pid = getpid(); held->thread = pthread_self(); held->original = original; ++original->borrowers;
  int wrapped = 0;
  const napi_property_descriptor methods[] = {
    {"assertHeld", NULL, lms_exclusive_assert, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, lms_exclusive_close, NULL, NULL, NULL, napi_default, NULL}
  };
  if (napi_create_reference(env, argument, 1, &held->original_reference) != napi_ok ||
      napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &lms_exclusive_tag) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, held, lms_exclusive_finalize, NULL, NULL) != napi_ok) goto failed;
  wrapped = 1;
  if (napi_create_reference(env, result, 1, &held->self_reference) != napi_ok) goto failed;
  return result;
failed:
  if (held->original_reference && napi_delete_reference(env, held->original_reference) != napi_ok) {
    lms_exclusive_poison(held); return lms_exclusive_error(env, "model-store EX derivation cleanup is uncertain");
  }
  held->original_reference = NULL; --original->borrowers; held->closed = 1;
  if (!wrapped) free(held);
  napi_throw_error(env, NULL, "model-store EX binding construction failed"); return NULL;
}

static napi_value lms_error(napi_env env, const char *code, const char *message) {
  napi_throw_error(env, code, message); return NULL;
}
static void lms_poison(lms_context *ctx) {
  if (ctx) ctx->uncertain = 1;
  atomic_store(&lms_process.poisoned, 1);
}
static int lms_owner(const lms_context *ctx, napi_env env) {
  if (!kernel_global_main_thread()) return 0;
  return ctx && ctx->env == env && ctx->pid == getpid() &&
    pthread_equal(ctx->thread, pthread_self()) && ctx->uid == getuid() &&
    ctx->uid == geteuid() && ctx->gid == getgid() && ctx->gid == getegid();
}
static int lms_close_fd(lms_context *ctx, int *fd) {
  int owned = *fd; *fd = -1;
  if (owned < 0 || close(owned) == 0) return 0;
  lms_poison(ctx); return -1;
}
static int lms_directory(const struct stat *st) {
  return S_ISDIR(st->st_mode) && st->st_uid == geteuid() &&
    st->st_gid == getegid() && (st->st_mode & 07777) == 0700;
}
static int lms_data_file(const struct stat *st) {
  return S_ISREG(st->st_mode) && st->st_uid == geteuid() &&
    st->st_gid == getegid() && (st->st_mode & 07777) == 0600 && st->st_nlink == 1;
}
static int lms_object_file(const struct stat *st) {
  return S_ISREG(st->st_mode) && st->st_uid == geteuid() &&
    st->st_gid == getegid() && (st->st_mode & 07777) == 0400 && st->st_nlink == 1 && st->st_size > 0;
}
static int lms_sync(lms_context *ctx, int fd) {
  if (cliq_fd_sqlite_sync(fd, SQLITE_SYNC_FULL, NULL) == SQLITE_OK) return 0;
  lms_poison(ctx); return -1;
}
/* Locator-only canonical no-follow walk. The held root identity, not this
 * pathname, selects the store. Only directory descriptors are opened here. */
static int lms_walk(lms_context *ctx, const char *path) {
  if (!path || path[0] != '/' || path[1] == '\0') return -1;
  int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current < 0) return -1;
  const char *cursor = path + 1;
  while (*cursor) {
    const char *end = strchr(cursor, '/');
    size_t count = end ? (size_t)(end - cursor) : strlen(cursor);
    char part[NAME_MAX + 1];
    if (!count || count > NAME_MAX || (count == 1 && cursor[0] == '.') ||
        (count == 2 && cursor[0] == '.' && cursor[1] == '.') || (end && !end[1])) goto failed;
    memcpy(part, cursor, count); part[count] = '\0';
    int next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lms_close_fd(ctx, &current) != 0) return -1;
    if (next < 0) return -1;
    current = next; cursor = end ? end + 1 : cursor + count;
  }
  return current;
failed:
  lms_close_fd(ctx, &current); return -1;
}
static int lms_check(lms_context *ctx) {
  if (!lms_owner(ctx, ctx ? ctx->env : NULL) || !ctx->prepared || ctx->retired || ctx->uncertain ||
      ctx->archive_cancelled || atomic_load(&lms_process.poisoned) || atomic_load(&lms_process.active) != ctx) return -1;
  if (ctx->exclusive ? ctx->global != NULL || lms_exclusive_check(ctx->exclusive, ctx->env) != 0 ||
      strcmp(ctx->exclusive->original->owner->path, ctx->root_path) != 0 ||
      !same_inode(&ctx->exclusive->original->owner->root, &ctx->identity[LMS_ROOT]) :
      ctx->global == NULL || kernel_global_check(ctx->global, ctx->env) != 0) return -1;
  int visible = lms_walk(ctx, ctx->root_path);
  struct stat named, held;
  if (visible < 0) goto failed;
  if (fstat(visible, &named) != 0 || !lms_directory(&named) || !same_inode(&named, &ctx->identity[LMS_ROOT])) goto failed;
  for (int role = 0; role < LMS_ROLES; ++role) {
    if (ctx->fd[role] < 0 || fstat(ctx->fd[role], &held) != 0 ||
        !same_inode(&held, &ctx->identity[role]) ||
        (role <= LMS_OBJECTS ? !lms_directory(&held) : !lms_data_file(&held))) goto failed;
    if (role == LMS_ROOT) continue;
    int parent = role == LMS_STORE ? ctx->fd[LMS_ROOT] : ctx->fd[LMS_STORE];
    if (fstatat(parent, lms_leaves[role], &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_inode(&named, &held) || (role <= LMS_OBJECTS ? !lms_directory(&named) : !lms_data_file(&named))) goto failed;
  }
  return lms_close_fd(ctx, &visible);
failed:
  if (!ctx->uncertain) lms_close_fd(ctx, &visible);
  lms_poison(ctx); return -1;
}
static int lms_hold_directory(lms_context *ctx, int parent, const char *leaf, int role) {
  int created = 0;
  if (!ctx->exclusive && !ctx->existing_only) {
    created = mkdirat(parent, leaf, 0700) == 0;
    if (!created && errno != EEXIST) return -1;
  }
  ctx->fd[role] = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (ctx->fd[role] < 0 || fstat(ctx->fd[role], &ctx->identity[role]) != 0 || !lms_directory(&ctx->identity[role])) return -1;
  return created && (lms_sync(ctx, ctx->fd[role]) != 0 || lms_sync(ctx, parent) != 0) ? -1 : 0;
}
static int lms_hold_file(lms_context *ctx, int role) {
  int created = 0;
  if (ctx->exclusive || ctx->existing_only) {
    ctx->fd[role] = openat(ctx->fd[LMS_STORE], lms_leaves[role], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  } else {
    created = 1;
    ctx->fd[role] = openat(ctx->fd[LMS_STORE], lms_leaves[role], O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (ctx->fd[role] < 0 && errno == EEXIST) {
      created = 0; ctx->fd[role] = openat(ctx->fd[LMS_STORE], lms_leaves[role], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    }
  }
  if (ctx->fd[role] < 0 || fstat(ctx->fd[role], &ctx->identity[role]) != 0 || !lms_data_file(&ctx->identity[role])) return -1;
  return created && (lms_sync(ctx, ctx->fd[role]) != 0 || lms_sync(ctx, ctx->fd[LMS_STORE]) != 0) ? -1 : 0;
}
static int lms_inode_guard(lms_context *ctx, int role) {
  /* This family owns its original pager inodes throughout all leases. Never
   * duplicate/open/close one of these data inodes while its guard is held. */
  struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0x40000000, .l_len = 512};
  int status;
  do { status = fcntl(ctx->fd[role], F_SETLK, &lock); } while (status < 0 && errno == EINTR);
  return status;
}
static int lms_retire(lms_context *ctx) {
  if (ctx->uncertain || ctx->live_files || ctx->package || atomic_load(&ctx->archive_held)) return -1;
  static const int roles[] = {LMS_JOURNAL, LMS_MAIN, LMS_LOCK, LMS_OBJECTS, LMS_STORE, LMS_ROOT};
  for (size_t n = 0; n < sizeof(roles) / sizeof(roles[0]); ++n)
    if (lms_close_fd(ctx, &ctx->fd[roles[n]]) != 0) return -1;
  if (ctx->global) {
    if (kernel_global_check(ctx->global, ctx->env) != 0 || kernel_global_retire(ctx->global) != 0) { lms_poison(ctx); return -1; }
    ctx->global->finalized = 1; kernel_global_free(ctx->global); ctx->global = NULL;
  }
  if (ctx->exclusive) {
    if (lms_exclusive_check(ctx->exclusive, ctx->env) != 0 || !ctx->exclusive_reference || !ctx->exclusive->borrowers) { lms_poison(ctx); return -1; }
    napi_ref reference = ctx->exclusive_reference; ctx->exclusive_reference = NULL;
    if (napi_delete_reference(ctx->env, reference) != napi_ok) { lms_exclusive_poison(ctx->exclusive); lms_poison(ctx); return -1; }
    --ctx->exclusive->borrowers; ctx->exclusive = NULL;
  }
  ctx->prepared = 0; ctx->retired = 1; return 0;
}
typedef struct { sqlite3_file base; lms_context *ctx; uint64_t generation; int role, alive, lock; } lms_file;
static int lms_io_failure(lms_context *ctx, int code) { lms_poison(ctx); return code; }
static int lms_file_ready(lms_file *file) {
  return lms_owner(file->ctx, file->ctx ? file->ctx->env : NULL) && file->alive &&
    file->generation == file->ctx->generation && file->role >= LMS_MAIN && file->role <= LMS_JOURNAL &&
    file->ctx->leases[file->role] == 1 && lms_check(file->ctx) == 0;
}
static int lms_io_close(sqlite3_file *base) {
  lms_file *file = (lms_file *)base; lms_context *ctx = file->ctx;
  if (!lms_owner(ctx, ctx ? ctx->env : NULL) || !file->alive || file->role < LMS_MAIN ||
      file->role > LMS_JOURNAL || ctx->leases[file->role] != 1 || !ctx->live_files) return lms_io_failure(ctx, SQLITE_IOERR_CLOSE);
  ctx->leases[file->role] = 0; --ctx->live_files;
  file->alive = 0; file->ctx = NULL; base->pMethods = NULL; return SQLITE_OK;
}
static int lms_io_read(sqlite3_file *base, void *buffer, int size, sqlite3_int64 offset) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR_READ;
  int result = cliq_fd_sqlite_read(file->ctx->fd[file->role], buffer, size, offset, NULL);
  return result == SQLITE_OK || result == SQLITE_IOERR_SHORT_READ ? result : lms_io_failure(file->ctx, result);
}
static int lms_io_write(sqlite3_file *base, const void *buffer, int size, sqlite3_int64 offset) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file) || file->ctx->exclusive) return SQLITE_IOERR_WRITE;
  int result = cliq_fd_sqlite_write(file->ctx->fd[file->role], buffer, size, offset, NULL);
  return result == SQLITE_OK ? result : lms_io_failure(file->ctx, result);
}
static int lms_io_truncate(sqlite3_file *base, sqlite3_int64 size) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file) || file->ctx->exclusive) return SQLITE_IOERR_TRUNCATE;
  int result = cliq_fd_sqlite_truncate(file->ctx->fd[file->role], size, NULL);
  return result == SQLITE_OK ? result : lms_io_failure(file->ctx, result);
}
static int lms_io_sync(sqlite3_file *base, int flags) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR_FSYNC;
  int result = cliq_fd_sqlite_sync(file->ctx->fd[file->role], flags, NULL);
  return result == SQLITE_OK ? result : lms_io_failure(file->ctx, result);
}
static int lms_io_size(sqlite3_file *base, sqlite3_int64 *size) {
  lms_file *file = (lms_file *)base; struct stat st;
  if (!lms_file_ready(file)) return SQLITE_IOERR_FSTAT;
  if (fstat(file->ctx->fd[file->role], &st) != 0 || st.st_size < 0) return lms_io_failure(file->ctx, SQLITE_IOERR_FSTAT);
  *size = (sqlite3_int64)st.st_size; return SQLITE_OK;
}
static int lms_io_lock(sqlite3_file *base, int level) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR_LOCK;
  if (file->role != LMS_MAIN || level < SQLITE_LOCK_SHARED || level > SQLITE_LOCK_EXCLUSIVE) return lms_io_failure(file->ctx, SQLITE_IOERR_LOCK);
  if (file->lock < level) file->lock = level;
  return SQLITE_OK;
}
static int lms_io_unlock(sqlite3_file *base, int level) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR_UNLOCK;
  if (file->role != LMS_MAIN || (level != SQLITE_LOCK_NONE && level != SQLITE_LOCK_SHARED)) return lms_io_failure(file->ctx, SQLITE_IOERR_UNLOCK);
  if (file->lock > level) file->lock = level;
  return SQLITE_OK;
}
static int lms_io_reserved(sqlite3_file *base, int *reserved) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR_CHECKRESERVEDLOCK;
  *reserved = file->lock >= SQLITE_LOCK_RESERVED; return SQLITE_OK;
}
static int lms_io_control(sqlite3_file *base, int operation, void *argument) {
  lms_file *file = (lms_file *)base;
  if (!lms_file_ready(file)) return SQLITE_IOERR;
  switch (operation) {
    case SQLITE_FCNTL_LOCKSTATE: *(int *)argument = file->lock; return SQLITE_OK;
    case SQLITE_FCNTL_HAS_MOVED: *(int *)argument = 0; return SQLITE_OK;
    case SQLITE_FCNTL_MMAP_SIZE: *(sqlite3_int64 *)argument = 0; return SQLITE_OK;
    case SQLITE_FCNTL_PRAGMA: {
      const char *const *pragma = argument;
      if (pragma[1] && pragma[2] &&
          ((sqlite3_stricmp(pragma[1], "locking_mode") == 0 && sqlite3_stricmp(pragma[2], "exclusive") != 0) ||
           (sqlite3_stricmp(pragma[1], "journal_mode") == 0 && sqlite3_stricmp(pragma[2], "delete") != 0))) return SQLITE_ERROR;
      return SQLITE_NOTFOUND;
    }
    default: return SQLITE_NOTFOUND;
  }
}
static int lms_io_sector(sqlite3_file *base) { (void)base; return 4096; }
static int lms_io_capabilities(sqlite3_file *base) { (void)base; return 0; }
static const sqlite3_io_methods lms_io = {
  .iVersion = 1, .xClose = lms_io_close, .xRead = lms_io_read, .xWrite = lms_io_write,
  .xTruncate = lms_io_truncate, .xSync = lms_io_sync, .xFileSize = lms_io_size,
  .xLock = lms_io_lock, .xUnlock = lms_io_unlock, .xCheckReservedLock = lms_io_reserved,
  .xFileControl = lms_io_control, .xSectorSize = lms_io_sector, .xDeviceCharacteristics = lms_io_capabilities
};
static int lms_filename_role(const char *name) {
  if (name && strcmp(name, lms_main_name) == 0) return LMS_MAIN;
  if (name && strcmp(name, "/cliq-local-model-registry-journal") == 0) return LMS_JOURNAL;
  return LMS_ROLES;
}
static int lms_vfs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *base, int flags, int *output) {
  (void)vfs; base->pMethods = NULL;
  int role = lms_filename_role(name);
  int types = flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_WAL | SQLITE_OPEN_TEMP_DB |
    SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_TRANSIENT_DB | SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL);
  int expected = role == LMS_MAIN ? SQLITE_OPEN_MAIN_DB : SQLITE_OPEN_MAIN_JOURNAL;
  lms_context *ctx = atomic_load(&lms_process.active);
  if (role == LMS_ROLES || types != expected || !(flags & SQLITE_OPEN_READWRITE) ||
      (flags & (SQLITE_OPEN_READONLY | SQLITE_OPEN_MEMORY | SQLITE_OPEN_DELETEONCLOSE)) || !ctx ||
      atomic_load(&ctx->archive_held) || lms_check(ctx) != 0) return SQLITE_CANTOPEN;
  if (ctx->leases[role]) return SQLITE_BUSY;
  lms_file *file = (lms_file *)base;
  file->ctx = ctx; file->generation = ctx->generation; file->role = role; file->alive = 1; file->lock = SQLITE_LOCK_NONE;
  ctx->leases[role] = 1; ++ctx->live_files; base->pMethods = &lms_io;
  if (output) *output = flags;
  return SQLITE_OK;
}
static int lms_vfs_delete(sqlite3_vfs *vfs, const char *name, int sync_directory) {
  (void)vfs; lms_context *ctx = atomic_load(&lms_process.active);
  if (!ctx || lms_check(ctx) != 0 || ctx->exclusive) return SQLITE_IOERR_DELETE;
  if (lms_filename_role(name) != LMS_JOURNAL) return lms_io_failure(ctx, SQLITE_IOERR_DELETE);
  if (cliq_fd_sqlite_truncate(ctx->fd[LMS_JOURNAL], 0, NULL) != SQLITE_OK ||
      cliq_fd_sqlite_sync(ctx->fd[LMS_JOURNAL], SQLITE_SYNC_FULL, NULL) != SQLITE_OK ||
      (sync_directory && lms_sync(ctx, ctx->fd[LMS_STORE]) != 0)) return lms_io_failure(ctx, SQLITE_IOERR_DELETE);
  return SQLITE_OK;
}
static int lms_vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
  (void)vfs; *result = 0; lms_context *ctx = atomic_load(&lms_process.active);
  int role = lms_filename_role(name); struct stat st;
  /* Even the DELETE pager asks whether its fixed WAL exists. This is an
   * original-directory observation, never a fabricated absence or permission
   * to open, recover, mutate or remove WAL. Other names/flags still refuse. */
  if (name && strcmp(name, "/cliq-local-model-registry-wal") == 0) {
    if (flags != SQLITE_ACCESS_EXISTS || !ctx || lms_check(ctx) != 0) return SQLITE_IOERR_ACCESS;
    if (fstatat(ctx->fd[LMS_STORE], "registry.sqlite3-wal", &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT) return SQLITE_OK;
    return SQLITE_IOERR_ACCESS;
  }
  if (role == LMS_ROLES || (flags != SQLITE_ACCESS_EXISTS && flags != SQLITE_ACCESS_READ && flags != SQLITE_ACCESS_READWRITE)) return SQLITE_IOERR_ACCESS;
  if (!ctx || lms_check(ctx) != 0) return SQLITE_IOERR_ACCESS;
  if (fstat(ctx->fd[role], &st) != 0) return lms_io_failure(ctx, SQLITE_IOERR_ACCESS);
  *result = flags == SQLITE_ACCESS_EXISTS && role == LMS_JOURNAL ? st.st_size != 0 : 1; return SQLITE_OK;
}
static int lms_vfs_full_path(sqlite3_vfs *vfs, const char *name, int capacity, char *output) {
  (void)vfs;
  if (!name || (strcmp(name, "cliq-local-model-registry") != 0 && strcmp(name, lms_main_name) != 0) ||
      capacity <= 0 || (size_t)capacity < sizeof(lms_main_name)) return SQLITE_CANTOPEN;
  memcpy(output, lms_main_name, sizeof(lms_main_name)); return SQLITE_OK;
}
static void *lms_vfs_dl_open(sqlite3_vfs *vfs, const char *name) { (void)vfs; (void)name; return NULL; }
static void lms_vfs_dl_error(sqlite3_vfs *vfs, int capacity, char *output) {
  (void)vfs; if (capacity > 0) snprintf(output, (size_t)capacity, "%s", "model store VFS cannot load extensions");
}
static void (*lms_vfs_dl_sym(sqlite3_vfs *vfs, void *image, const char *name))(void) { (void)vfs; (void)image; (void)name; return NULL; }
static void lms_vfs_dl_close(sqlite3_vfs *vfs, void *image) { (void)vfs; (void)image; }
static int lms_vfs_random(sqlite3_vfs *vfs, int count, char *bytes) { (void)vfs; return lms_process.base->xRandomness(lms_process.base, count, bytes); }
static int lms_vfs_sleep(sqlite3_vfs *vfs, int micros) { (void)vfs; return lms_process.base->xSleep(lms_process.base, micros); }
static int lms_vfs_time(sqlite3_vfs *vfs, double *time) { (void)vfs; return lms_process.base->xCurrentTime(lms_process.base, time); }
static int lms_vfs_time64(sqlite3_vfs *vfs, sqlite3_int64 *time) {
  (void)vfs; sqlite3_vfs *base = lms_process.base;
  if (base->iVersion >= 2 && base->xCurrentTimeInt64) return base->xCurrentTimeInt64(base, time);
  double value; int result = base->xCurrentTime(base, &value);
  if (result == SQLITE_OK) *time = (sqlite3_int64)(value * 86400000.0);
  return result;
}
__attribute__((visibility("default"))) int sqlite3_cliqlocalmodelvfs_init(sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  (void)database; (void)error;
  lms_context *ctx = atomic_load(&lms_process.active);
  if (!lms_owner(ctx, ctx ? ctx->env : NULL) || lms_check(ctx) != 0 || !api || !api->sourceid || !api->stricmp ||
      !api->vfs_find || !api->vfs_register || (sqlite3_api && sqlite3_api != api)) return SQLITE_ERROR;
  SQLITE_EXTENSION_INIT2(api);
  if (lms_process.registered) return sqlite3_vfs_find(lms_vfs_name) == &lms_process.vfs ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
  sqlite3_vfs *base = sqlite3_vfs_find(NULL);
  if (!base || !base->xRandomness || !base->xSleep || !base->xCurrentTime || sqlite3_vfs_find(lms_vfs_name)) return SQLITE_ERROR;
  lms_process.base = base;
  lms_process.vfs = (sqlite3_vfs) {
    .iVersion = 2, .szOsFile = sizeof(lms_file), .mxPathname = 128, .zName = lms_vfs_name,
    .pAppData = &lms_process, .xOpen = lms_vfs_open, .xDelete = lms_vfs_delete,
    .xAccess = lms_vfs_access, .xFullPathname = lms_vfs_full_path,
    .xDlOpen = lms_vfs_dl_open, .xDlError = lms_vfs_dl_error, .xDlSym = lms_vfs_dl_sym,
    .xDlClose = lms_vfs_dl_close, .xRandomness = lms_vfs_random,
    .xSleep = lms_vfs_sleep, .xCurrentTime = lms_vfs_time, .xCurrentTimeInt64 = lms_vfs_time64
  };
  if (sqlite3_vfs_register(&lms_process.vfs, 0) != SQLITE_OK) return SQLITE_ERROR;
  lms_process.registered = 1; return SQLITE_OK_LOAD_PERMANENTLY;
}

static lms_context *lms_receiver(napi_env env, napi_value self) {
  bool tagged = false; lms_context *ctx = NULL;
  if (napi_check_object_type_tag(env, self, &lms_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&ctx) != napi_ok || !lms_owner(ctx, env) ||
      ctx->retired || atomic_load(&lms_process.active) != ctx) {
    lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "invalid original model-store holder"); return NULL;
  }
  if (lms_check(ctx) != 0) { lms_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "model-store custody changed or is uncertain"); return NULL; }
  return ctx;
}
static napi_value lms_assert(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "model-store assertion accepts no arguments");
  if (!lms_receiver(env, self)) return NULL;
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static int lms_cancelled_retirement_custody(lms_context *ctx, napi_env env) {
  if (!lms_owner(ctx, env) || !ctx->exclusive || lms_exclusive_check(ctx->exclusive, env) != 0 ||
      ctx->uncertain || atomic_load(&lms_process.active) != ctx) return -1;
  for (int role = 0; role < LMS_ROLES; ++role) {
    struct stat held;
    if (ctx->fd[role] < 0 || fstat(ctx->fd[role], &held) != 0 || !same_inode(&held, &ctx->identity[role])) {
      lms_poison(ctx); return -1;
    }
  }
  return 0;
}
static napi_value lms_close(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; bool tagged = false; lms_context *ctx = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
      napi_check_object_type_tag(env, self, &lms_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&ctx) != napi_ok || !lms_owner(ctx, env)) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "invalid original model-store close");
  if (!ctx->retired) {
    /* A failed archive data snapshot has no authority to resume. Its private
     * cancel path already consumed every owned visitor description and bound
     * the unchanged original FD identities; only actual retirement remains. */
    if ((!ctx->archive_cancelled && lms_check(ctx) != 0) ||
        (ctx->archive_cancelled && lms_cancelled_retirement_custody(ctx, env) != 0) ||
        ctx->live_files || ctx->package || atomic_load(&ctx->archive_held) || lms_retire(ctx) != 0)
      return lms_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "model-store resources remain live or uncertain; original custody retained");
    atomic_store(&lms_process.active, NULL);
    if (ctx->reference) { napi_ref reference = ctx->reference; ctx->reference = NULL;
      if (napi_delete_reference(env, reference) != napi_ok) { lms_poison(ctx); return lms_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "model-store owner reference did not retire"); }
    }
  }
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void lms_finalize(napi_env env, void *data, void *hint) {
  (void)hint; lms_context *ctx = data;
  if (!lms_owner(ctx, env)) return;
  ctx->finalized = 1;
  if (ctx->retired && !ctx->uncertain && !ctx->package && !ctx->live_files && !ctx->package_handles) free(ctx);
}
static int lms_ref(napi_env env, napi_value value, char output[65]) {
  size_t length;
  if (napi_get_value_string_utf8(env, value, NULL, 0, &length) != napi_ok || length != 64 ||
      napi_get_value_string_utf8(env, value, output, 65, &length) != napi_ok || length != 64) return -1;
  for (size_t i = 0; i < 64; ++i) if (!((output[i] >= '0' && output[i] <= '9') || (output[i] >= 'a' && output[i] <= 'f'))) return -1;
  return 0;
}
static int lms_hash_fd(lms_context *ctx, int fd, const struct stat *identity, const char *reference, unsigned char *small, size_t capacity) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || identity->st_size <= 0 || (small && (uint64_t)identity->st_size > capacity)) return -1;
  struct sha256_context hash; sha256_init(&hash);
  unsigned char bytes[65536]; off_t offset = 0;
  while (offset < identity->st_size) {
    size_t size = (uint64_t)(identity->st_size - offset) < sizeof(bytes) ? (size_t)(identity->st_size - offset) : sizeof(bytes);
    if (cliq_fd_sqlite_read(fd, bytes, (int)size, (sqlite3_int64)offset, NULL) != SQLITE_OK) return -1;
    sha256_update(&hash, bytes, size); if (small) memcpy(small + offset, bytes, size); offset += (off_t)size;
  }
  struct stat after; char digest[65]; publication_hash_hex(&hash, digest);
  if (fstat(fd, &after) != 0 || !source_metadata_same(identity, &after) || strcmp(digest, reference) != 0 || lms_check(ctx) != 0) return -1;
  return 0;
}
static napi_value lms_read_small(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; char reference[65];
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count != 1 || lms_ref(env, argument, reference) != 0)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "invalid model-store content reference");
  lms_context *ctx = lms_receiver(env, self); if (!ctx) return NULL;
  if (atomic_load(&ctx->archive_held)) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original archive visitor currently owns the model-store namespace");
  int fd = openat(ctx->fd[LMS_OBJECTS], reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st; unsigned char *bytes = NULL;
  if (fd < 0 || fstat(fd, &st) != 0 || !lms_object_file(&st) || st.st_size > 1048576 ||
      !(bytes = malloc((size_t)st.st_size)) || lms_hash_fd(ctx, fd, &st, reference, bytes, (size_t)st.st_size) != 0) goto failed;
  if (lms_close_fd(ctx, &fd) != 0) goto failed;
  if (napi_create_buffer_copy(env, (size_t)st.st_size, bytes, NULL, &result) != napi_ok) goto failed;
  free(bytes); return result;
failed:
  free(bytes); if (!ctx->uncertain) lms_close_fd(ctx, &fd);
  return lms_error(env, ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_STORE", "model-store original object failed bounded complete-byte validation");
}
static int lms_temp(lms_context *ctx, char output[96]) {
  unsigned char random[16];
#ifdef __linux__
  size_t consumed = 0;
  while (consumed < sizeof(random)) {
    ssize_t size = syscall(SYS_getrandom, random + consumed, sizeof(random) - consumed, 0);
    if (size < 0 && errno == EINTR) continue;
    if (size <= 0) return -1;
    consumed += (size_t)size;
  }
#else
  if (getentropy(random, sizeof(random)) != 0) return -1;
#endif
  char suffix[33];
  for (size_t i = 0; i < sizeof(random); ++i) snprintf(suffix + i * 2, 3, "%02x", random[i]);
  int count = snprintf(output, 96, ".model-object-v1-%s", suffix);
  (void)ctx; return count > 0 && count < 96 ? 0 : -1;
}
static int lms_discard_temp(lms_context *ctx, int *fd, const struct stat *birth, const char *name) {
  struct stat held, named;
  if (*fd < 0 || !name[0]) return *fd < 0 && !name[0] ? 0 : -1;
  if (lms_check(ctx) != 0 || fstat(*fd, &held) != 0 || !same_inode(&held, birth) ||
      fstatat(ctx->fd[LMS_OBJECTS], name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !same_inode(&held, &named) ||
      held.st_nlink != 1 || !S_ISREG(held.st_mode) || unlinkat(ctx->fd[LMS_OBJECTS], name, 0) != 0 ||
      lms_sync(ctx, ctx->fd[LMS_OBJECTS]) != 0 || lms_close_fd(ctx, fd) != 0) { lms_poison(ctx); return -1; }
  return 0;
}
/* chmod does not revoke an existing writable open-file-description. Consume
 * that exact writer, then independently open only this original named inode
 * read-only before the full target readback. A failed close is never retried. */
static int lms_reopen_read_only(lms_context *ctx, int *fd, const char *name, const struct stat *expected) {
  struct stat held, named; int flags = fcntl(*fd, F_GETFL);
  if (lms_check(ctx) != 0 || flags < 0 || (flags & O_ACCMODE) != O_RDWR ||
      fstat(*fd, &held) != 0 || !lms_object_file(&held) || !source_metadata_same(&held, expected) ||
      fstatat(ctx->fd[LMS_OBJECTS], name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&held, &named)) return -1;
  if (lms_close_fd(ctx, fd) != 0) return -1;
  *fd = openat(ctx->fd[LMS_OBJECTS], name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  flags = *fd < 0 ? -1 : fcntl(*fd, F_GETFL);
  if (*fd < 0 || flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat(*fd, &held) != 0 || !lms_object_file(&held) ||
      !source_metadata_same(&held, expected) || fstatat(ctx->fd[LMS_OBJECTS], name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
      !source_metadata_same(&held, &named) || lms_check(ctx) != 0) { lms_poison(ctx); return -1; }
  return 0;
}
static napi_value lms_publish_small(napi_env env, napi_callback_info info) {
  size_t count = 2, size = 0; napi_value arguments[2], self, result; char reference[65], temporary[96] = {0}; void *data;
  if (napi_get_cb_info(env, info, &count, arguments, &self, NULL) != napi_ok || count != 2 ||
      lms_ref(env, arguments[0], reference) != 0 || napi_get_buffer_info(env, arguments[1], &data, &size) != napi_ok || !size || size > 1048576)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "invalid bounded immutable model object");
  lms_context *ctx = lms_receiver(env, self); if (!ctx) return NULL;
  if (ctx->exclusive) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "archive model-store borrow cannot publish objects");
  struct sha256_context hash; char digest[65]; sha256_init(&hash); sha256_update(&hash, data, size); publication_hash_hex(&hash, digest);
  if (strcmp(digest, reference) != 0) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "model object bytes differ from original content reference");
  int fd = openat(ctx->fd[LMS_OBJECTS], reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat birth = {0};
  if (fd >= 0) {
    if (fstat(fd, &birth) != 0 || !lms_object_file(&birth) || birth.st_size != (off_t)size ||
        lms_hash_fd(ctx, fd, &birth, reference, NULL, 0) != 0 || lms_close_fd(ctx, &fd) != 0) goto failed;
    return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
  }
  if (errno != ENOENT || lms_temp(ctx, temporary) != 0) goto failed;
  fd = openat(ctx->fd[LMS_OBJECTS], temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) { temporary[0] = '\0'; goto failed; }
  if (fstat(fd, &birth) != 0 || !lms_data_file(&birth) ||
      cliq_fd_sqlite_write(fd, data, (int)size, 0, NULL) != SQLITE_OK || fchmod(fd, 0400) != 0 || lms_sync(ctx, fd) != 0) goto failed;
  struct stat ready;
  if (fstat(fd, &ready) != 0 || !same_inode(&ready, &birth) || !lms_object_file(&ready) || ready.st_size != (off_t)size ||
      lms_reopen_read_only(ctx, &fd, temporary, &ready) != 0 ||
      lms_hash_fd(ctx, fd, &ready, reference, NULL, 0) != 0 ||
      !publication_rename_exclusive(ctx->fd[LMS_OBJECTS], temporary, ctx->fd[LMS_OBJECTS], reference)) goto failed;
  temporary[0] = '\0';
  if (lms_sync(ctx, ctx->fd[LMS_OBJECTS]) != 0 || lms_close_fd(ctx, &fd) != 0 || lms_check(ctx) != 0) goto failed;
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
failed:
  if (!ctx->uncertain) {
    if (temporary[0]) lms_discard_temp(ctx, &fd, &birth, temporary);
    else lms_close_fd(ctx, &fd);
  }
  return lms_error(env, ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_STORE", "immutable model object publication failed; head unchanged");
}

/* Package capture and bounded 64 KiB copy are defined below, under this same
 * original store holder. No source descriptor is exposed to JavaScript. */
static napi_value lms_open_package(napi_env env, napi_callback_info info);
static napi_value lms_open_object_source(napi_env env, napi_callback_info info);
static napi_value acquire_local_model_store_fixed(napi_env env, napi_callback_info info, int existing_only) {
  int expected = 0;
  if (!atomic_compare_exchange_strong(&lms_process.acquiring, &expected, 1))
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "model-store holder is active, uncertain or foreign");
  if (atomic_load(&lms_process.active) || atomic_load(&lms_process.poisoned) ||
      !kernel_global_main_thread() || getuid() != geteuid() || getgid() != getegid()) {
    atomic_store(&lms_process.acquiring, 0);
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "model-store holder is active, uncertain or foreign");
  }
  lms_context *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) { atomic_store(&lms_process.acquiring, 0); return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "model-store allocation failed"); }
  for (int i = 0; i < LMS_ROLES; ++i) ctx->fd[i] = -1;
  ctx->env = env; ctx->pid = getpid(); ctx->uid = geteuid(); ctx->gid = getegid(); ctx->thread = pthread_self();
  ctx->existing_only = existing_only;
  size_t count = 5, length; napi_value arguments[5]; double descriptor;
  bool array = false, lossless; uint32_t tuple_length; uint64_t tuple[5]; int busy = 0, wrapped = 0, absent = 0;
  const char *code = "ERR_CLIQ_LOCAL_MODEL_STORE";
  if (napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || (count != 3 && (existing_only || count != 4)) ||
      napi_get_value_double(env, arguments[0], &descriptor) != napi_ok || !(descriptor >= 0 && descriptor <= INT_MAX) || descriptor != (int)descriptor ||
      napi_get_value_string_utf8(env, arguments[1], NULL, 0, &length) != napi_ok || length < 2 || length >= sizeof(ctx->root_path) ||
      napi_get_value_string_utf8(env, arguments[1], ctx->root_path, sizeof(ctx->root_path), &length) != napi_ok || strlen(ctx->root_path) != length ||
      napi_is_array(env, arguments[2], &array) != napi_ok || !array || napi_get_array_length(env, arguments[2], &tuple_length) != napi_ok || tuple_length != 5) goto failed;
  for (uint32_t i = 0; i < 5; ++i) { napi_value item;
    if (napi_get_element(env, arguments[2], i, &item) != napi_ok || napi_get_value_bigint_uint64(env, item, &tuple[i], &lossless) != napi_ok || !lossless) goto failed;
  }
  if (count == 4) {
    bool tagged = false; lms_exclusive_binding *exclusive = NULL;
    if (napi_check_object_type_tag(env, arguments[3], &lms_exclusive_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[3], (void **)&exclusive) != napi_ok || lms_exclusive_check(exclusive, env) != 0 ||
        exclusive->borrowers == UINT_MAX) goto failed;
    ctx->exclusive = exclusive; ++exclusive->borrowers;
    if (napi_create_reference(env, arguments[3], 1, &ctx->exclusive_reference) != napi_ok) {
      lms_exclusive_poison(exclusive); lms_poison(ctx); goto failed;
    }
  } else if (kernel_global_acquire(env, 1, 0, &ctx->global, &code) != 1) { busy = strcmp(code, "ERR_CLIQ_KERNEL_GLOBAL_BUSY") == 0; goto failed; }
  struct stat original;
  if (fstat((int)descriptor, &original) != 0 || !lms_directory(&original) ||
      (uint64_t)original.st_dev != tuple[0] || (uint64_t)original.st_ino != tuple[1] ||
      (uint64_t)original.st_uid != tuple[2] || (uint64_t)original.st_gid != tuple[3] || (uint64_t)original.st_mode != tuple[4]) goto failed;
  ctx->identity[LMS_ROOT] = original; ctx->fd[LMS_ROOT] = fcntl((int)descriptor, F_DUPFD_CLOEXEC, 0);
  if (ctx->exclusive && (strcmp(ctx->exclusive->original->owner->path, ctx->root_path) != 0 ||
      !same_inode(&ctx->exclusive->original->owner->root, &original))) goto failed;
  if (ctx->exclusive || ctx->existing_only) {
    struct stat store;
    if (fstatat(ctx->fd[LMS_ROOT], "local-models", &store, AT_SYMLINK_NOFOLLOW) != 0) {
      absent = errno == ENOENT; goto failed;
    }
  }
  if (ctx->fd[LMS_ROOT] < 0 || lms_hold_directory(ctx, ctx->fd[LMS_ROOT], "local-models", LMS_STORE) != 0 ||
      lms_hold_file(ctx, LMS_LOCK) != 0) goto failed;
  int locked; do { locked = flock(ctx->fd[LMS_LOCK], LOCK_EX | LOCK_NB); } while (locked < 0 && errno == EINTR);
  if (locked != 0) { busy = errno == EWOULDBLOCK || errno == EAGAIN || errno == EACCES; goto failed; }
  if (lms_hold_directory(ctx, ctx->fd[LMS_STORE], "objects", LMS_OBJECTS) != 0 ||
      lms_hold_file(ctx, LMS_MAIN) != 0 || lms_inode_guard(ctx, LMS_MAIN) != 0 ||
      lms_hold_file(ctx, LMS_JOURNAL) != 0 || lms_inode_guard(ctx, LMS_JOURNAL) != 0) goto failed;
  if (ctx->existing_only) {
    unsigned char header[100];
    if (ctx->identity[LMS_MAIN].st_size < (off_t)sizeof(header) ||
        cliq_fd_sqlite_read(ctx->fd[LMS_MAIN], header, sizeof(header), 0, NULL) != SQLITE_OK ||
        memcmp(header, "SQLite format 3\0", 16) || header[18] != 1 || header[19] != 1) goto failed;
  }
  if (lms_process.generation == UINT64_MAX) { lms_poison(ctx); goto failed; }
  ctx->generation = ++lms_process.generation; ctx->prepared = 1;
  atomic_store(&lms_process.active, ctx);
  if (lms_check(ctx) != 0) goto failed;
  const napi_property_descriptor methods[] = {
    {"assertHeld", NULL, lms_assert, NULL, NULL, NULL, napi_default, NULL},
    {"readSmallObject", NULL, lms_read_small, NULL, NULL, NULL, napi_default, NULL},
    {"publishSmallObject", NULL, lms_publish_small, NULL, NULL, NULL, napi_default, NULL},
    {"openPackage", NULL, lms_open_package, NULL, NULL, NULL, napi_default, NULL},
    {"openObjectSource", NULL, lms_open_object_source, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, lms_close, NULL, NULL, NULL, napi_default, NULL}
  };
  napi_value result;
  if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &lms_tag) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, ctx, lms_finalize, NULL, NULL) != napi_ok) goto failed;
  wrapped = 1;
  if (napi_create_reference(env, result, 1, &ctx->reference) != napi_ok) goto failed;
  atomic_store(&lms_process.acquiring, 0); return result;
failed:
  if (!ctx->uncertain && lms_retire(ctx) == 0) { atomic_store(&lms_process.active, NULL); if (!wrapped) free(ctx); }
  else { lms_poison(ctx); atomic_store(&lms_process.active, ctx); code = "ERR_CLIQ_RESOURCE_RETIREMENT"; busy = 0; }
  atomic_store(&lms_process.acquiring, 0);
  if (absent && strcmp(code, "ERR_CLIQ_RESOURCE_RETIREMENT") != 0) {
    napi_value result; return napi_get_null(env, &result) == napi_ok ? result : NULL;
  }
  return lms_error(env, busy ? "ERR_CLIQ_LOCAL_MODEL_BUSY" : code,
    busy ? "original model-store or account gate is busy" : "model-store acquisition refused; original custody retained if uncertain");
}
static napi_value acquire_local_model_store(napi_env env, napi_callback_info info) { return acquire_local_model_store_fixed(env, info, 0); }
static napi_value inspect_existing_local_model_store(napi_env env, napi_callback_info info) { return acquire_local_model_store_fixed(env, info, 1); }

typedef struct { char reference[65]; struct stat original; int copied; } lms_package_entry;
struct lms_package {
  lms_context *ctx;
  uint64_t generation;
  int root_fd, objects_fd, manifest_fd, source_fd, target_fd;
  struct stat root, objects, manifest, source, target, temporary_birth;
  napi_ref reference;
  char path[PATH_MAX], temporary[96], current_ref[65];
  lms_package_entry *entries;
  size_t count, current;
  int captured, completed, closed, phase, existing, finalized;
  off_t offset;
  struct sha256_context hash;
};
static int lms_package_directory(const struct stat *st) {
  return S_ISDIR(st->st_mode) && st->st_uid == geteuid() && st->st_gid == getegid() &&
    (st->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) == 0;
}
static int lms_package_file(const struct stat *st) {
  return S_ISREG(st->st_mode) && st->st_uid == geteuid() && st->st_gid == getegid() &&
    st->st_nlink == 1 && st->st_size > 0 && (uint64_t)st->st_size <= 9007199254740991ULL &&
    (st->st_mode & (0111 | S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) == 0;
}
static int lms_package_check(lms_package *package) {
  lms_context *ctx = package->ctx; struct stat st, named;
  if (package->closed || ctx->package != package || package->generation != ctx->generation || lms_check(ctx) != 0) return -1;
  int visible = lms_walk(ctx, package->path);
  if (visible < 0) return -1;
  int valid = fstat(visible, &st) == 0 && source_metadata_same(&st, &package->root) &&
    fstat(package->root_fd, &st) == 0 && source_metadata_same(&st, &package->root) &&
    fstat(package->objects_fd, &st) == 0 && source_metadata_same(&st, &package->objects) &&
    fstatat(package->root_fd, "objects", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&st, &named) &&
    fstat(package->manifest_fd, &st) == 0 && source_metadata_same(&st, &package->manifest) &&
    fstatat(package->root_fd, "model-manifest.json", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&st, &named);
  if (lms_close_fd(ctx, &visible) != 0) return -1;
  return valid ? 0 : -1;
}
static lms_package *lms_package_receiver(napi_env env, napi_value self) {
  bool tagged = false; lms_package *package = NULL;
  if (napi_check_object_type_tag(env, self, &lms_package_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&package) != napi_ok || !package || !lms_owner(package->ctx, env) ||
      lms_package_check(package) != 0) {
    lms_error(env, package && package->ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_PACKAGE",
      "original model package is closed, changed or foreign"); return NULL;
  }
  return package;
}
static int lms_package_root_entries(lms_package *package) {
  int duplicate = openat(package->root_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate < 0) return -1;
  DIR *directory = fdopendir(duplicate);
  if (!directory) { lms_close_fd(package->ctx, &duplicate); return -1; }
  struct dirent *entry; unsigned count = 0; int valid = 1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    if (++count > 2 || (strcmp(entry->d_name, "model-manifest.json") != 0 && strcmp(entry->d_name, "objects") != 0)) { valid = 0; break; }
    errno = 0;
  }
  if (errno || count != 2) valid = 0;
  if (closedir(directory) != 0) { lms_poison(package->ctx); return -1; }
  return valid ? 0 : -1;
}
static int lms_entry_compare(const void *left, const void *right) {
  return strcmp(((const lms_package_entry *)left)->reference, ((const lms_package_entry *)right)->reference);
}
static lms_package_entry *lms_find_entry(lms_package *package, const char *reference) {
  if (strlen(reference) != 64) return NULL;
  lms_package_entry key = {0}; memcpy(key.reference, reference, 65);
  return package->captured ? bsearch(&key, package->entries, package->count, sizeof(key), lms_entry_compare) : NULL;
}
static int lms_package_inventory(lms_package *package, int require_copied) {
  if (lms_package_check(package) != 0 || lms_package_root_entries(package) != 0) return -1;
  int duplicate = openat(package->objects_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (duplicate < 0) return -1;
  DIR *directory = fdopendir(duplicate);
  if (!directory) { lms_close_fd(package->ctx, &duplicate); return -1; }
  struct dirent *entry; size_t count = 0; int valid = 1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    lms_package_entry *expected = lms_find_entry(package, entry->d_name); struct stat st;
    if (++count > package->count || !expected || (require_copied && !expected->copied) ||
        fstatat(package->objects_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !lms_package_file(&st) || !source_metadata_same(&st, &expected->original)) { valid = 0; break; }
    errno = 0;
  }
  if (errno || count != package->count) valid = 0;
  if (closedir(directory) != 0) { lms_poison(package->ctx); return -1; }
  return valid && lms_package_check(package) == 0 ? 0 : -1;
}
static napi_value lms_package_manifest(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "manifest read accepts no arguments");
  lms_package *package = lms_package_receiver(env, self); if (!package) return NULL;
  size_t size = (size_t)package->manifest.st_size; unsigned char *bytes;
  if (size > 1048576 || !(bytes = malloc(size))) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "model manifest exceeds fixed byte budget");
  int status = cliq_fd_sqlite_read(package->manifest_fd, bytes, (int)size, 0, NULL);
  if (status != SQLITE_OK || lms_package_check(package) != 0 || napi_create_buffer_copy(env, size, bytes, NULL, &result) != napi_ok) {
    free(bytes); return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "original manifest changed during bounded read");
  }
  free(bytes); return result;
}
static uint64_t lms_u64(const unsigned char *bytes) {
  uint64_t value = 0; for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (8U * i); return value;
}
static void lms_put_u64(unsigned char *bytes, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) bytes[i] = (unsigned char)(value >> (8U * i));
}
static napi_value lms_package_capture(napi_env env, napi_callback_info info) {
  size_t count = 1, size; napi_value argument, self, result; unsigned char *bytes;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count != 1 ||
      napi_get_buffer_info(env, argument, (void **)&bytes, &size) != napi_ok || size < 144 || size % 72 || size / 72 > 10000)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "invalid closed package inventory");
  lms_package *package = lms_package_receiver(env, self); if (!package) return NULL;
  if (package->captured || package->entries) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "original package inventory is already captured");
  package->count = size / 72; package->entries = calloc(package->count, sizeof(*package->entries));
  if (!package->entries) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "package inventory allocation failed");
  for (size_t i = 0; i < package->count; ++i) {
    lms_package_entry *entry = &package->entries[i]; memcpy(entry->reference, bytes + i * 72, 64); entry->reference[64] = '\0';
    for (unsigned j = 0; j < 64; ++j) if (!((entry->reference[j] >= '0' && entry->reference[j] <= '9') ||
        (entry->reference[j] >= 'a' && entry->reference[j] <= 'f'))) goto failed;
    uint64_t expected = lms_u64(bytes + i * 72 + 64);
    if (expected > 9007199254740991ULL || fstatat(package->objects_fd, entry->reference, &entry->original, AT_SYMLINK_NOFOLLOW) != 0 ||
        !lms_package_file(&entry->original) || (expected && expected != (uint64_t)entry->original.st_size)) goto failed;
  }
  qsort(package->entries, package->count, sizeof(*package->entries), lms_entry_compare);
  for (size_t i = 1; i < package->count; ++i) if (strcmp(package->entries[i - 1].reference, package->entries[i].reference) == 0) goto failed;
  package->captured = 1;
  if (lms_package_inventory(package, 0) != 0) goto failed;
  unsigned char *observed = malloc(size); if (!observed) goto failed;
  for (size_t i = 0; i < package->count; ++i) {
    memcpy(observed + i * 72, package->entries[i].reference, 64);
    lms_put_u64(observed + i * 72 + 64, (uint64_t)package->entries[i].original.st_size);
  }
  int status = napi_create_buffer_copy(env, size, observed, NULL, &result); free(observed);
  if (status == napi_ok) return result;
failed:
  /* A failed capture cannot be repaired by a different caller inventory. */
  package->captured = 0;
  return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "package must contain all and only its original declared objects");
}
static napi_value lms_package_signature(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; char reference[65];
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count != 1 || lms_ref(env, argument, reference) != 0)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "invalid detached model signature reference");
  lms_package *package = lms_package_receiver(env, self); if (!package) return NULL;
  lms_package_entry *entry = lms_find_entry(package, reference);
  if (!entry || entry->original.st_size != 64) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "detached Ed25519 signature must be an original 64-byte inventory object");
  int fd = openat(package->objects_fd, reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat st;
  unsigned char bytes[64]; struct sha256_context hash; char digest[65];
  if (fd < 0 || fstat(fd, &st) != 0 || !source_metadata_same(&st, &entry->original) ||
      cliq_fd_sqlite_read(fd, bytes, 64, 0, NULL) != SQLITE_OK || fstat(fd, &st) != 0 ||
      !source_metadata_same(&st, &entry->original) || lms_package_check(package) != 0) goto failed;
  sha256_init(&hash); sha256_update(&hash, bytes, 64); publication_hash_hex(&hash, digest);
  if (strcmp(digest, reference) != 0 || lms_close_fd(package->ctx, &fd) != 0) goto failed;
  return napi_create_buffer_copy(env, 64, bytes, NULL, &result) == napi_ok ? result : NULL;
failed:
  if (!package->ctx->uncertain) lms_close_fd(package->ctx, &fd);
  return lms_error(env, package->ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "original detached model signature changed");
}
static int lms_package_current(lms_package *package) {
  struct stat st, named;
  if (lms_package_check(package) != 0 || package->source_fd < 0 || package->target_fd < 0 ||
      fstat(package->source_fd, &st) != 0 || !source_metadata_same(&st, &package->source) ||
      fstatat(package->objects_fd, package->current_ref, &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&st, &named) ||
      fstat(package->target_fd, &st) != 0 || !same_inode(&st, &package->target) || st.st_nlink != 1 || !S_ISREG(st.st_mode) ||
      ((package->existing || package->phase > 0) && (!source_metadata_same(&st, &package->target) ||
        (fcntl(package->target_fd, F_GETFL) & O_ACCMODE) != O_RDONLY))) return -1;
  const char *leaf = package->existing ? package->current_ref : package->temporary;
  return fstatat(package->ctx->fd[LMS_OBJECTS], leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&st, &named) ? 0 : -1;
}
static int lms_package_begin_copy(lms_package *package, const char *reference) {
  lms_package_entry *entry = lms_find_entry(package, reference);
  if (!entry || entry->copied || package->source_fd >= 0 || package->target_fd >= 0 || package->completed) return -1;
  package->current = (size_t)(entry - package->entries); memcpy(package->current_ref, reference, 65);
  package->source_fd = openat(package->objects_fd, reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (package->source_fd < 0 || fstat(package->source_fd, &package->source) != 0 || !source_metadata_same(&package->source, &entry->original)) return -1;
  package->target_fd = openat(package->ctx->fd[LMS_OBJECTS], reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  package->existing = package->target_fd >= 0;
  if (!package->existing) {
    if (errno != ENOENT || lms_temp(package->ctx, package->temporary) != 0) return -1;
    package->target_fd = openat(package->ctx->fd[LMS_OBJECTS], package->temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (package->target_fd < 0) { package->temporary[0] = '\0'; return -1; }
  }
  if (fstat(package->target_fd, &package->target) != 0 ||
      (package->existing ? !lms_object_file(&package->target) || package->target.st_size != package->source.st_size : !lms_data_file(&package->target))) return -1;
  package->temporary_birth = package->target;
  package->phase = 0; package->offset = 0; sha256_init(&package->hash); return lms_package_current(package);
}
static int lms_package_step(lms_package *package) {
  if (lms_package_current(package) != 0) return -1;
  if (package->offset < package->source.st_size) {
    unsigned char bytes[65536];
    size_t count = (uint64_t)(package->source.st_size - package->offset) < sizeof(bytes) ? (size_t)(package->source.st_size - package->offset) : sizeof(bytes);
    int descriptor = package->phase == 2 ? package->target_fd : package->source_fd;
    if (cliq_fd_sqlite_read(descriptor, bytes, (int)count, (sqlite3_int64)package->offset, NULL) != SQLITE_OK ||
        (package->phase == 0 && !package->existing &&
          cliq_fd_sqlite_write(package->target_fd, bytes, (int)count, (sqlite3_int64)package->offset, NULL) != SQLITE_OK)) return -1;
    sha256_update(&package->hash, bytes, count); package->offset += (off_t)count;
    return lms_package_current(package) == 0 ? 0 : -1;
  }
  char digest[65]; publication_hash_hex(&package->hash, digest);
  if (strcmp(digest, package->current_ref) != 0) return -1;
  if (package->phase == 0 && !package->existing) {
    if (fchmod(package->target_fd, 0400) != 0 || lms_sync(package->ctx, package->target_fd) != 0 ||
        fstat(package->target_fd, &package->target) != 0 || !lms_object_file(&package->target) ||
        package->target.st_size != package->source.st_size ||
        lms_reopen_read_only(package->ctx, &package->target_fd, package->temporary, &package->target) != 0) return -1;
  }
  if (package->phase < 2) { ++package->phase; package->offset = 0; sha256_init(&package->hash); return 0; }
  if (!package->existing) {
    if (!publication_rename_exclusive(package->ctx->fd[LMS_OBJECTS], package->temporary,
        package->ctx->fd[LMS_OBJECTS], package->current_ref)) return -1;
    package->temporary[0] = '\0';
    if (lms_sync(package->ctx, package->ctx->fd[LMS_OBJECTS]) != 0) return -1;
  }
  if (lms_close_fd(package->ctx, &package->source_fd) != 0 || lms_close_fd(package->ctx, &package->target_fd) != 0) return -1;
  package->entries[package->current].copied = 1; package->current_ref[0] = '\0'; package->phase = 0; return 1;
}
static napi_value lms_package_copy(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; char reference[65];
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count != 1 || lms_ref(env, argument, reference) != 0)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "invalid package copy reference");
  lms_package *package = lms_package_receiver(env, self); if (!package) return NULL;
  if (!package->captured || (package->current_ref[0] ? strcmp(package->current_ref, reference) != 0 : lms_package_begin_copy(package, reference) != 0)) goto failed;
  int complete = lms_package_step(package);
  if (complete < 0) goto failed;
  return napi_get_boolean(env, complete != 0, &result) == napi_ok ? result : NULL;
failed:
  /* Caller must close/join the original package; a rejected copy cannot be
   * restarted or converted into an active registry pointer. */
  package->completed = -1;
  return lms_error(env, package->ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "original package copy failed complete integrity or custody checks");
}
static napi_value lms_package_finish(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "package finish accepts no arguments");
  lms_package *package = lms_package_receiver(env, self); if (!package) return NULL;
  if (!package->captured || package->completed < 0 || package->source_fd >= 0 || package->target_fd >= 0 ||
      lms_package_inventory(package, 1) != 0 || lms_sync(package->ctx, package->ctx->fd[LMS_OBJECTS]) != 0)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "model package has incomplete or changed original objects");
  package->completed = 1; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static int lms_package_join(lms_package *package) {
  if (package->closed) return 0;
  lms_context *ctx = package->ctx;
  if (!lms_owner(ctx, ctx->env) || ctx->uncertain || ctx->package != package || lms_check(ctx) != 0) return -1;
  if (package->temporary[0]) {
    if (lms_discard_temp(ctx, &package->target_fd, &package->temporary_birth, package->temporary) != 0) return -1;
    package->temporary[0] = '\0';
  } else if (lms_close_fd(ctx, &package->target_fd) != 0) return -1;
  if (lms_close_fd(ctx, &package->source_fd) != 0 || lms_close_fd(ctx, &package->manifest_fd) != 0 ||
      lms_close_fd(ctx, &package->objects_fd) != 0 || lms_close_fd(ctx, &package->root_fd) != 0) return -1;
  ctx->package = NULL; package->closed = 1;
  if (package->reference) { napi_ref ref = package->reference; package->reference = NULL;
    if (napi_delete_reference(ctx->env, ref) != napi_ok) { lms_poison(ctx); return -1; }
  }
  return 0;
}
static napi_value lms_package_close(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; bool tagged = false; lms_package *package = NULL; void *purpose;
  if (napi_get_cb_info(env, info, &count, &argument, &self, &purpose) != napi_ok || count ||
      napi_check_object_type_tag(env, self, purpose ? &lms_object_source_tag : &lms_package_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&package) != napi_ok || !package || !lms_owner(package->ctx, env))
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "invalid original package close");
  if (lms_package_join(package) != 0) return lms_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "original model package resources did not join; store retained");
  return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void lms_package_finalize(napi_env env, void *data, void *hint) {
  (void)hint; lms_package *package = data;
  if (!lms_owner(package->ctx, env)) return;
  package->finalized = 1;
  if (package->closed && !package->ctx->uncertain) {
    lms_context *ctx = package->ctx;
    if (!ctx->package_handles) { lms_poison(ctx); return; }
    --ctx->package_handles; free(package->entries); free(package);
    if (ctx->finalized && ctx->retired && !ctx->package_handles && !ctx->live_files && !ctx->package) free(ctx);
  }
}
static napi_value lms_open_package(napi_env env, napi_callback_info info) {
  size_t count = 1, length; napi_value argument, self, result;
  char path[PATH_MAX];
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count != 1 ||
      napi_get_value_string_utf8(env, argument, NULL, 0, &length) != napi_ok || length < sizeof("/model-manifest.json") - 1 || length >= sizeof(path) ||
      napi_get_value_string_utf8(env, argument, path, sizeof(path), &length) != napi_ok || strlen(path) != length)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "model enrollment requires an explicit canonical manifest path");
  char *leaf = strrchr(path, '/');
  if (!leaf || leaf == path || strcmp(leaf + 1, "model-manifest.json") != 0) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "fixed model-manifest.json basename required");
  *leaf = '\0';
  lms_context *ctx = lms_receiver(env, self); if (!ctx) return NULL;
  if (ctx->exclusive) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "archive model-store borrow cannot enroll a source package");
  if (ctx->package || ctx->package_handles == UINT_MAX) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "model store already holds an original package or exhausted its handle count");
  lms_package *package = calloc(1, sizeof(*package));
  if (!package) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "model package allocation failed");
  package->ctx = ctx; package->generation = ctx->generation; ++ctx->package_handles;
  package->root_fd = package->objects_fd = package->manifest_fd = package->source_fd = package->target_fd = -1;
  memcpy(package->path, path, strlen(path) + 1); ctx->package = package;
  package->root_fd = lms_walk(ctx, path); int wrapped = 0;
  if (package->root_fd < 0 || fstat(package->root_fd, &package->root) != 0 || !lms_package_directory(&package->root)) goto failed;
  package->objects_fd = openat(package->root_fd, "objects", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  package->manifest_fd = openat(package->root_fd, "model-manifest.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (package->objects_fd < 0 || package->manifest_fd < 0 ||
      fstat(package->objects_fd, &package->objects) != 0 || !lms_package_directory(&package->objects) ||
      fstat(package->manifest_fd, &package->manifest) != 0 || !lms_package_file(&package->manifest) ||
      package->manifest.st_size > 1048576 || lms_package_check(package) != 0 || lms_package_root_entries(package) != 0) goto failed;
  const napi_property_descriptor methods[] = {
    {"readManifest", NULL, lms_package_manifest, NULL, NULL, NULL, napi_default, NULL},
    {"captureInventory", NULL, lms_package_capture, NULL, NULL, NULL, napi_default, NULL},
    {"readSignature", NULL, lms_package_signature, NULL, NULL, NULL, napi_default, NULL},
    {"copyObjectStep", NULL, lms_package_copy, NULL, NULL, NULL, napi_default, NULL},
    {"finish", NULL, lms_package_finish, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, lms_package_close, NULL, NULL, NULL, napi_default, NULL}
  };
  if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &lms_package_tag) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, package, lms_package_finalize, NULL, NULL) != napi_ok) goto failed;
  wrapped = 1;
  if (napi_create_reference(env, result, 1, &package->reference) != napi_ok) goto failed;
  return result;
failed:
  if (!ctx->uncertain && lms_package_join(package) == 0) { if (!wrapped) { --ctx->package_handles; free(package); } }
  else lms_poison(ctx);
  return lms_error(env, ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_PACKAGE", "original package acquisition refused");
}

/* The retained source borrows the existing package custody slot and actual
 * close/finalizer. Its distinct tag exposes no import, target or pager methods. */
static int lms_object_source_current(lms_package *source) {
  lms_context *ctx = source->ctx; struct stat held, named;
  if (source->closed || source->source_fd < 0 || ctx->package != source ||
      source->generation != ctx->generation || lms_check(ctx) != 0 ||
      fstat(source->source_fd, &held) != 0 || !lms_object_file(&held) ||
      !source_metadata_same(&held, &source->source) ||
      fstatat(ctx->fd[LMS_OBJECTS], source->current_ref, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
      !source_metadata_same(&held, &named)) return -1;
  return 0;
}
static napi_value lms_object_source_read(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument, self, result; bool tagged = false; lms_package *source = NULL;
  if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
      napi_check_object_type_tag(env, self, &lms_object_source_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, self, (void **)&source) != napi_ok || !source || !lms_owner(source->ctx, env) ||
      source->completed < 0 || lms_object_source_current(source) != 0)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model object source is invalid or changed");
  if (source->offset == source->source.st_size) {
    if (!source->completed) {
      char digest[65]; publication_hash_hex(&source->hash, digest);
      if (strcmp(digest, source->current_ref) != 0) {
        source->completed = -1;
        return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model object source complete bytes differ");
      }
      source->completed = 1;
    }
    return napi_get_null(env, &result) == napi_ok ? result : NULL;
  }
  unsigned char bytes[65536]; off_t remaining = source->source.st_size - source->offset;
  size_t size = remaining < (off_t)sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
  if (cliq_fd_sqlite_read(source->source_fd, bytes, (int)size, (sqlite3_int64)source->offset, NULL) != SQLITE_OK ||
      lms_object_source_current(source) != 0 || napi_create_buffer_copy(env, size, bytes, NULL, &result) != napi_ok) {
    source->completed = -1;
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model object source did not provide its next complete chunk");
  }
  sha256_update(&source->hash, bytes, size); source->offset += (off_t)size; return result;
}
static napi_value lms_open_object_source(napi_env env, napi_callback_info info) {
  size_t count = 3; napi_value arguments[3], self, result; char reference[65]; double length;
  if (napi_get_cb_info(env, info, &count, arguments, &self, NULL) != napi_ok || count != 2 ||
      lms_ref(env, arguments[0], reference) != 0 || napi_get_value_double(env, arguments[1], &length) != napi_ok ||
      !(length >= 1 && length <= 268435456) || (off_t)length != length)
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model source requires an exact content reference and bounded size");
  lms_context *ctx = lms_receiver(env, self); if (!ctx) return NULL;
  if (ctx->exclusive || ctx->package || ctx->package_handles == UINT_MAX || atomic_load(&ctx->archive_held))
    return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model source custody is unavailable");
  lms_package *source = calloc(1, sizeof(*source));
  if (!source) return lms_error(env, "ERR_CLIQ_LOCAL_MODEL_STORE", "original model source allocation failed");
  source->ctx = ctx; source->generation = ctx->generation; ++ctx->package_handles; ctx->package = source;
  source->root_fd = source->objects_fd = source->manifest_fd = source->target_fd = -1;
  source->source_fd = openat(ctx->fd[LMS_OBJECTS], reference, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  memcpy(source->current_ref, reference, sizeof(reference)); sha256_init(&source->hash);
  int wrapped = 0, flags = source->source_fd < 0 ? -1 : fcntl(source->source_fd, F_GETFL);
  if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat(source->source_fd, &source->source) != 0 ||
      source->source.st_size != (off_t)length || lms_object_source_current(source) != 0) goto failed;
  const napi_property_descriptor methods[] = {
    {"readChunk", NULL, lms_object_source_read, NULL, NULL, NULL, napi_default, NULL},
    {"close", NULL, lms_package_close, NULL, NULL, NULL, napi_default, (void *)&lms_object_source_tag},
  };
  if (napi_create_object(env, &result) != napi_ok || napi_type_tag_object(env, result, &lms_object_source_tag) != napi_ok ||
      napi_define_properties(env, result, sizeof(methods) / sizeof(methods[0]), methods) != napi_ok ||
      napi_wrap(env, result, source, lms_package_finalize, NULL, NULL) != napi_ok) goto failed;
  wrapped = 1;
  if (napi_create_reference(env, result, 1, &source->reference) != napi_ok) goto failed;
  return result;
failed:
  if (!ctx->uncertain && lms_package_join(source) == 0) { if (!wrapped) { --ctx->package_handles; free(source); } }
  else lms_poison(ctx);
  return lms_error(env, ctx->uncertain ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_LOCAL_MODEL_STORE", "original model object source acquisition refused");
}

#include "local-model-store-archive.c"
