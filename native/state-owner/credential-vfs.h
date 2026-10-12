/* Private fixed credential VFS. Included by the signed image and its closed
 * conformance adapter; never linked to another SQLite implementation. */
#ifndef CLIQ_CREDENTIAL_VFS_H
#define CLIQ_CREDENTIAL_VFS_H
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <node_api.h>
#include <pthread.h>
#include <sqlite3ext.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <unistd.h>

enum credential_role {
  CREDENTIAL_ROOT, CREDENTIAL_CREDENTIALS, CREDENTIAL_LOCK, CREDENTIAL_MAIN,
  CREDENTIAL_WAL, CREDENTIAL_JOURNAL, CREDENTIAL_RUNTIME, CREDENTIAL_GLOBAL,
  CREDENTIAL_ROLE_COUNT
};
static const char *const credential_leaves[CREDENTIAL_ROLE_COUNT] = {
  NULL, "credentials", "authority.lock", "authority.sqlite", "authority.sqlite-wal",
  "authority.sqlite-journal", "runtime", "kernel-global.lock"
};
typedef struct credential_context {
  int descriptors[CREDENTIAL_ROLE_COUNT];
  struct stat identities[CREDENTIAL_ROLE_COUNT];
  int prepared, fenced, uncertain, retired;
  unsigned int live_files, leases[CREDENTIAL_ROLE_COUNT];
  struct {
    unsigned int reads, writes, truncates, syncs, locks, opens, closes,
                 fence_checks, journal_retirements;
  } counts;
  napi_env owner_env;
  pid_t owner_pid;
  uid_t owner_uid;
  gid_t owner_gid;
  pthread_t owner_thread;
  uint64_t generation;
  napi_ref owner_reference;
  char root_path[PATH_MAX], process_start[128];
} credential_context;

typedef struct {
  _Atomic(credential_context *) active;
  atomic_int acquiring, poisoned;
  napi_env owner_env;
  pid_t owner_pid;
  pthread_t owner_thread;
  uint64_t next_generation;
  int registered;
  sqlite3_vfs *original_default;
  sqlite3_vfs vfs;
} credential_manager;
static credential_manager credential_process;
static const char credential_main_name[] = "/cliq-credential-authority";

/* Adapter performs a locator-only nofollow walk; authority is always held.
 * This is a private compile-time seam, not a callable path/FD selector. */
static int credential_visible_root(credential_context *ctx, int capture);

static void credential_initialize_context(credential_context *ctx, napi_env env) {
  for (int role = 0; role < CREDENTIAL_ROLE_COUNT; ++role) ctx->descriptors[role] = -1;
  ctx->owner_env = env;
  ctx->owner_pid = getpid();
  ctx->owner_uid = geteuid();
  ctx->owner_gid = getegid();
  ctx->owner_thread = pthread_self();
}
static int credential_process_main_thread(void) {
#ifdef __linux__
  return syscall(SYS_gettid) == getpid();
#else
  return pthread_main_np();
#endif
}
static int credential_owner_context(const credential_context *ctx) {
  /* A rejected foreign SQLite caller has not acquired a file lease. The
   * main thread may retire and free its observed active pointer meanwhile;
   * reject independently of that pointer before reading any ctx field. */
  if (!credential_process_main_thread()) return 0;
  return ctx != NULL && ctx->owner_env != NULL && ctx->owner_pid == getpid() &&
         pthread_equal(ctx->owner_thread, pthread_self()) &&
         getuid() == ctx->owner_uid && geteuid() == ctx->owner_uid &&
         getgid() == ctx->owner_gid && getegid() == ctx->owner_gid;
}
static void credential_poison(credential_context *ctx) {
  if (ctx != NULL) ctx->uncertain = 1;
  atomic_store(&credential_process.poisoned, 1);
}
static int credential_checked_close(credential_context *ctx, int *descriptor) {
  int owned = *descriptor;
  *descriptor = -1;
  if (owned < 0 || close(owned) == 0) return 0;
  credential_poison(ctx);
  return -1;
}
static int credential_same_object(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}
static int credential_valid_directory(const struct stat *info) {
  return S_ISDIR(info->st_mode) && info->st_uid == geteuid() &&
         info->st_gid == getegid() && (info->st_mode & 07777) == 0700;
}
static int credential_valid_file(const struct stat *info) {
  return S_ISREG(info->st_mode) && info->st_uid == geteuid() &&
         info->st_gid == getegid() && (info->st_mode & 07777) == 0600 &&
         info->st_nlink == 1;
}
/* Walk every canonical ancestor without following symlinks. No data leaf is
 * opened here. On a close error, stop: consumed numbers may already be reused. */
static int credential_walk_path(credential_context *ctx, const char *path) {
  if (path == NULL || path[0] != '/' || path[1] == '\0') return -1;
  const char *cursor = path + 1;
  int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current < 0) return -1;
  while (*cursor != '\0') {
    const char *end = strchr(cursor, '/');
    size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
    char component[NAME_MAX + 1];
    if (length == 0 || length > NAME_MAX ||
        (length == 1 && cursor[0] == '.') ||
        (length == 2 && cursor[0] == '.' && cursor[1] == '.') ||
        (end != NULL && end[1] == '\0')) {
      credential_checked_close(ctx, &current);
      return -1;
    }
    memcpy(component, cursor, length); component[length] = '\0';
    int next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (credential_checked_close(ctx, &current) != 0) return -1;
    if (next < 0) return -1;
    current = next;
    cursor = end == NULL ? cursor + length : end + 1;
  }
  return current;
}
static int credential_check_bindings(credential_context *ctx) {
  struct stat held, named;
  int visible = -1;
  if (!credential_owner_context(ctx)) return -1;
  ctx->counts.fence_checks++;
  if (!ctx->prepared || ctx->retired || ctx->fenced || ctx->uncertain ||
      atomic_load(&credential_process.poisoned)) return -1;
  visible = credential_visible_root(ctx, 0);
  if (visible < 0) goto changed;
  for (int role = 0; role < CREDENTIAL_ROLE_COUNT; ++role) {
    if (role >= CREDENTIAL_RUNTIME && ctx->descriptors[role] < 0) continue;
    if (ctx->descriptors[role] < 0 || fstat(ctx->descriptors[role], &held) != 0 ||
        !credential_same_object(&held, &ctx->identities[role]) ||
        ((role <= CREDENTIAL_CREDENTIALS || role == CREDENTIAL_RUNTIME) ?
          !credential_valid_directory(&held) : !credential_valid_file(&held))) goto changed;
    if (role == CREDENTIAL_ROOT) continue;
    int parent = role == CREDENTIAL_CREDENTIALS || role == CREDENTIAL_RUNTIME ?
                 ctx->descriptors[CREDENTIAL_ROOT] : role == CREDENTIAL_GLOBAL ?
                 ctx->descriptors[CREDENTIAL_RUNTIME] : ctx->descriptors[CREDENTIAL_CREDENTIALS];
    if (fstatat(parent, credential_leaves[role], &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !credential_same_object(&held, &named) ||
        ((role == CREDENTIAL_CREDENTIALS || role == CREDENTIAL_RUNTIME) ?
          !credential_valid_directory(&named) : !credential_valid_file(&named))) goto changed;
  }
  return credential_checked_close(ctx, &visible);
changed:
  ctx->fenced = 1;
  atomic_store(&credential_process.poisoned, 1);
  if (!ctx->uncertain) credential_checked_close(ctx, &visible);
  return -1;
}
static int credential_hold_directory(credential_context *ctx, int parent,
                                     const char *name, enum credential_role role) {
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  ctx->descriptors[role] = fd;
  return fstat(fd, &ctx->identities[role]) == 0 &&
         credential_valid_directory(&ctx->identities[role]) ? 0 : -1;
}
static int credential_hold_file(credential_context *ctx, enum credential_role role) {
  int parent = role == CREDENTIAL_GLOBAL ? ctx->descriptors[CREDENTIAL_RUNTIME] :
               ctx->descriptors[CREDENTIAL_CREDENTIALS];
  int created = 1;
  int fd = openat(parent, credential_leaves[role],
                  O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0 && errno == EEXIST) {
    created = 0;
    fd = openat(parent, credential_leaves[role], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  }
  if (fd < 0) return -1;
  ctx->descriptors[role] = fd;
  if (fstat(fd, &ctx->identities[role]) != 0 || !credential_valid_file(&ctx->identities[role])) return -1;
  if (created && (fsync(fd) != 0 || fsync(parent) != 0)) return -1;
  if (created) ctx->counts.syncs += 2;
  return 0;
}
static int credential_guard_data_inode(credential_context *ctx, enum credential_role role) {
  /* Guard each original data inode against partial namespace replacement.
   * MAIN covers SQLite's pending/reserved/510 shared bytes. Sidecars use the
   * same fixed range solely for this closed protocol. POSIX F_SETLK belongs
   * to the process: never open/close a duplicate data FD. Pager lock levels
   * are independent; the guard is consumed only by physical FD retirement. */
  struct flock guard = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                        .l_start = 0x40000000, .l_len = 512};
  int result;
  do {
    ctx->counts.locks++;
    result = fcntl(ctx->descriptors[role], F_SETLK, &guard);
  } while (result < 0 && errno == EINTR);
  return result;
}
static int credential_consume_close(credential_context *ctx, enum credential_role role) {
  int fd = ctx->descriptors[role];
  ctx->descriptors[role] = -1;
  if (fd < 0) return 0;
  ctx->counts.closes++;
  if (close(fd) == 0) return 0;
  credential_poison(ctx);
  return -1;
}
static int credential_retire_resources(credential_context *ctx) {
  static const enum credential_role order[] = {
    CREDENTIAL_JOURNAL, CREDENTIAL_WAL, CREDENTIAL_CREDENTIALS, CREDENTIAL_ROOT,
    CREDENTIAL_MAIN, CREDENTIAL_LOCK, CREDENTIAL_RUNTIME, CREDENTIAL_GLOBAL
  };
  if (ctx->live_files != 0 || ctx->uncertain || ctx->fenced) return -1;
  for (size_t index = 0; index < sizeof(order) / sizeof(order[0]); ++index) {
    if (credential_consume_close(ctx, order[index]) != 0) return -1;
  }
  ctx->prepared = 0;
  ctx->retired = 1;
  return 0;
}
typedef struct {
  sqlite3_file base;
  credential_context *context;
  uint64_t generation;
  enum credential_role role;
  int alive, lock_level;
} credential_file;

static int credential_io_failure(credential_context *ctx, int result) { credential_poison(ctx); return result; }

static int credential_file_ready(credential_file *file) {
  credential_context *ctx = file->context;
  if (!credential_owner_context(ctx) || file->generation != ctx->generation) return 0;
  return file->alive && file->role >= CREDENTIAL_MAIN && file->role <= CREDENTIAL_JOURNAL &&
         ctx->leases[file->role] == 1 && credential_check_bindings(ctx) == 0;
}

static int credential_valid_range(sqlite3_int64 offset, int amount) {
  return amount >= 0 && offset >= 0 && offset <= INT64_MAX - amount &&
         (sqlite3_int64)(off_t)offset == offset &&
         (sqlite3_int64)(off_t)(offset + amount) == offset + amount;
}

static int credential_sync_descriptor(credential_context *ctx, int descriptor, int flags) {
  int result;
#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if ((flags & 0x0f) == SQLITE_SYNC_FULL) {
    do { ctx->counts.syncs++; result = fcntl(descriptor, F_FULLFSYNC); } while (result < 0 && errno == EINTR);
    return result == 0 ? SQLITE_OK : credential_io_failure(ctx, SQLITE_IOERR_FSYNC);
  }
#else
  (void)flags;
#endif
  do { ctx->counts.syncs++; result = fsync(descriptor); } while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : credential_io_failure(ctx, SQLITE_IOERR_FSYNC);
}

static int credential_truncate_descriptor(credential_context *ctx, int descriptor, sqlite3_int64 size) {
  int result;
  if (size < 0 || (sqlite3_int64)(off_t)size != size) return credential_io_failure(ctx, SQLITE_IOERR_TRUNCATE);
  do { ctx->counts.truncates++; result = ftruncate(descriptor, (off_t)size); } while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : credential_io_failure(ctx, SQLITE_IOERR_TRUNCATE);
}

/* SQLite leases never close physical descriptors or release the native gate. */
static int credential_io_close(sqlite3_file *base) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  if (ctx == NULL || !credential_owner_context(ctx)) return SQLITE_IOERR_CLOSE;
  if (!file->alive || file->role < CREDENTIAL_MAIN || file->role > CREDENTIAL_JOURNAL ||
      ctx->leases[file->role] != 1 || ctx->live_files == 0)
    return credential_io_failure(ctx, SQLITE_IOERR_CLOSE);
  ctx->leases[file->role] = 0;
  ctx->live_files--;
  file->alive = 0;
  file->lock_level = SQLITE_LOCK_NONE;
  file->context = NULL;
  base->pMethods = NULL;
  return SQLITE_OK;
}

static int credential_io_read(sqlite3_file *base, void *buffer, int amount, sqlite3_int64 offset) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  int consumed = 0;
  if (!credential_file_ready(file)) return SQLITE_IOERR_READ;
  if (!credential_valid_range(offset, amount)) return credential_io_failure(ctx, SQLITE_IOERR_READ);
  while (consumed < amount) {
    ssize_t result;
    do {
      ctx->counts.reads++;
      result = pread(ctx->descriptors[file->role], (char *)buffer + consumed,
                     (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result < 0) return credential_io_failure(ctx, SQLITE_IOERR_READ);
    if (result == 0) {
      memset((char *)buffer + consumed, 0, (size_t)(amount - consumed));
      return SQLITE_IOERR_SHORT_READ;
    }
    consumed += (int)result;
  }
  return SQLITE_OK;
}

static int credential_io_write(sqlite3_file *base, const void *buffer, int amount, sqlite3_int64 offset) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  int consumed = 0;
  if (!credential_file_ready(file)) return SQLITE_IOERR_WRITE;
  if (!credential_valid_range(offset, amount)) return credential_io_failure(ctx, SQLITE_IOERR_WRITE);
  while (consumed < amount) {
    ssize_t result;
    do {
      ctx->counts.writes++;
      result = pwrite(ctx->descriptors[file->role], (const char *)buffer + consumed,
                      (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return credential_io_failure(ctx, SQLITE_IOERR_WRITE);
    consumed += (int)result;
  }
  return SQLITE_OK;
}

static int credential_io_truncate(sqlite3_file *base, sqlite3_int64 size) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  return credential_file_ready(file) ? credential_truncate_descriptor(ctx, ctx->descriptors[file->role], size) : SQLITE_IOERR_TRUNCATE;
}

static int credential_io_sync(sqlite3_file *base, int flags) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  return credential_file_ready(file) ? credential_sync_descriptor(ctx, ctx->descriptors[file->role], flags) : SQLITE_IOERR_FSYNC;
}

static int credential_io_size(sqlite3_file *base, sqlite3_int64 *size) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  struct stat info;
  if (!credential_file_ready(file)) return SQLITE_IOERR_FSTAT;
  if (fstat(ctx->descriptors[file->role], &info) != 0 || info.st_size < 0) return credential_io_failure(ctx, SQLITE_IOERR_FSTAT);
  *size = (sqlite3_int64)info.st_size;
  return SQLITE_OK;
}

static int credential_io_lock(sqlite3_file *base, int level) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  if (!credential_file_ready(file)) return SQLITE_IOERR_LOCK;
  if (file->role != CREDENTIAL_MAIN || level < SQLITE_LOCK_SHARED || level > SQLITE_LOCK_EXCLUSIVE)
    return credential_io_failure(ctx, SQLITE_IOERR_LOCK);
  /* The physical inode guard remains exclusive even when the pager changes
   * its virtual lock level, including hot-journal detection and recovery. */
  if (level > file->lock_level) file->lock_level = level;
  ctx->counts.locks++;
  return SQLITE_OK;
}

static int credential_io_unlock(sqlite3_file *base, int level) {
  credential_file *file = (credential_file *)base;
  credential_context *ctx = file->context;
  if (!credential_file_ready(file)) return SQLITE_IOERR_UNLOCK;
  if (file->role != CREDENTIAL_MAIN || (level != SQLITE_LOCK_NONE && level != SQLITE_LOCK_SHARED))
    return credential_io_failure(ctx, SQLITE_IOERR_UNLOCK);
  if (level < file->lock_level) file->lock_level = level;
  return SQLITE_OK;
}

static int credential_io_reserved(sqlite3_file *base, int *result) {
  credential_file *file = (credential_file *)base;
  if (!credential_file_ready(file)) return SQLITE_IOERR_CHECKRESERVEDLOCK;
  *result = file->lock_level >= SQLITE_LOCK_RESERVED;
  return SQLITE_OK;
}

static int credential_io_control(sqlite3_file *base, int operation, void *argument) {
  credential_file *file = (credential_file *)base;
  if (!credential_file_ready(file)) return SQLITE_IOERR;
  switch (operation) {
    case SQLITE_FCNTL_PERSIST_WAL:
      if (*(int *)argument == 0) return SQLITE_ERROR;
      *(int *)argument = 1;
      return SQLITE_OK;
    case SQLITE_FCNTL_LOCKSTATE:
      *(int *)argument = file->lock_level;
      return SQLITE_OK;
    case SQLITE_FCNTL_HAS_MOVED:
      *(int *)argument = 0;
      return SQLITE_OK;
    case SQLITE_FCNTL_MMAP_SIZE:
      *(sqlite3_int64 *)argument = 0;
      return SQLITE_OK;
    case SQLITE_FCNTL_PRAGMA: {
      const char *const *pragma = (const char *const *)argument;
      if (pragma[1] != NULL && pragma[2] != NULL &&
          sqlite3_stricmp(pragma[1], "locking_mode") == 0 &&
          sqlite3_stricmp(pragma[2], "exclusive") != 0) return SQLITE_ERROR;
      return SQLITE_NOTFOUND;
    }
    default:
      return SQLITE_NOTFOUND;
  }
}

static int credential_io_sector_size(sqlite3_file *base) { (void)base; return 4096; }
static int credential_io_characteristics(sqlite3_file *base) { (void)base; return 0; }

/* Exclusive-mode WAL uses a heap index. There are deliberately no SHM,
 * mmap, Unix-file wrappers, temp files or second SQLite implementation. */
static const sqlite3_io_methods credential_io_methods = {
  .iVersion = 1, .xClose = credential_io_close, .xRead = credential_io_read, .xWrite = credential_io_write,
  .xTruncate = credential_io_truncate, .xSync = credential_io_sync, .xFileSize = credential_io_size,
  .xLock = credential_io_lock, .xUnlock = credential_io_unlock, .xCheckReservedLock = credential_io_reserved,
  .xFileControl = credential_io_control, .xSectorSize = credential_io_sector_size,
  .xDeviceCharacteristics = credential_io_characteristics,
};

static enum credential_role credential_filename_role(const char *name) {
  if (name == NULL) return CREDENTIAL_ROLE_COUNT;
  if (strcmp(name, credential_main_name) == 0) return CREDENTIAL_MAIN;
  if (strcmp(name, "/cliq-credential-authority-wal") == 0) return CREDENTIAL_WAL;
  if (strcmp(name, "/cliq-credential-authority-journal") == 0) return CREDENTIAL_JOURNAL;
  return CREDENTIAL_ROLE_COUNT;
}

static int credential_vfs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *base,
                    int flags, int *out_flags) {
  credential_context *ctx = credential_process.active;
  enum credential_role role = credential_filename_role(name);
  int expected = role == CREDENTIAL_MAIN ? SQLITE_OPEN_MAIN_DB : role == CREDENTIAL_WAL ? SQLITE_OPEN_WAL : SQLITE_OPEN_MAIN_JOURNAL;
  int types = flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_WAL |
                       SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_TRANSIENT_DB |
                       SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL);
  (void)vfs;
  base->pMethods = NULL;
  if (role == CREDENTIAL_ROLE_COUNT || types != expected || (flags & SQLITE_OPEN_READWRITE) == 0 ||
      (flags & (SQLITE_OPEN_READONLY | SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_MEMORY)) != 0)
    return SQLITE_CANTOPEN;
  if (ctx == NULL || credential_check_bindings(ctx) != 0) return SQLITE_CANTOPEN;
  if (ctx->leases[role] != 0) return SQLITE_BUSY;
  credential_file *file = (credential_file *)base;
  file->context = ctx;
  file->generation = ctx->generation;
  file->role = role;
  file->alive = 1;
  file->lock_level = SQLITE_LOCK_NONE;
  ctx->leases[role] = 1;
  ctx->live_files++;
  ctx->counts.opens++;
  if (out_flags != NULL) *out_flags = flags;
  base->pMethods = &credential_io_methods;
  return SQLITE_OK;
}

static int credential_vfs_delete(sqlite3_vfs *vfs, const char *name, int sync_directory) {
  credential_context *ctx = credential_process.active;
  (void)vfs;
  if (ctx == NULL || !credential_owner_context(ctx)) return SQLITE_IOERR_DELETE;
  if (credential_filename_role(name) != CREDENTIAL_JOURNAL) return credential_io_failure(ctx, SQLITE_IOERR_DELETE);
  if (ctx == NULL || credential_check_bindings(ctx) != 0) return SQLITE_IOERR_DELETE;
  if (credential_truncate_descriptor(ctx, ctx->descriptors[CREDENTIAL_JOURNAL], 0) != SQLITE_OK ||
      credential_sync_descriptor(ctx, ctx->descriptors[CREDENTIAL_JOURNAL], SQLITE_SYNC_FULL) != SQLITE_OK ||
      (sync_directory && credential_sync_descriptor(ctx, ctx->descriptors[CREDENTIAL_CREDENTIALS], SQLITE_SYNC_NORMAL) != SQLITE_OK))
    return SQLITE_IOERR_DELETE;
  ctx->counts.journal_retirements++;
  return SQLITE_OK;
}

static int credential_vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
  credential_context *ctx = credential_process.active;
  enum credential_role role = credential_filename_role(name);
  struct stat info;
  (void)vfs;
  *result = 0;
  if (role == CREDENTIAL_ROLE_COUNT || (flags != SQLITE_ACCESS_EXISTS && flags != SQLITE_ACCESS_READ &&
                            flags != SQLITE_ACCESS_READWRITE)) return SQLITE_IOERR_ACCESS;
  if (ctx == NULL || credential_check_bindings(ctx) != 0) return SQLITE_IOERR_ACCESS;
  if (fstat(ctx->descriptors[role], &info) != 0) return credential_io_failure(ctx, SQLITE_IOERR_ACCESS);
  *result = flags == SQLITE_ACCESS_EXISTS && role != CREDENTIAL_MAIN ? info.st_size != 0 : 1;
  return SQLITE_OK;
}

static int credential_vfs_full_path(sqlite3_vfs *vfs, const char *name, int size, char *output) {
  (void)vfs;
  if (name == NULL || (strcmp(name, "cliq-credential-authority") != 0 && strcmp(name, credential_main_name) != 0) ||
      size <= 0 || (size_t)size < sizeof(credential_main_name)) return SQLITE_CANTOPEN;
  memcpy(output, credential_main_name, sizeof(credential_main_name));
  return SQLITE_OK;
}

/* Only non-file OS services delegate, always with the original VFS pointer.
 * Private VFS cannot become a generic dlopen or OS syscall selector. */
static void *credential_vfs_dl_open(sqlite3_vfs *vfs, const char *name) {
  (void)vfs; (void)name; return NULL;
}
static void credential_vfs_dl_error(sqlite3_vfs *vfs, int size, char *message) {
  (void)vfs;
  if (size > 0) snprintf(message, (size_t)size, "%s", "credential VFS cannot load extensions");
}
static void (*credential_vfs_dl_sym(sqlite3_vfs *vfs, void *image, const char *name))(void) {
  (void)vfs; (void)image; (void)name; return NULL;
}
static void credential_vfs_dl_close(sqlite3_vfs *vfs, void *image) { (void)vfs; (void)image; }
static int credential_vfs_random(sqlite3_vfs *vfs, int amount, char *output) {
  (void)vfs;
  sqlite3_vfs *base = credential_process.original_default;
  return base->xRandomness(base, amount, output);
}
static int credential_vfs_sleep(sqlite3_vfs *vfs, int micros) {
  (void)vfs;
  sqlite3_vfs *base = credential_process.original_default;
  return base->xSleep(base, micros);
}
static int credential_vfs_time(sqlite3_vfs *vfs, double *value) {
  (void)vfs;
  sqlite3_vfs *base = credential_process.original_default;
  return base->xCurrentTime(base, value);
}
static int credential_vfs_time64(sqlite3_vfs *vfs, sqlite3_int64 *value) {
  (void)vfs;
  sqlite3_vfs *base = credential_process.original_default;
  if (base->iVersion >= 2 && base->xCurrentTimeInt64 != NULL) return base->xCurrentTimeInt64(base, value);
  double time;
  int result = base->xCurrentTime(base, &time);
  if (result == SQLITE_OK) *value = (sqlite3_int64)(time * 86400000.0);
  return result;
}
static int credential_register_vfs(const char *name, const sqlite3_api_routines *api) {
  credential_context *ctx = atomic_load(&credential_process.active);
  if (!credential_owner_context(ctx) || credential_check_bindings(ctx) != 0 || api == NULL ||
      api->sourceid == NULL || api->stricmp == NULL || api->vfs_find == NULL ||
      api->vfs_register == NULL || (sqlite3_api != NULL && sqlite3_api != api)) return SQLITE_ERROR;
  SQLITE_EXTENSION_INIT2(api);
  if (credential_process.registered)
    return sqlite3_vfs_find(name) == &credential_process.vfs ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
  sqlite3_vfs *base = sqlite3_vfs_find(NULL);
  if (base == NULL || base->xRandomness == NULL || base->xSleep == NULL ||
      base->xCurrentTime == NULL || sqlite3_vfs_find(name) != NULL) return SQLITE_ERROR;
  credential_process.original_default = base;
  credential_process.vfs = (sqlite3_vfs) {
    .iVersion = 2, .szOsFile = sizeof(credential_file), .mxPathname = 128,
    .zName = name, .pAppData = &credential_process, .xOpen = credential_vfs_open,
    .xDelete = credential_vfs_delete, .xAccess = credential_vfs_access,
    .xFullPathname = credential_vfs_full_path, .xDlOpen = credential_vfs_dl_open,
    .xDlError = credential_vfs_dl_error, .xDlSym = credential_vfs_dl_sym,
    .xDlClose = credential_vfs_dl_close, .xRandomness = credential_vfs_random,
    .xSleep = credential_vfs_sleep, .xCurrentTime = credential_vfs_time,
    .xCurrentTimeInt64 = credential_vfs_time64
  };
  if (sqlite3_vfs_register(&credential_process.vfs, 0) != SQLITE_OK) return SQLITE_ERROR;
  credential_process.registered = 1;
  return SQLITE_OK_LOAD_PERMANENTLY;
}
#endif
