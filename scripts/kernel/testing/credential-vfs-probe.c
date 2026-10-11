/* Test-only fixed credential I/O experiment, not credential authority.
 * All SQLite calls come from Node's supplied extension API table. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <node_api.h>
#include <pthread.h>
#include <sqlite3ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

SQLITE_EXTENSION_INIT1

#define PROBE_EXPORT __attribute__((visibility("default")))
enum role { ROOT, CREDENTIALS, LOCK, MAIN, WAL, JOURNAL, ROLE_COUNT };
static const char *const roles[] = {"root", "credentials", "lock", "main", "wal", "journal"};
static const char *const leaves[] = {NULL, "credentials", "authority.lock", "authority.sqlite",
                                   "authority.sqlite-wal", "authority.sqlite-journal"};
static int descriptors[ROLE_COUNT] = {-1, -1, -1, -1, -1, -1};
static struct stat identities[ROLE_COUNT];
static int prepared = 0, registered = 0, fenced = 0, uncertain = 0, retired = 0;
static unsigned int live_files = 0;
static struct {
  unsigned int reads, writes, truncates, syncs, locks, opens, closes, fence_checks,
               journal_retirements;
} counts;
static sqlite3_vfs *original_default = NULL;
static sqlite3_vfs private_vfs;
static const char vfs_name[] = "cliq-credential-vfs-probe-v1";
static const char main_name[] = "/cliq-credential-authority";
static char home_path[PATH_MAX];
static struct stat home_identity, probe_identity;
static napi_env owner_env = NULL;
static pid_t owner_pid;
static pthread_t owner_thread;
static unsigned int leases[ROLE_COUNT];

static int owner_context(void) {
  return owner_env != NULL && owner_pid == getpid() && pthread_equal(owner_thread, pthread_self());
}

static int checked_close(int *descriptor) {
  int fd = *descriptor;
  *descriptor = -1;
  if (fd < 0 || close(fd) == 0) return 0;
  uncertain = 1;
  return -1;
}

static int same_object(const struct stat *left, const struct stat *right) {
  return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int valid_directory(const struct stat *info) {
  return S_ISDIR(info->st_mode) && info->st_uid == geteuid() &&
         info->st_gid == getegid() && (info->st_mode & 07777) == 0700;
}

static int valid_file(const struct stat *info) {
  return S_ISREG(info->st_mode) && info->st_uid == geteuid() &&
         info->st_gid == getegid() && (info->st_mode & 07777) == 0600 &&
         info->st_nlink == 1;
}

/* Traverse every HOME ancestor without following symlinks. Only directory
 * descriptors are opened here; data leaves are never reopened for I/O. */
static int walk_home(void) {
  const char *cursor = home_path + 1;
  int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current < 0) return -1;
  while (*cursor != '\0') {
    const char *end = strchr(cursor, '/');
    size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
    char component[NAME_MAX + 1];
    if (length == 0 || length > NAME_MAX ||
        (length == 1 && cursor[0] == '.') ||
        (length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
      checked_close(&current);
      return -1;
    }
    memcpy(component, cursor, length);
    component[length] = '\0';
    int next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (checked_close(&current) != 0) { checked_close(&next); return -1; }
    if (next < 0) return -1;
    current = next;
    cursor = end == NULL ? cursor + length : end + 1;
  }
  return current;
}

static int visible_root(int capture) {
  int home = walk_home(), probe = -1, root = -1;
  struct stat info;
  if (home < 0) return -1;
  if (fstat(home, &info) != 0 || !valid_directory(&info) ||
      (!capture && !same_object(&info, &home_identity))) goto failed;
  if (capture) home_identity = info;
  probe = openat(home, "probe", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (probe < 0 || fstat(probe, &info) != 0 || !valid_directory(&info) ||
      (!capture && !same_object(&info, &probe_identity))) goto failed;
  if (capture) probe_identity = info;
  root = openat(probe, "credential-vfs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (root < 0 || fstat(root, &info) != 0 || !valid_directory(&info) ||
      (!capture && !same_object(&info, &identities[ROOT]))) goto failed;
  if (capture) identities[ROOT] = info;
  if (checked_close(&probe) != 0 || checked_close(&home) != 0) goto failed;
  return root;
failed:
  checked_close(&root);
  checked_close(&probe);
  checked_close(&home);
  return -1;
}

static int check_bindings(void) {
  int visible = -1;
  struct stat held, named;
  if (!owner_context()) return -1;
  counts.fence_checks++;
  if (!prepared || retired || fenced || uncertain) return -1;
  visible = visible_root(0);
  if (visible < 0) goto changed;
  for (int role = ROOT; role < ROLE_COUNT; ++role) {
    if (descriptors[role] < 0 || fstat(descriptors[role], &held) != 0 ||
        !same_object(&held, &identities[role]) ||
        (role <= CREDENTIALS ? !valid_directory(&held) : !valid_file(&held))) goto changed;
    if (role == ROOT) continue;
    int parent = role == CREDENTIALS ? descriptors[ROOT] : descriptors[CREDENTIALS];
    if (fstatat(parent, leaves[role], &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(&held, &named) ||
        (role == CREDENTIALS ? !valid_directory(&named) : !valid_file(&named))) goto changed;
  }
  if (checked_close(&visible) != 0) return -1;
  return 0;
changed:
  fenced = 1;
  checked_close(&visible);
  return -1;
}

static int hold_directory_at(int parent, const char *name, enum role role) {
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  descriptors[role] = fd;
  return fstat(fd, &identities[role]) == 0 && valid_directory(&identities[role]) ? 0 : -1;
}

static int hold_file(enum role role) {
  int created = 1;
  int fd = openat(descriptors[CREDENTIALS], leaves[role],
                  O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0 && errno == EEXIST) {
    created = 0;
    fd = openat(descriptors[CREDENTIALS], leaves[role], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  }
  if (fd < 0) return -1;
  descriptors[role] = fd;
  if (fstat(fd, &identities[role]) != 0 || !valid_file(&identities[role])) return -1;
  if (created && (fsync(fd) != 0 || fsync(descriptors[CREDENTIALS]) != 0)) return -1;
  if (created) counts.syncs += 2;
  return 0;
}

static int guard_data_inode(enum role role) {
  /* Guard each original data inode so replacing authority.lock or another
   * data leaf cannot admit a second helper sharing even one held inode.
   * MAIN covers SQLite's pending, reserved and 510 shared bytes; sidecars
   * use the same fixed range only as this closed helper's private protocol.
   * F_SETLK is nonblocking and process-owned: never open/close a duplicate
   * data FD, since any such close would drop that inode's guard. Pager lock
   * levels remain separate; each physical close consumes its own guard. */
  struct flock guard = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                        .l_start = 0x40000000, .l_len = 512};
  int result;
  do {
    counts.locks++;
    result = fcntl(descriptors[role], F_SETLK, &guard);
  } while (result < 0 && errno == EINTR);
  return result;
}

static int prepare_fixed(void) {
  const char *home = getenv("HOME");
  int created;
  if (!owner_context() || home == NULL || home[0] != '/' || strlen(home) >= sizeof(home_path) ||
      getuid() != geteuid() || getgid() != getegid()) return -1;
  memcpy(home_path, home, strlen(home) + 1);
  descriptors[ROOT] = visible_root(1);
  if (descriptors[ROOT] < 0) return -1;
  created = mkdirat(descriptors[ROOT], "credentials", 0700) == 0;
  if (!created && errno != EEXIST) return -1;
  if (hold_directory_at(descriptors[ROOT], leaves[CREDENTIALS], CREDENTIALS) != 0) return -1;
  if (created && fsync(descriptors[ROOT]) != 0) return -1;
  if (created) counts.syncs++;
  if (hold_file(LOCK) != 0 || flock(descriptors[LOCK], LOCK_EX | LOCK_NB) != 0) return -1;
  counts.locks++;
  if (hold_file(MAIN) != 0 || guard_data_inode(MAIN) != 0 ||
      hold_file(WAL) != 0 || guard_data_inode(WAL) != 0 ||
      hold_file(JOURNAL) != 0 || guard_data_inode(JOURNAL) != 0) return -1;
  if (identities[MAIN].st_size == 0 && identities[WAL].st_size != 0) return -1;
  prepared = 1;
  return check_bindings();
}

typedef struct {
  sqlite3_file base;
  enum role role;
  int alive;
  int lock_level;
} probe_file;

static int io_failure(int result) { uncertain = 1; return result; }

static int file_ready(probe_file *file) {
  return file->alive && file->role >= MAIN && file->role <= JOURNAL &&
         leases[file->role] == 1 && check_bindings() == 0;
}

static int valid_range(sqlite3_int64 offset, int amount) {
  return amount >= 0 && offset >= 0 && offset <= INT64_MAX - amount &&
         (sqlite3_int64)(off_t)offset == offset &&
         (sqlite3_int64)(off_t)(offset + amount) == offset + amount;
}

static int sync_descriptor(int descriptor, int flags) {
  int result;
#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if ((flags & 0x0f) == SQLITE_SYNC_FULL) {
    do { counts.syncs++; result = fcntl(descriptor, F_FULLFSYNC); } while (result < 0 && errno == EINTR);
    return result == 0 ? SQLITE_OK : io_failure(SQLITE_IOERR_FSYNC);
  }
#else
  (void)flags;
#endif
  do { counts.syncs++; result = fsync(descriptor); } while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : io_failure(SQLITE_IOERR_FSYNC);
}

static int truncate_descriptor(int descriptor, sqlite3_int64 size) {
  int result;
  if (size < 0 || (sqlite3_int64)(off_t)size != size) return io_failure(SQLITE_IOERR_TRUNCATE);
  do { counts.truncates++; result = ftruncate(descriptor, (off_t)size); } while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : io_failure(SQLITE_IOERR_TRUNCATE);
}

/* SQLite leases never close physical descriptors or release the native gate. */
static int io_close(sqlite3_file *base) {
  probe_file *file = (probe_file *)base;
  if (!owner_context()) return SQLITE_IOERR_CLOSE;
  if (!file->alive || file->role < MAIN || file->role > JOURNAL ||
      leases[file->role] != 1 || live_files == 0)
    return io_failure(SQLITE_IOERR_CLOSE);
  leases[file->role] = 0;
  live_files--;
  file->alive = 0;
  file->lock_level = SQLITE_LOCK_NONE;
  base->pMethods = NULL;
  return SQLITE_OK;
}

static int io_read(sqlite3_file *base, void *buffer, int amount, sqlite3_int64 offset) {
  probe_file *file = (probe_file *)base;
  int consumed = 0;
  if (!file_ready(file)) return SQLITE_IOERR_READ;
  if (!valid_range(offset, amount)) return io_failure(SQLITE_IOERR_READ);
  while (consumed < amount) {
    ssize_t result;
    do {
      counts.reads++;
      result = pread(descriptors[file->role], (char *)buffer + consumed,
                     (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result < 0) return io_failure(SQLITE_IOERR_READ);
    if (result == 0) {
      memset((char *)buffer + consumed, 0, (size_t)(amount - consumed));
      return SQLITE_IOERR_SHORT_READ;
    }
    consumed += (int)result;
  }
  return SQLITE_OK;
}

static int io_write(sqlite3_file *base, const void *buffer, int amount, sqlite3_int64 offset) {
  probe_file *file = (probe_file *)base;
  int consumed = 0;
  if (!file_ready(file)) return SQLITE_IOERR_WRITE;
  if (!valid_range(offset, amount)) return io_failure(SQLITE_IOERR_WRITE);
  while (consumed < amount) {
    ssize_t result;
    do {
      counts.writes++;
      result = pwrite(descriptors[file->role], (const char *)buffer + consumed,
                      (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return io_failure(SQLITE_IOERR_WRITE);
    consumed += (int)result;
  }
  return SQLITE_OK;
}

static int io_truncate(sqlite3_file *base, sqlite3_int64 size) {
  probe_file *file = (probe_file *)base;
  return file_ready(file) ? truncate_descriptor(descriptors[file->role], size) : SQLITE_IOERR_TRUNCATE;
}

static int io_sync(sqlite3_file *base, int flags) {
  probe_file *file = (probe_file *)base;
  return file_ready(file) ? sync_descriptor(descriptors[file->role], flags) : SQLITE_IOERR_FSYNC;
}

static int io_size(sqlite3_file *base, sqlite3_int64 *size) {
  probe_file *file = (probe_file *)base;
  struct stat info;
  if (!file_ready(file)) return SQLITE_IOERR_FSTAT;
  if (fstat(descriptors[file->role], &info) != 0 || info.st_size < 0) return io_failure(SQLITE_IOERR_FSTAT);
  *size = (sqlite3_int64)info.st_size;
  return SQLITE_OK;
}

static int io_lock(sqlite3_file *base, int level) {
  probe_file *file = (probe_file *)base;
  if (!file_ready(file)) return SQLITE_IOERR_LOCK;
  if (file->role != MAIN || level < SQLITE_LOCK_SHARED || level > SQLITE_LOCK_EXCLUSIVE)
    return io_failure(SQLITE_IOERR_LOCK);
  /* The physical inode guard remains exclusive even when the pager changes
   * its virtual lock level, including hot-journal detection and recovery. */
  if (level > file->lock_level) file->lock_level = level;
  counts.locks++;
  return SQLITE_OK;
}

static int io_unlock(sqlite3_file *base, int level) {
  probe_file *file = (probe_file *)base;
  if (!file_ready(file)) return SQLITE_IOERR_UNLOCK;
  if (file->role != MAIN || (level != SQLITE_LOCK_NONE && level != SQLITE_LOCK_SHARED))
    return io_failure(SQLITE_IOERR_UNLOCK);
  if (level < file->lock_level) file->lock_level = level;
  return SQLITE_OK;
}

static int io_reserved(sqlite3_file *base, int *result) {
  probe_file *file = (probe_file *)base;
  if (!file_ready(file)) return SQLITE_IOERR_CHECKRESERVEDLOCK;
  *result = file->lock_level >= SQLITE_LOCK_RESERVED;
  return SQLITE_OK;
}

static int io_control(sqlite3_file *base, int operation, void *argument) {
  probe_file *file = (probe_file *)base;
  if (!file_ready(file)) return SQLITE_IOERR;
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

static int io_sector_size(sqlite3_file *base) { (void)base; return 4096; }
static int io_characteristics(sqlite3_file *base) { (void)base; return 0; }

/* Exclusive-mode WAL uses a heap index. There are deliberately no SHM,
 * mmap, Unix-file wrappers, temp files or second SQLite implementation. */
static const sqlite3_io_methods io_methods = {
  .iVersion = 1, .xClose = io_close, .xRead = io_read, .xWrite = io_write,
  .xTruncate = io_truncate, .xSync = io_sync, .xFileSize = io_size,
  .xLock = io_lock, .xUnlock = io_unlock, .xCheckReservedLock = io_reserved,
  .xFileControl = io_control, .xSectorSize = io_sector_size,
  .xDeviceCharacteristics = io_characteristics,
};

static enum role filename_role(const char *name) {
  if (name == NULL) return ROLE_COUNT;
  if (strcmp(name, main_name) == 0) return MAIN;
  if (strcmp(name, "/cliq-credential-authority-wal") == 0) return WAL;
  if (strcmp(name, "/cliq-credential-authority-journal") == 0) return JOURNAL;
  return ROLE_COUNT;
}

static int vfs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *base,
                    int flags, int *out_flags) {
  enum role role = filename_role(name);
  int expected = role == MAIN ? SQLITE_OPEN_MAIN_DB : role == WAL ? SQLITE_OPEN_WAL : SQLITE_OPEN_MAIN_JOURNAL;
  int types = flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_WAL |
                       SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_TRANSIENT_DB |
                       SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL);
  (void)vfs;
  base->pMethods = NULL;
  if (role == ROLE_COUNT || types != expected || (flags & SQLITE_OPEN_READWRITE) == 0 ||
      (flags & (SQLITE_OPEN_READONLY | SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_MEMORY)) != 0)
    return SQLITE_CANTOPEN;
  if (check_bindings() != 0) return SQLITE_CANTOPEN;
  if (leases[role] != 0) return SQLITE_BUSY;
  probe_file *file = (probe_file *)base;
  file->role = role;
  file->alive = 1;
  file->lock_level = SQLITE_LOCK_NONE;
  leases[role] = 1;
  live_files++;
  counts.opens++;
  if (out_flags != NULL) *out_flags = flags;
  base->pMethods = &io_methods;
  return SQLITE_OK;
}

static int vfs_delete(sqlite3_vfs *vfs, const char *name, int sync_directory) {
  (void)vfs;
  if (!owner_context()) return SQLITE_IOERR_DELETE;
  if (filename_role(name) != JOURNAL) return io_failure(SQLITE_IOERR_DELETE);
  if (check_bindings() != 0) return SQLITE_IOERR_DELETE;
  if (truncate_descriptor(descriptors[JOURNAL], 0) != SQLITE_OK ||
      sync_descriptor(descriptors[JOURNAL], SQLITE_SYNC_FULL) != SQLITE_OK ||
      (sync_directory && sync_descriptor(descriptors[CREDENTIALS], SQLITE_SYNC_NORMAL) != SQLITE_OK))
    return SQLITE_IOERR_DELETE;
  counts.journal_retirements++;
  return SQLITE_OK;
}

static int vfs_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
  enum role role = filename_role(name);
  struct stat info;
  (void)vfs;
  *result = 0;
  if (role == ROLE_COUNT || (flags != SQLITE_ACCESS_EXISTS && flags != SQLITE_ACCESS_READ &&
                            flags != SQLITE_ACCESS_READWRITE)) return SQLITE_IOERR_ACCESS;
  if (check_bindings() != 0) return SQLITE_IOERR_ACCESS;
  if (fstat(descriptors[role], &info) != 0) return io_failure(SQLITE_IOERR_ACCESS);
  *result = flags == SQLITE_ACCESS_EXISTS && role != MAIN ? info.st_size != 0 : 1;
  return SQLITE_OK;
}

static int vfs_full_path(sqlite3_vfs *vfs, const char *name, int size, char *output) {
  (void)vfs;
  if (name == NULL || (strcmp(name, "cliq-credential-authority") != 0 && strcmp(name, main_name) != 0) ||
      size <= 0 || (size_t)size < sizeof(main_name)) return SQLITE_CANTOPEN;
  memcpy(output, main_name, sizeof(main_name));
  return SQLITE_OK;
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

static napi_status descriptor_property(napi_env env, napi_value object, enum role role) {
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
    if (descriptor_property(env, files, (enum role)role) != napi_ok) return NULL;
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

static int consume_close(enum role role) {
  int fd = descriptors[role];
  descriptors[role] = -1;
  if (fd < 0) return 0;
  counts.closes++;
  if (close(fd) == 0) return 0;
  uncertain = 1;
  return -1;
}

static napi_value retire(napi_env env, napi_callback_info info) {
  static const enum role order[] = {JOURNAL, WAL, CREDENTIALS, ROOT, MAIN, LOCK};
  if (!no_arguments(env, info)) return failure(env, "retire takes no arguments");
  if (env != owner_env || !owner_context()) return failure(env, "probe belongs to another context");
  if (live_files != 0) return failure(env, "live SQLite file leases cannot be retired");
  if (uncertain || fenced) return failure(env, "native resources cannot be retired");
  if (prepared && check_bindings() != 0) return failure(env, "native bindings changed; resources retained");
  for (size_t index = 0; index < sizeof(order) / sizeof(order[0]); ++index) {
    if (consume_close(order[index]) != 0) return failure(env, "native close is uncertain; later resources retained");
  }
  retired = 1;
  prepared = 0;
  return snapshot(env);
}

/* The image and its static VFS callbacks intentionally remain mapped until
 * process exit. retire() retires held resources, not executable code. */
PROBE_EXPORT int sqlite3_cliqcredentialvfsprobe_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  (void)database;
  (void)error;
  if (!owner_context() || !prepared || fenced || uncertain || retired || api == NULL ||
      api->sourceid == NULL || api->stricmp == NULL || api->vfs_find == NULL ||
      api->vfs_register == NULL || (sqlite3_api != NULL && sqlite3_api != api)) return SQLITE_ERROR;
  SQLITE_EXTENSION_INIT2(api);
  if (registered) return sqlite3_vfs_find(vfs_name) == &private_vfs ? SQLITE_OK_LOAD_PERMANENTLY : SQLITE_ERROR;
  original_default = sqlite3_vfs_find(NULL);
  if (original_default == NULL || sqlite3_vfs_find(vfs_name) != NULL) return SQLITE_ERROR;
  private_vfs = *original_default;
  private_vfs.pNext = NULL;
  private_vfs.zName = vfs_name;
  private_vfs.szOsFile = sizeof(probe_file);
  private_vfs.xOpen = vfs_open;
  private_vfs.xDelete = vfs_delete;
  private_vfs.xAccess = vfs_access;
  private_vfs.xFullPathname = vfs_full_path;
  if (sqlite3_vfs_register(&private_vfs, 0) != SQLITE_OK) return SQLITE_ERROR;
  registered = 1;
  return SQLITE_OK_LOAD_PERMANENTLY;
}

static napi_value initialize_napi(napi_env env, napi_value exports) {
  if (owner_env != NULL && (owner_env != env || !owner_context()))
    return failure(env, "probe belongs to another context");
  if (owner_env == NULL) {
    owner_env = env;
    owner_pid = getpid();
    owner_thread = pthread_self();
  }
  napi_property_descriptor methods[] = {
    {"prepare", NULL, prepare, NULL, NULL, NULL, napi_default, NULL},
    {"observe", NULL, observe, NULL, NULL, NULL, napi_default, NULL},
    {"retire", NULL, retire, NULL, NULL, NULL, napi_default, NULL},
  };
  return napi_define_properties(env, exports, sizeof(methods) / sizeof(methods[0]), methods) == napi_ok ? exports : NULL;
}

NAPI_MODULE(cliq_credential_vfs_probe, initialize_napi)
