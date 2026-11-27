/* Mechanism only. The caller must first assert its own original family,
 * descriptor lease, inode guard, process and gate. These routines neither
 * acquire authority nor close, cache, duplicate or lend a descriptor. */
#ifndef CLIQ_FIXED_FD_SQLITE_IO_H
#define CLIQ_FIXED_FD_SQLITE_IO_H
static int cliq_fd_sqlite_range(sqlite3_int64 offset, int amount) {
  return amount >= 0 && offset >= 0 && offset <= INT64_MAX - amount &&
         (sqlite3_int64)(off_t)offset == offset &&
         (sqlite3_int64)(off_t)(offset + amount) == offset + amount;
}
static int cliq_fd_sqlite_read(int descriptor, void *buffer, int amount,
                               sqlite3_int64 offset, unsigned int *calls) {
  int consumed = 0;
  if (!cliq_fd_sqlite_range(offset, amount)) return SQLITE_IOERR_READ;
  while (consumed < amount) {
    ssize_t result;
    do {
      if (calls) ++*calls;
      result = pread(descriptor, (char *)buffer + consumed,
                     (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result < 0) return SQLITE_IOERR_READ;
    if (result == 0) {
      memset((char *)buffer + consumed, 0, (size_t)(amount - consumed));
      return SQLITE_IOERR_SHORT_READ;
    }
    consumed += (int)result;
  }
  return SQLITE_OK;
}
static int cliq_fd_sqlite_write(int descriptor, const void *buffer, int amount,
                                sqlite3_int64 offset, unsigned int *calls) {
  int consumed = 0;
  if (!cliq_fd_sqlite_range(offset, amount)) return SQLITE_IOERR_WRITE;
  while (consumed < amount) {
    ssize_t result;
    do {
      if (calls) ++*calls;
      result = pwrite(descriptor, (const char *)buffer + consumed,
                      (size_t)(amount - consumed), (off_t)(offset + consumed));
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return SQLITE_IOERR_WRITE;
    consumed += (int)result;
  }
  return SQLITE_OK;
}
static int cliq_fd_sqlite_sync(int descriptor, int flags, unsigned int *calls) {
  int result;
#if defined(__APPLE__) && defined(F_FULLFSYNC)
  if ((flags & 0x0f) == SQLITE_SYNC_FULL) {
    do { if (calls) ++*calls; result = fcntl(descriptor, F_FULLFSYNC); }
    while (result < 0 && errno == EINTR);
    return result == 0 ? SQLITE_OK : SQLITE_IOERR_FSYNC;
  }
#else
  (void)flags;
#endif
  do { if (calls) ++*calls; result = fsync(descriptor); }
  while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}
static int cliq_fd_sqlite_truncate(int descriptor, sqlite3_int64 size, unsigned int *calls) {
  int result;
  if (size < 0 || (sqlite3_int64)(off_t)size != size) return SQLITE_IOERR_TRUNCATE;
  do { if (calls) ++*calls; result = ftruncate(descriptor, (off_t)size); }
  while (result < 0 && errno == EINTR);
  return result == 0 ? SQLITE_OK : SQLITE_IOERR_TRUNCATE;
}
#endif
