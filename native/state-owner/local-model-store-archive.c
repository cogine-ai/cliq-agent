/* Mechanism for the existing original archive holder, not a JS API. */
struct cliq_model_store_archive {
  lms_context *ctx;
  napi_env env;
  napi_ref scope_reference;
  pid_t pid; uid_t uid; gid_t gid;
  int global_fd, owner_fd, current_fd, current_borrowed, current_active, scanned;
  struct stat global, owner, identities[LMS_ROLES], current;
  DIR *scan;
  unsigned fixed_index;
  off_t offset;
  struct cliq_model_store_archive_entry entry;
};
static inline int cliq_model_store_archive_close_scan(cliq_model_store_archive *source) {
  DIR *owned = source->scan; source->scan = NULL;
  if (!owned || closedir(owned) == 0) return 0;
  lms_poison(source->ctx); return -1;
}
static inline int cliq_model_store_archive_root_entries(lms_context *ctx) {
  int fd = openat(ctx->fd[LMS_STORE], ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return -1;
  DIR *scan = fdopendir(fd);
  if (!scan) { lms_close_fd(ctx, &fd); return -1; }
  unsigned count = 0, seen = 0; int valid = 1; struct dirent *entry;
  errno = 0;
  while ((entry = readdir(scan)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    unsigned bit = strcmp(entry->d_name, "objects") == 0 ? 1 : strcmp(entry->d_name, "registry.lock") == 0 ? 2 :
      strcmp(entry->d_name, "registry.sqlite3") == 0 ? 4 : strcmp(entry->d_name, "registry.sqlite3-journal") == 0 ? 8 : 0;
    if (++count > 4 || !bit || (seen & bit)) { valid = 0; break; }
    seen |= bit; errno = 0;
  }
  if (errno || count != 4 || seen != 15) valid = 0;
  if (closedir(scan) != 0) { lms_poison(ctx); return -1; }
  return valid ? 0 : -1;
}
static inline int cliq_model_store_archive_assert(cliq_model_store_archive *source) {
  if (!source || source->pid != getpid() || source->uid != getuid() || source->uid != geteuid() ||
      source->gid != getgid() || source->gid != getegid()) return -1;
  lms_context *ctx = source->ctx; struct stat held, named;
  if (atomic_load(&ctx->uncertain) || atomic_load(&lms_process.poisoned) || atomic_load(&kernel_global_poisoned) ||
      atomic_load(&current_process_retirement_failed) || atomic_load(&ctx->archive_held) != 1 ||
      atomic_load(&lms_process.active) != ctx || !source->scope_reference) return -1;
  /* The strong original EX/model borrow prevents the main thread from
   * retiring these FD numbers. Only immutable snapshots/atomic failure state
   * and actual filesystem observations are consulted on worker threads. */
  if (fstat(source->global_fd, &held) != 0 || !same_inode(&held, &source->global) || !lms_data_file(&held) ||
      fstat(source->owner_fd, &held) != 0 || !same_inode(&held, &source->owner) || !lms_data_file(&held)) return -1;
  int visible = lms_walk(ctx, ctx->root_path);
  if (visible < 0) return -1;
  int valid = fstat(visible, &held) == 0 && lms_directory(&held) && same_inode(&held, &source->identities[LMS_ROOT]);
  if (lms_close_fd(ctx, &visible) != 0 || !valid) return -1;
  for (int role = 0; role < LMS_ROLES; ++role) {
    if (fstat(ctx->fd[role], &held) != 0 || !same_inode(&held, &source->identities[role]) ||
        (role <= LMS_OBJECTS ? !lms_directory(&held) : !lms_data_file(&held)) ||
        (role != LMS_ROOT && role != LMS_LOCK && !source_metadata_same(&held, &source->identities[role]))) return -1;
    if (role == LMS_ROOT) continue;
    int parent = role == LMS_STORE ? ctx->fd[LMS_ROOT] : ctx->fd[LMS_STORE];
    if (fstatat(parent, lms_leaves[role], &named, AT_SYMLINK_NOFOLLOW) != 0 || !source_metadata_same(&held, &named)) return -1;
  }
  return 0;
}
static inline int cliq_model_store_archive_begin(napi_env env, napi_value model_scope,
  migration_credential_gate *original, cliq_model_store_archive **output) {
  *output = NULL;
  lms_context *ctx = lms_receiver(env, model_scope);
  if (!ctx || !ctx->exclusive || ctx->exclusive->original != original || migration_credential_check(original, env) != 0 ||
      ctx->live_files || ctx->package || atomic_load(&ctx->archive_held)) return -1;
  cliq_model_store_archive *source = calloc(1, sizeof(*source));
  if (!source) return -1;
  source->ctx = ctx; source->env = env; source->pid = getpid(); source->uid = geteuid(); source->gid = getegid(); source->current_fd = -1;
  source->global_fd = original->gate->gate_fd; source->owner_fd = original->owner->lock_fd;
  if (fstat(source->global_fd, &source->global) != 0 || !lms_data_file(&source->global) ||
      fstat(source->owner_fd, &source->owner) != 0 || !lms_data_file(&source->owner) ||
      cliq_model_store_archive_root_entries(ctx) != 0) goto failed;
  for (int role = 0; role < LMS_ROLES; ++role) if (fstat(ctx->fd[role], &source->identities[role]) != 0) goto failed;
  if (napi_create_reference(env, model_scope, 1, &source->scope_reference) != napi_ok) goto failed;
  atomic_store(&ctx->archive_held, 1);
  if (cliq_model_store_archive_assert(source) != 0) goto failed;
  *output = source; return 0;
failed:
  if (source->scope_reference) {
    napi_ref reference = source->scope_reference; source->scope_reference = NULL;
    if (napi_delete_reference(env, reference) != napi_ok) { lms_poison(ctx); return -1; }
  }
  atomic_store(&ctx->archive_held, 0); free(source); return -1;
}
static inline int cliq_model_store_archive_directories(cliq_model_store_archive *source,
  struct cliq_model_store_archive_directories *directories) {
  if (cliq_model_store_archive_assert(source) != 0) return -1;
  directories->store = source->identities[LMS_STORE]; directories->objects = source->identities[LMS_OBJECTS];
  return 0;
}
static inline int cliq_model_store_archive_name(const char *name) {
  size_t count = strlen(name);
  if (count == 64) {
    for (size_t i = 0; i < count; ++i) if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return CLIQ_MODEL_STORE_OBJECT;
  }
  if (count == 49 && memcmp(name, ".model-object-v1-", 17) == 0) {
    for (size_t i = 17; i < count; ++i) if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return CLIQ_MODEL_STORE_TEMPORARY;
  }
  return 0;
}
static inline int cliq_model_store_archive_current(cliq_model_store_archive *source) {
  if (!source->current_active || source->current_fd < 0 || cliq_model_store_archive_assert(source) != 0) return -1;
  struct stat held, named;
  if (fstat(source->current_fd, &held) != 0 || !source_metadata_same(&held, &source->current)) return -1;
  const char *leaf = strrchr(source->entry.relative_path, '/');
  if (!leaf) return -1;
  int parent = source->entry.kind >= CLIQ_MODEL_STORE_OBJECT ? source->ctx->fd[LMS_OBJECTS] : source->ctx->fd[LMS_STORE];
  return fstatat(parent, leaf + 1, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&held, &named) ? 0 : -1;
}
static inline int cliq_model_store_archive_next(cliq_model_store_archive *source,
  struct cliq_model_store_archive_entry *entry) {
  if (source->current_active || cliq_model_store_archive_assert(source) != 0) return -1;
  memset(&source->entry, 0, sizeof(source->entry)); source->offset = 0;
  static const int roles[] = {LMS_MAIN, LMS_JOURNAL, LMS_LOCK};
  if (source->fixed_index < 3) {
    int role = roles[source->fixed_index++];
    source->entry.kind = role == LMS_MAIN ? CLIQ_MODEL_STORE_REGISTRY : role == LMS_JOURNAL ? CLIQ_MODEL_STORE_JOURNAL : CLIQ_MODEL_STORE_LOCK;
    int length = snprintf(source->entry.relative_path, sizeof(source->entry.relative_path), "local-models/%s", lms_leaves[role]);
    if (length < 0 || (size_t)length >= sizeof(source->entry.relative_path)) return -1;
    source->current_fd = source->ctx->fd[role]; source->current_borrowed = 1;
    source->current = source->identities[role];
  } else {
    if (source->scanned) return 0;
    if (!source->scan) {
      int descriptor = openat(source->ctx->fd[LMS_OBJECTS], ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (descriptor < 0) return -1;
      source->scan = fdopendir(descriptor);
      if (!source->scan) { lms_close_fd(source->ctx, &descriptor); return -1; }
    }
    struct dirent *item;
    for (;;) {
      errno = 0; item = readdir(source->scan);
      if (!item) {
        if (errno || cliq_model_store_archive_close_scan(source) != 0 || cliq_model_store_archive_assert(source) != 0) return -1;
        source->scanned = 1; return 0;
      }
      if (strcmp(item->d_name, ".") != 0 && strcmp(item->d_name, "..") != 0) break;
    }
    int kind = cliq_model_store_archive_name(item->d_name);
    if (!kind) return -1;
    const char prefix[] = "local-models/objects/";
    size_t length = strlen(item->d_name);
    if (length >= sizeof(source->entry.relative_path) - (sizeof(prefix) - 1)) return -1;
    memcpy(source->entry.relative_path, prefix, sizeof(prefix) - 1);
    memcpy(source->entry.relative_path + sizeof(prefix) - 1, item->d_name, length + 1);
    source->entry.kind = (enum cliq_model_store_archive_kind)kind;
    if (fstatat(source->ctx->fd[LMS_OBJECTS], item->d_name, &source->current, AT_SYMLINK_NOFOLLOW) != 0 ||
        (kind == CLIQ_MODEL_STORE_OBJECT ? !lms_object_file(&source->current) :
          !S_ISREG(source->current.st_mode) || source->current.st_uid != source->uid || source->current.st_gid != source->gid ||
          source->current.st_nlink != 1 || source->current.st_size < 0 ||
          ((source->current.st_mode & 07777) != 0400 && (source->current.st_mode & 07777) != 0600))) return -1;
    source->current_fd = openat(source->ctx->fd[LMS_OBJECTS], item->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source->current_fd < 0) return -1;
    source->current_borrowed = 0;
  }
  source->current_active = 1;
  if (cliq_model_store_archive_current(source) != 0) return -1;
  source->entry.identity = source->current; *entry = source->entry; return 1;
}
static inline int cliq_model_store_archive_read(cliq_model_store_archive *source,
  unsigned char bytes[65536], size_t *size) {
  *size = 0;
  if (cliq_model_store_archive_current(source) != 0 || source->offset < 0 || source->offset > source->current.st_size) return -1;
  size_t count = (uint64_t)(source->current.st_size - source->offset) < 65536 ? (size_t)(source->current.st_size - source->offset) : 65536;
  if (count && cliq_fd_sqlite_read(source->current_fd, bytes, (int)count, (sqlite3_int64)source->offset, NULL) != SQLITE_OK) return -1;
  source->offset += (off_t)count;
  if (cliq_model_store_archive_current(source) != 0) return -1;
  *size = count; return 0;
}
static inline int cliq_model_store_archive_finish_metadata(cliq_model_store_archive *source) {
  if (cliq_model_store_archive_assert(source) != 0) return -1;
  if (!source->current_active) return 0;
  int valid = cliq_model_store_archive_current(source) == 0;
  if (source->current_borrowed) source->current_fd = -1;
  else if (lms_close_fd(source->ctx, &source->current_fd) != 0) return -1;
  source->current_active = 0; source->current_borrowed = 0;
  return valid ? 0 : -1;
}
static inline int cliq_model_store_archive_close_current(cliq_model_store_archive *source) {
  if (!source || (source->current_active && source->offset != source->current.st_size)) return -1;
  return cliq_model_store_archive_finish_metadata(source);
}
static inline int cliq_model_store_archive_rewind(cliq_model_store_archive *source) {
  if (source->current_active || cliq_model_store_archive_assert(source) != 0 ||
      cliq_model_store_archive_close_scan(source) != 0) return -1;
  source->fixed_index = 0; source->scanned = 0; return 0;
}
static inline int cliq_model_store_archive_end(napi_env env, cliq_model_store_archive *source) {
  if (!source || !lms_owner(source->ctx, env) || source->env != env ||
      cliq_model_store_archive_assert(source) != 0 || cliq_model_store_archive_close_current(source) != 0 ||
      cliq_model_store_archive_close_scan(source) != 0 || lms_check(source->ctx) != 0 ||
      cliq_model_store_archive_root_entries(source->ctx) != 0) return -1;
  napi_ref reference = source->scope_reference; source->scope_reference = NULL;
  if (napi_delete_reference(env, reference) != napi_ok) { lms_poison(source->ctx); return -1; }
  atomic_store(&source->ctx->archive_held, 0); free(source); return 0;
}
static inline int cliq_model_store_archive_cancel(napi_env env, cliq_model_store_archive *source) {
  if (!source || !lms_owner(source->ctx, env) || source->env != env || source->pid != getpid()) return -1;
  lms_context *ctx = source->ctx;
  if (!ctx->exclusive || lms_exclusive_check(ctx->exclusive, env) != 0 || atomic_load(&ctx->uncertain) ||
      atomic_load(&lms_process.poisoned) || atomic_load(&ctx->archive_held) != 1 || atomic_load(&lms_process.active) != ctx ||
      ctx->retired || ctx->live_files || ctx->package || !source->scope_reference) return -1;
  napi_value original_scope; bool tagged = false; lms_context *original = NULL;
  if (napi_get_reference_value(env, source->scope_reference, &original_scope) != napi_ok ||
      napi_check_object_type_tag(env, original_scope, &lms_tag, &tagged) != napi_ok || !tagged ||
      napi_unwrap(env, original_scope, (void **)&original) != napi_ok || original != ctx) return -1;
  /* Changed data/modes/names are not a failed close. These descriptors are
   * still our exact original descriptions; close does not publish, delete,
   * rewrite, recover or certify any of their current source bytes. */
  struct stat observed;
  for (int role = 0; role < LMS_ROLES; ++role)
    if (ctx->fd[role] < 0 || fstat(ctx->fd[role], &observed) != 0 || !same_inode(&observed, &source->identities[role])) {
      lms_poison(ctx); return -1;
    }
  if (source->current_active) {
    if (source->current_fd < 0 || fstat(source->current_fd, &observed) != 0 || !same_inode(&observed, &source->current)) {
      lms_poison(ctx); return -1;
    }
    if (source->current_borrowed) source->current_fd = -1;
    else if (lms_close_fd(ctx, &source->current_fd) != 0) return -1;
    source->current_active = 0; source->current_borrowed = 0;
  }
  if (source->scan) {
    int descriptor = dirfd(source->scan);
    if (descriptor < 0 || fstat(descriptor, &observed) != 0 || !same_inode(&observed, &source->identities[LMS_OBJECTS])) {
      lms_poison(ctx); return -1;
    }
  }
  if (cliq_model_store_archive_close_scan(source) != 0) return -1;
  napi_ref reference = source->scope_reference; source->scope_reference = NULL;
  if (napi_delete_reference(env, reference) != napi_ok) { lms_poison(ctx); return -1; }
  ctx->archive_cancelled = 1; atomic_store(&ctx->archive_held, 0); free(source); return 0;
}
