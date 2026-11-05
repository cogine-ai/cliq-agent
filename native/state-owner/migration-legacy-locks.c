/* Canonical Legacy path-lock cohort under one genuine migration holder.
 * Included after migration-publication.c. No caller path/target list, stale
 * removal, JavaScript heartbeat, process-scan proof or lease extension exists.
 * A libuv native thread owns the original 1666ms heartbeat; async release really
 * stops and joins it. Blocking filesystem calls have no Stop2 latency claim. */
#include <sys/resource.h>
#include "migration-legacy-locks.h"

#define ML_TARGET_LIMIT 256U
#define ML_PARENT_LIMIT 256U
#define ML_WALK_LIMIT 6U
#define ML_METADATA_LIMIT (16ULL * 1024ULL * 1024ULL)
#define ML_HEARTBEAT_NS 1666000000ULL
#define ML_LEASE_NS 5000000000ULL
enum ml_family { ML_ROOT, ML_SESSIONS, ML_YEAR, ML_MONTH, ML_DAY,
    ML_PLANS, ML_PLAN_WORKSPACE, ML_PLAN_SESSION, ML_PLAN, ML_TX_ROOT, ML_TX, ML_OTHER };
typedef struct ml_node ml_node;
struct ml_node {
    ml_node *parent, *next, *children, *sibling;
    ml_node **index;
    char *name, *path;
    struct stat identity;
    size_t child_count;
    uint64_t seen;
    int family, walked, dirty;
};
typedef struct ml_parent { ml_node *node; int fd; struct stat identity; } ml_parent;
typedef struct ml_target {
    ml_node *parent_node;
    size_t parent_index;
    char path[4097], leaf[NAME_MAX + 1];
    int directory_fd, owner_fd;
    struct stat directory, owner;
    atomic_int stage; /* 0 absent, 1 original dir, 2 original owner, 3 full token, 4 durable */
    atomic_uint_fast64_t renewed_mono, renewed_real;
    int birth_started, owner_unlinked, directory_unlinked;
} ml_target;
typedef struct ml_walk { ml_node *node; DIR *directory; int fd; } ml_walk;
struct migration_legacy_locks {
    migration_filesystem *scope;
    ml_node *nodes, *root;
    ml_target targets[ML_TARGET_LIMIT];
    ml_parent parents[ML_PARENT_LIMIT];
    ml_walk walk[ML_WALK_LIMIT];
    size_t target_count, parent_count, walk_count, parents_opened, acquired;
    uint64_t metadata_bytes, epoch;
    int discovered, ordered, checked_before_birth, complete, released, thread_started, thread_joined;
    atomic_int stop, failed, retiring, retirement_failed;
    atomic_uint_fast64_t completed_check_mono;
    uv_thread_t thread;
    uv_mutex_t wait_mutex;
    uv_mutex_t lease_mutex;
    uv_cond_t wait_condition;
    int mutex_ready, lease_mutex_ready, condition_ready;
    char token[80]; size_t token_size;
    napi_async_work release_work;
    napi_deferred release_deferred;
    napi_ref release_self, release_promise;
};

static int ml_same_directory(const struct stat *actual, const struct stat *expected) {
    return S_ISDIR(actual->st_mode) && same_inode(actual, expected) && actual->st_uid == expected->st_uid &&
        actual->st_gid == expected->st_gid && actual->st_mode == expected->st_mode;
}
static int ml_clock(clockid_t clock, uint64_t *value) {
    struct timespec now;
    if (clock_gettime(clock, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec) / 1000000000ULL) return -1;
    *value = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec; return 0;
}
static uint64_t ml_mtime(const struct stat *identity) {
#ifdef __APPLE__
    struct timespec value = identity->st_mtimespec;
#else
    struct timespec value = identity->st_mtim;
#endif
    if (value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1000000000L ||
        (uint64_t)value.tv_sec > (UINT64_MAX - (uint64_t)value.tv_nsec) / 1000000000ULL) return UINT64_MAX;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}
static int ml_account(migration_legacy_locks *state, size_t bytes) {
    migration_filesystem *scope = state->scope;
    if (state->metadata_bytes > ML_METADATA_LIMIT || bytes > ML_METADATA_LIMIT - state->metadata_bytes ||
        scope->backup_metadata_bytes > MIGRATION_BACKUP_METADATA_BYTES ||
        bytes > MIGRATION_BACKUP_METADATA_BYTES - scope->backup_metadata_bytes) return -1;
    state->metadata_bytes += bytes; scope->backup_metadata_bytes += bytes; return 0;
}
static ml_node *ml_node_new(migration_legacy_locks *state, ml_node *parent, const char *name, const struct stat *identity, int family) {
    size_t length = strlen(name), prefix = parent ? strlen(parent->path) : 0;
    size_t path_size = prefix + (prefix ? 1 : 0) + length;
    if (length > NAME_MAX || path_size > 4096 || ml_account(state, sizeof(ml_node) + length + 1 + path_size + 1) != 0) return NULL;
    ml_node *node = calloc(1, sizeof(*node) + length + 1 + path_size + 1);
    if (!node) return NULL;
    node->name = (char *)(node + 1); memcpy(node->name, name, length + 1);
    node->path = node->name + length + 1;
    if (prefix) { memcpy(node->path, parent->path, prefix); node->path[prefix++] = '/'; }
    memcpy(node->path + prefix, name, length + 1);
    node->parent = parent; node->identity = *identity; node->family = family;
    node->next = state->nodes; state->nodes = node;
    if (parent) { node->sibling = parent->children; parent->children = node; parent->child_count++; }
    return node;
}
static int ml_digits(const char *text, size_t size) { return strlen(text) == size && strspn(text, "0123456789") == size; }
static int ml_safe_id(const char *text) {
    size_t size = strlen(text);
    return size && size <= NAME_MAX && strspn(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == size;
}
static int ml_tx_id(const char *text) { return !strncmp(text, "tx_", 3) && strlen(text) <= 128 && ml_safe_id(text + 3); }
static int ml_family_of(ml_node *parent, const char *name, const struct stat *identity) {
    if (!S_ISDIR(identity->st_mode)) return ML_OTHER;
    switch (parent->family) {
    case ML_ROOT: return !strcmp(name, "sessions") ? ML_SESSIONS : !strcmp(name, "plans") ? ML_PLANS : !strcmp(name, "tx") ? ML_TX_ROOT : ML_OTHER;
    case ML_SESSIONS: return ml_digits(name, 4) ? ML_YEAR : ML_OTHER;
    case ML_YEAR: return ml_digits(name, 2) ? ML_MONTH : ML_OTHER;
    case ML_MONTH: return ml_digits(name, 2) ? ML_DAY : ML_OTHER;
    case ML_PLANS: return ml_safe_id(name) ? ML_PLAN_WORKSPACE : ML_OTHER;
    case ML_PLAN_WORKSPACE: return ml_safe_id(name) ? ML_PLAN_SESSION : ML_OTHER;
    case ML_PLAN_SESSION: return ml_safe_id(name) ? ML_PLAN : ML_OTHER;
    case ML_TX_ROOT: return ml_tx_id(name) ? ML_TX : ML_OTHER;
    default: return ML_OTHER;
    }
}
static int ml_add_target(migration_legacy_locks *state, ml_node *parent, const char *target) {
    if (state->target_count == ML_TARGET_LIMIT || strlen(target) + 5 > NAME_MAX) return -1;
    ml_target *entry = &state->targets[state->target_count];
    int size = snprintf(entry->path, sizeof(entry->path), "%s%s%s", parent->path, parent->path[0] ? "/" : "", target);
    if (size < 0 || (size_t)size >= sizeof(entry->path)) return -1;
    snprintf(entry->leaf, sizeof(entry->leaf), "%s.lock", target);
    entry->parent_node = parent; entry->directory_fd = entry->owner_fd = -1;
    atomic_init(&entry->stage, 0); atomic_init(&entry->renewed_mono, 0); atomic_init(&entry->renewed_real, 0); state->target_count++; return 0;
}
static int ml_target_compare(const void *left, const void *right) { return strcmp(((const ml_target *)left)->path, ((const ml_target *)right)->path); }
static int ml_node_compare(const void *left, const void *right) { return strcmp((*(ml_node *const *)left)->name, (*(ml_node *const *)right)->name); }
static int ml_index(migration_legacy_locks *state, ml_node *node) {
    if (node->index) return 0;
    size_t slots = node->child_count ? node->child_count : 1;
    if (slots > SIZE_MAX / sizeof(*node->index) || ml_account(state, slots * sizeof(*node->index)) != 0) return -1;
    node->index = calloc(slots, sizeof(*node->index)); if (!node->index) return -1;
    size_t offset = 0;
    for (ml_node *child = node->children; child; child = child->sibling) node->index[offset++] = child;
    qsort(node->index, node->child_count, sizeof(*node->index), ml_node_compare); return 0;
}
static ml_node *ml_find(ml_node *node, const char *name) {
    size_t low = 0, high = node->child_count;
    while (low < high) { size_t mid = low + (high - low) / 2; int order = strcmp(name, node->index[mid]->name);
        if (!order) return node->index[mid];
        if (order < 0) high = mid; else low = mid + 1;
    }
    return NULL;
}
static int ml_protocol_object(migration_legacy_locks *state, ml_node *parent, const char *name, const struct stat *identity) {
    migration_filesystem *scope = state->scope;
    if ((S_ISDIR(identity->st_mode) && same_inode(identity, &scope->binding->owner->root)) ||
        (S_ISREG(identity->st_mode) && same_inode(identity, &scope->binding->gate->file))) return 1;
    if (parent == state->root && scope->publication) for (size_t index = 0; index < MP_FILES; ++index)
        if (mp_is_named_file(scope, &scope->publication->files[index], name, identity)) return 1;
    return 0;
}
static int ml_open_node(migration_legacy_locks *state, ml_node *node, int strict) {
    ml_node *chain[ML_WALK_LIMIT]; size_t count = 0;
    for (ml_node *part = node; part && part->parent; part = part->parent) {
        if (count == ML_WALK_LIMIT) return -1;
        chain[count++] = part;
    }
    int current = openat(state->scope->legacy_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat observed;
    if (current < 0 || fstat(current, &observed) != 0 || !ml_same_directory(&observed, &state->root->identity) ||
        (strict && !state->root->dirty && !source_metadata_same(&observed, &state->root->identity))) goto failed;
    while (count) {
        ml_node *part = chain[--count]; struct stat named;
        if (fstatat(current, part->name, &named, AT_SYMLINK_NOFOLLOW) != 0 || !ml_same_directory(&named, &part->identity) ||
            (strict && !part->dirty && !source_metadata_same(&named, &part->identity))) goto failed;
        int next = openat(current, part->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto failed;
        int valid = fstat(next, &observed) == 0 && source_metadata_same(&named, &observed);
        if (migrate_scope_close_fd(state->scope, &current) != 0) { migrate_scope_close_fd(state->scope, &next); return -1; }
        current = next; if (!valid) goto failed;
    }
    return current;
failed:
    migrate_scope_close_fd(state->scope, &current); return -1;
}
static int ml_push(migration_legacy_locks *state, ml_node *node, int descriptor) {
    if (state->walk_count == ML_WALK_LIMIT) return -1;
    DIR *directory = fdopendir(descriptor); if (!directory) return -1;
    ml_walk *walk = &state->walk[state->walk_count++]; walk->node = node; walk->fd = descriptor; walk->directory = directory;
    node->walked = 1; return 0;
}
static int ml_discover_next(migration_legacy_locks *state) {
    ml_walk *walk = &state->walk[state->walk_count - 1]; errno = 0;
    struct dirent *entry = readdir(walk->directory);
    if (!entry) {
        struct stat after; int valid = !errno && fstat(walk->fd, &after) == 0 && source_metadata_same(&after, &walk->node->identity) && ml_index(state, walk->node) == 0;
        DIR *directory = walk->directory; walk->directory = NULL; walk->fd = -1; state->walk_count--;
        if (closedir(directory) != 0) { migrate_scope_poison(state->scope); return -1; }
        if (!valid) return -1;
        if (!state->walk_count) state->discovered = 1;
        return 0;
    }
    const char *name = entry->d_name;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return 0;
    if (!name[0] || strlen(name) > NAME_MAX || strchr(name, '\\') || !utf8_valid((unsigned char *)name)) return -1;
    struct stat identity;
    if (fstatat(walk->fd, name, &identity, AT_SYMLINK_NOFOLLOW) != 0) return -1;
    if (ml_protocol_object(state, walk->node, name, &identity)) return 0;
    if (identity.st_uid != geteuid() || identity.st_dev != state->scope->legacy.st_dev) return -1;
    int family = ml_family_of(walk->node, name, &identity);
    ml_node *node = ml_node_new(state, walk->node, name, &identity, family); if (!node) return -1;
    if (walk->node->family == ML_ROOT && (!strcmp(name, "sessions") || !strcmp(name, "plans") || !strcmp(name, "tx")) && !S_ISDIR(identity.st_mode)) return -1;
    if (walk->node->family == ML_DAY) {
        size_t size = strlen(name);
        if (size > 5 && !strcmp(name + size - 5, ".json")) {
            if (!S_ISREG(identity.st_mode) || identity.st_nlink != 1 || ml_add_target(state, walk->node, name) != 0) return -1;
        }
    }
    if (family == ML_OTHER) return 0;
    if ((family == ML_PLAN && (ml_add_target(state, node, "plan.json") != 0 || ml_add_target(state, node, "progress.json") != 0)) ||
        (family == ML_TX && ml_add_target(state, node, "tx") != 0)) return -1;
    int opened = openat(walk->fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat actual;
    if (opened < 0 || fstat(opened, &actual) != 0 || !source_metadata_same(&actual, &identity) || ml_push(state, node, opened) != 0) {
        migrate_scope_close_fd(state->scope, &opened); return -1;
    }
    return 0;
}
static int ml_directory_identity(migration_legacy_locks *state, ml_target *target) {
    ml_parent *parent = &state->parents[target->parent_index]; struct stat actual, named;
    return parent->fd >= 0 && fstat(parent->fd, &actual) == 0 && ml_same_directory(&actual, &parent->identity) &&
        target->directory_fd >= 0 && fstat(target->directory_fd, &actual) == 0 && S_ISDIR(actual.st_mode) &&
        same_inode(&actual, &target->directory) && actual.st_uid == geteuid() && actual.st_gid == target->directory.st_gid && (actual.st_mode & 07777) == 0700 &&
        fstatat(parent->fd, target->leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 && ml_same_directory(&actual, &named) ? 0 : -1;
}
static int ml_owner_identity(ml_target *target, struct stat *actual) {
    struct stat named;
    return target->owner_fd >= 0 && fstat(target->owner_fd, actual) == 0 && S_ISREG(actual->st_mode) &&
        same_inode(actual, &target->owner) && actual->st_uid == geteuid() && actual->st_gid == target->owner.st_gid && (actual->st_mode & 07777) == 0600 && actual->st_nlink == 1 &&
        fstatat(target->directory_fd, "owner", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(actual, &named) &&
        actual->st_uid == named.st_uid && actual->st_gid == named.st_gid && actual->st_mode == named.st_mode && named.st_nlink == 1 ? 0 : -1;
}
static int ml_token(migration_legacy_locks *state, ml_target *target) {
    unsigned char bytes[sizeof(state->token)]; size_t offset = 0; struct stat before, after;
    if (ml_owner_identity(target, &before) != 0 || before.st_size < 0 || (uint64_t)before.st_size != state->token_size) return -1;
    while (offset < state->token_size) {
        ssize_t got; do { got = pread(target->owner_fd, bytes + offset, state->token_size - offset, (off_t)offset); } while (got < 0 && errno == EINTR);
        if (got <= 0 || (size_t)got > state->token_size - offset) return -1;
        offset += (size_t)got;
    }
    unsigned char extra; ssize_t end; do { end = pread(target->owner_fd, &extra, 1, (off_t)offset); } while (end < 0 && errno == EINTR);
    return end == 0 && !memcmp(bytes, state->token, state->token_size) && ml_owner_identity(target, &after) == 0 &&
        source_metadata_same(&before, &after) ? 0 : -1;
}
static int ml_live_locked(migration_legacy_locks *state, ml_target *target, int renew, int require_ready) {
    int stage = atomic_load_explicit(&target->stage, memory_order_acquire);
    if (!stage) return require_ready ? -1 : 0;
    struct stat lease; uint64_t real, mono;
    if ((require_ready && stage != 4) || ml_directory_identity(state, target) != 0) return -1;
    int descriptor = target->directory_fd;
    if (stage >= 2) {
        descriptor = target->owner_fd;
        if (ml_owner_identity(target, &lease) != 0 || lease.st_size < 0 || (uint64_t)lease.st_size > state->token_size ||
            (stage >= 3 && ((uint64_t)lease.st_size != state->token_size || ml_token(state, target) != 0))) return -1;
    } else if (fstat(descriptor, &lease) != 0) return -1;
    uint64_t modified = ml_mtime(&lease), previous = atomic_load_explicit(&target->renewed_mono, memory_order_acquire);
    if (ml_clock(CLOCK_REALTIME, &real) != 0 || ml_clock(CLOCK_MONOTONIC, &mono) != 0) return -1;
    if (!previous || mono < previous || mono - previous > ML_LEASE_NS || modified > real || real - modified > ML_LEASE_NS) return -1;
    if (!renew) return 0;
    struct timespec times[2] = {{.tv_sec = (time_t)(real / 1000000000ULL), .tv_nsec = (long)(real % 1000000000ULL)},
        {.tv_sec = (time_t)(real / 1000000000ULL), .tv_nsec = (long)(real % 1000000000ULL)}};
    if (futimens(descriptor, times) != 0 || fstat(descriptor, &lease) != 0 || ml_mtime(&lease) != real ||
        ml_clock(CLOCK_MONOTONIC, &mono) != 0 || mono < previous || mono - previous > ML_LEASE_NS) return -1;
    atomic_store_explicit(&target->renewed_real, real, memory_order_release);
    atomic_store_explicit(&target->renewed_mono, mono, memory_order_release); return 0;
}
static int ml_live(migration_legacy_locks *state, ml_target *target, int renew, int require_ready) {
    /* Own futimens changes are serialized with the main thread's real lease
     * check; a heartbeat cannot make a prior clock sample appear future-dated.
     * No mutex is held across the protected SQL transaction. */
    uv_mutex_lock(&state->lease_mutex);
    int status = ml_live_locked(state, target, renew, require_ready);
    uv_mutex_unlock(&state->lease_mutex); return status;
}
static int ml_cohort_fresh(migration_legacy_locks *state, int all_ready) {
    uint64_t mono, real;
    if (ml_clock(CLOCK_MONOTONIC, &mono) != 0 || ml_clock(CLOCK_REALTIME, &real) != 0) return -1;
    for (size_t index = 0; index < state->target_count; ++index) {
        ml_target *target = &state->targets[index]; int stage = atomic_load_explicit(&target->stage, memory_order_acquire);
        if (!stage && !all_ready) continue;
        if (!stage || (all_ready && stage != 4)) return -1;
        uint64_t last_mono = atomic_load_explicit(&target->renewed_mono, memory_order_acquire);
        uint64_t last_real = atomic_load_explicit(&target->renewed_real, memory_order_acquire);
        /* A concurrently completed real heartbeat may be newer than the
         * initial clock sample. Re-sample once after loading that timestamp;
         * this is not a retry of a failed lease or filesystem action. */
        if (last_mono > mono && ml_clock(CLOCK_MONOTONIC, &mono) != 0) return -1;
        if (last_real > real && ml_clock(CLOCK_REALTIME, &real) != 0) return -1;
        if (!last_mono || !last_real || mono < last_mono || real < last_real ||
            mono - last_mono > ML_LEASE_NS || real - last_real > ML_LEASE_NS) return -1;
    }
    return 0;
}
static void ml_heartbeat(void *data) {
    migration_legacy_locks *state = data;
    while (!atomic_load(&state->stop)) {
        uint64_t before, after;
        if (ml_clock(CLOCK_MONOTONIC, &before) != 0) { atomic_store(&state->failed, 1); break; }
        for (size_t index = 0; index < state->target_count && !atomic_load(&state->stop); ++index)
            if (ml_live(state, &state->targets[index], 1, 0) != 0) { atomic_store(&state->failed, 1); atomic_store(&state->stop, 1); break; }
        if (ml_clock(CLOCK_MONOTONIC, &after) != 0 || after < before || after - before > ML_LEASE_NS || ml_cohort_fresh(state, 0) != 0) { atomic_store(&state->failed, 1); break; }
        if (!atomic_load(&state->failed) && !atomic_load(&state->stop)) atomic_store_explicit(&state->completed_check_mono, after, memory_order_release);
        uv_mutex_lock(&state->wait_mutex);
        if (!atomic_load(&state->stop)) {
            uint64_t elapsed = after - before;
            int status = elapsed < ML_HEARTBEAT_NS ? uv_cond_timedwait(&state->wait_condition, &state->wait_mutex, ML_HEARTBEAT_NS - elapsed) : 0;
            if (status && status != UV_ETIMEDOUT) { atomic_store(&state->failed, 1); atomic_store(&state->stop, 1); }
        }
        uv_mutex_unlock(&state->wait_mutex);
    }
}
static int ml_own_directory(migration_legacy_locks *state, const struct stat *identity) {
    for (size_t index = 0; index < state->target_count; ++index) {
        ml_target *target = &state->targets[index];
        if (atomic_load_explicit(&target->stage, memory_order_acquire) && !target->directory_unlinked &&
            same_inode(identity, &target->directory) && ml_directory_identity(state, target) == 0) return 1;
    }
    return 0;
}
static int ml_verify_directory(migration_legacy_locks *state, ml_node *node, int strict) {
    int fd = ml_open_node(state, node, strict); if (fd < 0) return -1;
    DIR *directory = fdopendir(fd);
    if (!directory) { migrate_scope_close_fd(state->scope, &fd); return -1; }
    struct stat before, after; int valid = fstat(fd, &before) == 0; size_t seen = 0;
    if (state->epoch == UINT64_MAX) valid = 0;
    uint64_t epoch = ++state->epoch;
    while (valid) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) valid = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat actual;
        if (fstatat(fd, entry->d_name, &actual, AT_SYMLINK_NOFOLLOW) != 0) { valid = 0; break; }
        ml_node *expected = ml_find(node, entry->d_name);
        if (ml_own_directory(state, &actual)) continue;
        if (ml_protocol_object(state, node, entry->d_name, &actual)) {
            if (expected) { if (expected->seen == epoch) { valid = 0; break; } expected->seen = epoch; seen++; }
            continue;
        }
        if (!expected || expected->seen == epoch || (strict ? !source_metadata_same(&actual, &expected->identity) :
            ((actual.st_mode & S_IFMT) != (expected->identity.st_mode & S_IFMT)))) { valid = 0; break; }
        expected->seen = epoch; seen++;
    }
    valid = valid && seen == node->child_count && fstat(fd, &after) == 0 && source_metadata_same(&before, &after) &&
        (!strict || node->dirty || source_metadata_same(&after, &node->identity));
    if (closedir(directory) != 0) { migrate_scope_poison(state->scope); return -1; }
    if (!valid) return -1;
    if (strict && node->dirty) { node->identity = after; node->dirty = 0; }
    return 0;
}
static int ml_verify_tree(migration_legacy_locks *state, int strict) {
    /* Children were allocated after their parents and prepended. Each dirty
     * real parent is therefore verified before its ancestor observes it. */
    for (ml_node *node = state->nodes; node; node = node->next)
        if (node->walked && ml_verify_directory(state, node, strict) != 0) return -1;
    return 0;
}
static int ml_order(migration_legacy_locks *state) {
    qsort(state->targets, state->target_count, sizeof(*state->targets), ml_target_compare);
    for (size_t index = 0; index < state->target_count; ++index) {
        ml_target *target = &state->targets[index];
        if (index && !strcmp(target->path, state->targets[index - 1].path)) return -1;
        size_t parent = 0;
        while (parent < state->parent_count && state->parents[parent].node != target->parent_node) parent++;
        if (parent == state->parent_count) {
            if (parent == ML_PARENT_LIMIT) return -1;
            state->parents[parent].node = target->parent_node; state->parents[parent].fd = -1; state->parent_count++;
        }
        target->parent_index = parent;
    }
    struct rlimit limit;
    uint64_t required = 2 * state->target_count + state->parent_count + 2 * ML_WALK_LIMIT + state->scope->legacy_chain_count + 32;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || (limit.rlim_cur != RLIM_INFINITY && required >= limit.rlim_cur)) return -1;
    /* This is not a promise that the remaining process FD slots are free.
     * Every actual open still must succeed; EMFILE never raises the limit. */
    state->ordered = 1; return 0;
}
static int ml_birth(migration_legacy_locks *state, ml_target *target) {
    ml_parent *parent = &state->parents[target->parent_index]; uint64_t before;
    if (ml_clock(CLOCK_MONOTONIC, &before) != 0 || mkdirat(parent->fd, target->leaf, 0700) != 0) return -1;
    target->birth_started = 1;
    target->parent_node->dirty = 1;
    target->directory_fd = openat(parent->fd, target->leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (target->directory_fd < 0 || fstat(target->directory_fd, &target->directory) != 0 || !private_directory(&target->directory)) return -1;
    atomic_store(&target->renewed_mono, before); atomic_store(&target->renewed_real, ml_mtime(&target->directory));
    atomic_store_explicit(&target->stage, 1, memory_order_release);
    if (ml_directory_identity(state, target) != 0) return -1;
    target->owner_fd = openat(target->directory_fd, "owner", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (target->owner_fd < 0 || fstat(target->owner_fd, &target->owner) != 0 || !private_lock_file(&target->owner)) return -1;
    /* Directory-only renewal cannot overwrite a later owner-file lease.
     * Publish that original owner FD and its actual mtime under the same
     * short mutex used by heartbeat checks, without holding it for writes. */
    uv_mutex_lock(&state->lease_mutex);
    atomic_store(&target->renewed_mono, before); atomic_store(&target->renewed_real, ml_mtime(&target->owner));
    atomic_store_explicit(&target->stage, 2, memory_order_release);
    uv_mutex_unlock(&state->lease_mutex);
    size_t offset = 0;
    while (offset < state->token_size) {
        ssize_t written; do { written = pwrite(target->owner_fd, state->token + offset, state->token_size - offset, (off_t)offset); } while (written < 0 && errno == EINTR);
        if (written <= 0 || (size_t)written > state->token_size - offset) return -1;
        offset += (size_t)written;
    }
    atomic_store_explicit(&target->stage, 3, memory_order_release);
    if (ml_live(state, target, 0, 0) != 0 || fsync(target->owner_fd) != 0 || fsync(target->directory_fd) != 0 || fsync(parent->fd) != 0) return -1;
    atomic_store_explicit(&target->stage, 4, memory_order_release);
    return ml_live(state, target, 0, 1);
}
static int ml_original_entry(migration_filesystem *scope) {
    return !scope->inspection && scope->publication && scope->publication->phase == 1 && !scope->publication->auth_observed &&
        !scope->backup_started && !scope->candidate_created && !scope->children && !scope->failed && mp_current(scope, scope->env) == 0;
}
static migration_legacy_locks *ml_create(migration_filesystem *scope, int current_inspector) {
    if (scope->legacy_locks || (current_inspector ? ci_legacy_entry(scope) != 0 : !ml_original_entry(scope))) return NULL;
    migration_legacy_locks *state = calloc(1, sizeof(*state)); if (!state) return NULL;
    state->scope = scope; scope->legacy_locks = state;
    atomic_init(&state->stop, 0); atomic_init(&state->failed, 0); atomic_init(&state->retiring, 0); atomic_init(&state->retirement_failed, 0);
    atomic_init(&state->completed_check_mono, 0);
    for (size_t index = 0; index < ML_WALK_LIMIT; ++index) state->walk[index].fd = -1;
    if (ml_account(state, sizeof(*state)) != 0 || uv_mutex_init(&state->wait_mutex) != 0) return NULL;
    state->mutex_ready = 1;
    if (uv_mutex_init(&state->lease_mutex) != 0) return NULL;
    state->lease_mutex_ready = 1;
    if (uv_cond_init(&state->wait_condition) != 0) return NULL;
    state->condition_ready = 1;
    unsigned char random[16];
    if (uv_random(NULL, NULL, random, sizeof(random), 0, NULL) != 0) return NULL;
    random[6] = (unsigned char)((random[6] & 15) | 64); random[8] = (unsigned char)((random[8] & 63) | 128);
    int size = snprintf(state->token, sizeof(state->token), "%ld:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", (long)getpid(),
        random[0], random[1], random[2], random[3], random[4], random[5], random[6], random[7], random[8], random[9], random[10], random[11], random[12], random[13], random[14], random[15]);
    if (size < 1 || (size_t)size >= sizeof(state->token)) return NULL;
    state->token_size = (size_t)size;
    struct stat identity;
    if (fstat(scope->legacy_fd, &identity) != 0 || !(state->root = ml_node_new(state, NULL, "", &identity, ML_ROOT)) ||
        ml_add_target(state, state->root, "auth.json") != 0 || ml_add_target(state, state->root, "workspace-state") != 0) return NULL;
    int opened = openat(scope->legacy_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (opened < 0 || ml_push(state, state->root, opened) != 0) { migrate_scope_close_fd(scope, &opened); return NULL; }
    return state;
}
static int migrate_legacy_locks_custody(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    if (!state || state->released) return 0;
    /* No method lends or consumes these FDs. Publication into the heartbeat
     * uses release/acquire stages; only actual joined retirement may close
     * them. Prevent access while that worker owns the original descriptions.
     * This is custody, not a successful current-lock/commit observation. */
    return atomic_load(&state->retiring) || atomic_load(&state->retirement_failed) ? -1 : 0;
}
static int migrate_legacy_locks_ready(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    return state && state->complete && !state->released && state->thread_started && !atomic_load(&state->stop) &&
        migrate_legacy_locks_validate(scope) == 0;
}
static int migrate_legacy_locks_validate(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    if (!state || state->released) return 0;
    if (atomic_load(&state->retiring) || atomic_load(&state->failed)) return -1;
    if (state->complete) {
        uint64_t last = atomic_load_explicit(&state->completed_check_mono, memory_order_acquire), now;
        if (!last || ml_clock(CLOCK_MONOTONIC, &now) != 0 || now < last || now - last > ML_LEASE_NS || ml_cohort_fresh(state, 1) != 0) return -1;
    }
    return 0;
}
static int migrate_legacy_locks_assert_current(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    if (!migrate_legacy_locks_ready(scope) || ml_verify_tree(state, 0) != 0) return -1;
    for (size_t index = 0; index < state->target_count; ++index)
        if (ml_live(state, &state->targets[index], 0, 1) != 0) return -1;
    return migrate_legacy_locks_ready(scope) ? 0 : -1;
}
static int migrate_legacy_locks_owns(migration_filesystem *scope, const struct stat *identity) {
    return migrate_legacy_locks_ready(scope) && ml_own_directory(scope->legacy_locks, identity);
}
static napi_value ml_prepare_for_scope(napi_env env, migration_filesystem *scope, int current_inspector) {
    migration_legacy_locks *state = scope->legacy_locks;
    if (!state) state = ml_create(scope, current_inspector);
    if (!state || scope->failed || state->released || atomic_load(&state->retiring) || atomic_load(&state->failed) ||
        (current_inspector ? ci_legacy_entry(scope) != 0 : !ml_original_entry(scope)) || migrate_legacy_locks_validate(scope) != 0)
        return migrate_scope_error(env, scope, "canonical Legacy locks require the original durable phase-1 spine and unstarted source consumers");
    int failed = 0;
    if (!state->discovered) failed = ml_discover_next(state);
    else if (!state->ordered) failed = ml_order(state);
    else if (state->parents_opened < state->parent_count) {
        ml_parent *parent = &state->parents[state->parents_opened];
        parent->fd = ml_open_node(state, parent->node, 1);
        failed = parent->fd < 0 || fstat(parent->fd, &parent->identity) != 0 || (parent->identity.st_mode & 07022) != 0;
        if (!failed) state->parents_opened++;
    } else if (!state->checked_before_birth) {
        failed = ml_verify_tree(state, 1);
        if (!failed) {
            state->checked_before_birth = 1;
            failed = uv_thread_create(&state->thread, ml_heartbeat, state);
            if (!failed) state->thread_started = 1;
        }
    } else if (state->acquired < state->target_count) {
        failed = ml_birth(state, &state->targets[state->acquired]);
        if (!failed) state->acquired++;
    } else if (!state->complete) {
        failed = ml_verify_tree(state, 1);
        for (size_t index = 0; !failed && index < state->target_count; ++index) failed = ml_live(state, &state->targets[index], 0, 1);
        uint64_t now;
        if (!failed && !atomic_load(&state->failed) && ml_clock(CLOCK_MONOTONIC, &now) == 0 && ml_cohort_fresh(state, 1) == 0) {
            atomic_store_explicit(&state->completed_check_mono, now, memory_order_release); state->complete = 1;
        } else failed = 1;
    }
    if (failed) { atomic_store(&state->failed, 1); return migrate_scope_error(env, scope, "canonical Legacy lock discovery, exclusive birth or original lease failed; no stale lock was adopted"); }
    napi_value result; return napi_get_boolean(env, state->complete != 0, &result) == napi_ok ? result : NULL;
}
static napi_value migrate_legacy_locks_prepare_next(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info); if (!scope) return NULL;
    return ml_prepare_for_scope(env, scope, 0);
}
static napi_value migrate_legacy_locks_assert(napi_env env, napi_callback_info info) {
    migration_filesystem *scope = migrate_scope_no_arguments(env, info); if (!scope) return NULL;
    if (scope->failed || mp_current(scope, env) != 0 || migrate_legacy_locks_assert_current(scope) != 0)
        return migrate_scope_error(env, scope, "the original complete canonical Legacy lock set changed or is unavailable");
    return mp_undefined(env);
}
static int ml_retire_fd(migration_legacy_locks *state, int *fd) {
    int original = *fd; *fd = -1;
    if (original >= 0 && close(original) != 0) { atomic_store(&state->retirement_failed, 1); return -1; }
    return 0;
}
static int ml_cleanup(migration_legacy_locks *state) {
    for (size_t index = state->target_count; index; --index) {
        ml_target *target = &state->targets[index - 1]; int stage = atomic_load(&target->stage);
        if (stage) {
            if (ml_directory_identity(state, target) != 0) return -1;
            if (target->owner_fd >= 0) {
                struct stat actual;
                if (ml_owner_identity(target, &actual) != 0 || (stage >= 3 && ml_token(state, target) != 0) ||
                    unlinkat(target->directory_fd, "owner", 0) != 0) return -1;
                target->owner_unlinked = 1;
                if (fsync(target->directory_fd) != 0) return -1;
            }
            if (unlinkat(state->parents[target->parent_index].fd, target->leaf, AT_REMOVEDIR) != 0) return -1;
            target->directory_unlinked = 1;
            if (fsync(state->parents[target->parent_index].fd) != 0) return -1;
        } else if (target->birth_started || target->directory_fd >= 0 || target->owner_fd >= 0) return -1;
        if (ml_retire_fd(state, &target->owner_fd) != 0 || ml_retire_fd(state, &target->directory_fd) != 0) return -1;
    }
    for (size_t index = state->parent_count; index; --index) if (ml_retire_fd(state, &state->parents[index - 1].fd) != 0) return -1;
    return 0;
}
static void ml_release_execute(napi_env env, void *data) {
    (void)env; migration_legacy_locks *state = data;
    if (state->thread_started && !state->thread_joined) {
        if (uv_thread_join(&state->thread) != 0) { atomic_store(&state->retirement_failed, 1); return; }
        state->thread_joined = 1;
    }
    if (ml_cleanup(state) != 0) atomic_store(&state->retirement_failed, 1);
}
static void ml_release_complete(napi_env env, napi_status status, void *data) {
    migration_legacy_locks *state = data; napi_value result, original_receiver, original_promise;
    if (status != napi_ok) atomic_store(&state->retirement_failed, 1);
    /* This callback handle keeps the genuine receiver alive across deleting
     * its async reference and the subsequent result/error allocations. */
    int receiver_held = state->release_self && napi_get_reference_value(env, state->release_self, &original_receiver) == napi_ok;
    int promise_held = state->release_promise && napi_get_reference_value(env, state->release_promise, &original_promise) == napi_ok;
    if (!receiver_held || !promise_held) atomic_store(&state->retirement_failed, 1);
    if (napi_delete_async_work(env, state->release_work) != napi_ok) { migrate_scope_poison(state->scope); atomic_store(&state->retirement_failed, 1); }
    state->release_work = NULL;
    if (receiver_held && promise_held && state->release_self) {
        napi_ref reference = state->release_self; state->release_self = NULL;
        if (napi_delete_reference(env, reference) != napi_ok) { migrate_scope_poison(state->scope); atomic_store(&state->retirement_failed, 1); }
    }
    if (receiver_held && promise_held && state->release_promise) {
        napi_ref reference = state->release_promise; state->release_promise = NULL;
        if (napi_delete_reference(env, reference) != napi_ok) { migrate_scope_poison(state->scope); atomic_store(&state->retirement_failed, 1); }
    }
    if (!atomic_load(&state->retirement_failed)) state->released = 1;
    else migrate_scope_poison(state->scope);
    atomic_store(&state->retiring, 0);
    if (atomic_load(&state->retirement_failed)) {
        napi_value code, message;
        if (napi_create_string_utf8(env, "ERR_CLIQ_RESOURCE_RETIREMENT", NAPI_AUTO_LENGTH, &code) == napi_ok &&
            napi_create_string_utf8(env, "original Legacy heartbeat or lock resources did not really retire", NAPI_AUTO_LENGTH, &message) == napi_ok &&
            napi_create_error(env, code, message, &result) == napi_ok) napi_reject_deferred(env, state->release_deferred, result);
    } else if (napi_get_undefined(env, &result) == napi_ok) napi_resolve_deferred(env, state->release_deferred, result);
}
static napi_value ml_release_for_scope(napi_env env, napi_callback_info info, migration_filesystem *scope) {
    napi_value self; size_t count = 0, inspected = 0;
    if (count || napi_get_cb_info(env, info, &inspected, NULL, &self, NULL) != napi_ok || scope->retired || scope->uncertain)
        return migrate_scope_error(env, scope, "Legacy lock retirement requires its original live receiver and no arguments");
    migration_legacy_locks *state = scope->legacy_locks; napi_value promise, name;
    if (state && state->release_promise) return napi_get_reference_value(env, state->release_promise, &promise) == napi_ok ? promise : NULL;
    if (!state || state->released) {
        napi_deferred observed; napi_value result;
        if (napi_create_promise(env, &observed, &promise) != napi_ok || napi_get_undefined(env, &result) != napi_ok ||
            napi_resolve_deferred(env, observed, result) != napi_ok) return NULL;
        return promise; /* Observe the same completed physical join; no I/O repeats. */
    }
    atomic_store(&state->stop, 1);
    if (state->mutex_ready && state->condition_ready) { uv_mutex_lock(&state->wait_mutex); uv_cond_signal(&state->wait_condition); uv_mutex_unlock(&state->wait_mutex); }
    atomic_store(&state->retiring, 1);
    /* Close any discovery cursors on this main thread before worker cleanup;
     * closedir owns/consumes each enumeration FD exactly once. */
    while (state->walk_count) {
        ml_walk *walk = &state->walk[--state->walk_count]; DIR *directory = walk->directory; walk->directory = NULL; walk->fd = -1;
        if (directory && closedir(directory) != 0) { atomic_store(&state->retirement_failed, 1); migrate_scope_poison(scope); }
    }
    if (napi_create_promise(env, &state->release_deferred, &promise) != napi_ok || napi_create_reference(env, promise, 1, &state->release_promise) != napi_ok ||
        napi_create_reference(env, self, 1, &state->release_self) != napi_ok ||
        napi_create_string_utf8(env, "cliq-original-Legacy-lock-retirement", NAPI_AUTO_LENGTH, &name) != napi_ok ||
        napi_create_async_work(env, NULL, name, ml_release_execute, ml_release_complete, state, &state->release_work) != napi_ok ||
        napi_queue_async_work(env, state->release_work) != napi_ok) {
        atomic_store(&state->retirement_failed, 1); migrate_scope_poison(scope);
        return migrate_scope_error(env, scope, "original Legacy retirement task could not be joined; custody remains retained");
    }
    return promise;
}
static napi_value migrate_legacy_locks_release(napi_env env, napi_callback_info info) {
    napi_value ignored; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &ignored); if (!scope) return NULL;
    if (count) return migrate_scope_error(env, scope, "Legacy lock release accepts no arguments");
    return ml_release_for_scope(env, info, scope);
}
static int migrate_legacy_locks_can_retire(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    return !state || (state->released && !atomic_load(&state->retiring) && !atomic_load(&state->retirement_failed)) ? 0 : -1;
}
static void migrate_legacy_locks_free(migration_filesystem *scope) {
    migration_legacy_locks *state = scope->legacy_locks;
    if (!state || migrate_legacy_locks_can_retire(scope) != 0) return;
    ml_node *node = state->nodes;
    while (node) { ml_node *next = node->next; free(node->index); free(node); node = next; }
    if (state->condition_ready) uv_cond_destroy(&state->wait_condition);
    if (state->lease_mutex_ready) uv_mutex_destroy(&state->lease_mutex);
    if (state->mutex_ready) uv_mutex_destroy(&state->wait_mutex);
    free(state); scope->legacy_locks = NULL;
}
