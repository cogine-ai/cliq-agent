/* Fixed account-domain flock. No env/path/FD override or arbitrary filesystem
 * interface exists. This fences cooperating entrypoints, not old binaries or
 * other same-uid host writers. Included by the original StateOwner image. */
typedef struct kernel_global_gate {
    int home_fd, parent_fd, gate_fd, exclusive, retired, uncertain, finalized;
    struct stat home, parent, file;
    char home_path[PATH_MAX];
    napi_env env;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    pthread_t thread;
    uint64_t generation;
    unsigned int borrowers;
} kernel_global_gate;

typedef struct migration_credential_gate {
    kernel_global_gate *gate;
    state_lock *owner;
    napi_ref gate_reference, owner_reference;
    napi_env env;
    uint64_t gate_generation;
    unsigned int borrowers;
    int retired, uncertain;
} migration_credential_gate;

/* These are production-only guards. The separate descriptor-I/O conformance
 * adapter is not account-gate qualification and never supplies this type. */
typedef struct credential_global_guard {
    kernel_global_gate *owned_shared;
    migration_credential_gate *migration;
    napi_ref migration_reference;
} credential_global_guard;

static const napi_type_tag kernel_global_tag = {0x87d43e2ad92b106cULL, 0xa8b6fc14572103d9ULL};
static const napi_type_tag migration_credential_tag = {0xc23914a8df60e327ULL, 0xbb158e7694a1302cULL};
static atomic_int kernel_global_poisoned;
static uint64_t kernel_global_generation;

static int kernel_global_main_thread(void) {
#ifdef __linux__
    return syscall(SYS_gettid) == getpid();
#else
    return pthread_main_np();
#endif
}
static int kernel_global_context(const kernel_global_gate *gate, napi_env env) {
    return kernel_global_main_thread() && gate && gate->env == env &&
        gate->pid == getpid() && pthread_equal(gate->thread, pthread_self()) &&
        gate->uid == getuid() && gate->uid == geteuid() &&
        gate->gid == getgid() && gate->gid == getegid();
}
static int kernel_global_close_fd(kernel_global_gate *gate, int *fd) {
    int original = *fd;
    *fd = -1;
    if (original < 0 || close(original) == 0) return 0;
    gate->uncertain = 1;
    atomic_store(&kernel_global_poisoned, 1);
    return -1;
}
static int kernel_global_account_home(char output[PATH_MAX], uid_t uid) {
    /* A bounded actual NSS lookup; a huge/ambiguous record is unsupported.
     * HOME/CLIQ_HOME remain entirely irrelevant to the lock domain. */
    struct passwd account, *found = NULL;
    char buffer[65536];
    if (getpwuid_r(uid, &account, buffer, sizeof(buffer), &found) != 0 ||
        !found || found->pw_uid != uid || !found->pw_dir ||
        found->pw_dir[0] != '/' || found->pw_dir[1] == '\0' ||
        strlen(found->pw_dir) >= PATH_MAX) return -1;
    memcpy(output, found->pw_dir, strlen(found->pw_dir) + 1);
    return 0;
}
static int kernel_global_walk(kernel_global_gate *gate, const char *path) {
    int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) return -1;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (!size || size > NAME_MAX || (size == 1 && *part == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.') ||
            (end && !end[1])) {
            kernel_global_close_fd(gate, &current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, size); name[size] = '\0';
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int failure = errno;
        if (kernel_global_close_fd(gate, &current) != 0) {
            kernel_global_close_fd(gate, &next); return -1;
        }
        if (next < 0) { errno = failure; return -1; }
        current = next;
        if (!end) break;
        part = end + 1;
    }
    return current;
}
static int kernel_global_directory(const kernel_global_gate *gate, const struct stat *info) {
    /* Legacy .cliq can be 0755. No incidental chmod of source data. */
    return S_ISDIR(info->st_mode) && info->st_uid == gate->uid &&
        (info->st_mode & 07000) == 0 && (info->st_mode & 0022) == 0;
}
static int kernel_global_file(const kernel_global_gate *gate, const struct stat *info) {
    return S_ISREG(info->st_mode) && info->st_uid == gate->uid &&
        (info->st_mode & 07777) == 0600 && info->st_nlink == 1;
}
static int kernel_global_check(kernel_global_gate *gate, napi_env env) {
    if (!kernel_global_context(gate, env) || gate->retired || gate->uncertain ||
        gate->gate_fd < 0 || atomic_load(&kernel_global_poisoned)) return -1;
    char current_home[PATH_MAX];
    struct stat home, parent, file, named;
    if (kernel_global_account_home(current_home, gate->uid) != 0 ||
        strcmp(current_home, gate->home_path) != 0) goto changed;
    int visible = kernel_global_walk(gate, current_home);
    if (visible < 0) goto changed;
    int valid = fstat(visible, &named) == 0 && same_inode(&named, &gate->home);
    if (kernel_global_close_fd(gate, &visible) != 0) return -1;
    if (valid && fstat(gate->home_fd, &home) == 0 &&
        kernel_global_directory(gate, &home) && same_inode(&home, &gate->home) &&
        fstat(gate->parent_fd, &parent) == 0 && kernel_global_directory(gate, &parent) &&
        same_inode(&parent, &gate->parent) &&
        fstatat(gate->home_fd, ".cliq", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        kernel_global_directory(gate, &named) && same_inode(&named, &parent) &&
        fstat(gate->gate_fd, &file) == 0 && kernel_global_file(gate, &file) &&
        same_inode(&file, &gate->file) &&
        fstatat(gate->parent_fd, "kernel-global-v1.lock", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        kernel_global_file(gate, &named) && same_inode(&named, &file)) return 0;
changed:
    gate->uncertain = 1;
    atomic_store(&kernel_global_poisoned, 1);
    return -1;
}
static int kernel_global_retire(kernel_global_gate *gate) {
    if (gate->uncertain || gate->borrowers) return -1;
    if (kernel_global_close_fd(gate, &gate->gate_fd) != 0 ||
        kernel_global_close_fd(gate, &gate->parent_fd) != 0 ||
        kernel_global_close_fd(gate, &gate->home_fd) != 0) return -1;
    gate->retired = 1;
    return 0;
}
static void kernel_global_free(kernel_global_gate *gate) {
    if (gate->finalized && gate->retired && !gate->uncertain && !gate->borrowers) free(gate);
}
static napi_value kernel_global_error(napi_env env, const char *code, const char *message) {
    napi_throw_error(env, code, message); return NULL;
}
/* Result 1=held, 0=exact absent on read-only inspection, -1=refused.
 * A failed physical close retains the remaining original custody forever. */
static int kernel_global_acquire(napi_env env, int create, int exclusive,
                                 kernel_global_gate **output, const char **code) {
    *output = NULL;
    *code = "ERR_CLIQ_KERNEL_GLOBAL_GATE";
    if (!kernel_global_main_thread() || getuid() != geteuid() || getgid() != getegid()) return -1;
    if (atomic_load(&kernel_global_poisoned) || kernel_global_generation == UINT64_MAX) {
        *code = "ERR_CLIQ_RESOURCE_RETIREMENT"; return -1;
    }
    kernel_global_gate *gate = calloc(1, sizeof(*gate));
    if (!gate) return -1;
    gate->home_fd = gate->parent_fd = gate->gate_fd = -1;
    gate->env = env; gate->pid = getpid(); gate->uid = geteuid(); gate->gid = getegid();
    gate->thread = pthread_self(); gate->exclusive = exclusive;
    gate->generation = ++kernel_global_generation;
    int absent = 0, parent_created = 0, file_created = 0;
    if (kernel_global_account_home(gate->home_path, gate->uid) != 0) goto failed;
    gate->home_fd = kernel_global_walk(gate, gate->home_path);
    if (gate->home_fd < 0 || fstat(gate->home_fd, &gate->home) != 0 ||
        !kernel_global_directory(gate, &gate->home)) goto failed;
    if (create) {
        parent_created = mkdirat(gate->home_fd, ".cliq", 0700) == 0;
        if (!parent_created && errno != EEXIST) goto failed;
    }
    gate->parent_fd = openat(gate->home_fd, ".cliq", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (gate->parent_fd < 0) { absent = !create && errno == ENOENT; goto failed; }
    if (fstat(gate->parent_fd, &gate->parent) != 0 ||
        !kernel_global_directory(gate, &gate->parent)) goto failed;
    if (create) {
        gate->gate_fd = openat(gate->parent_fd, "kernel-global-v1.lock",
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
        file_created = gate->gate_fd >= 0;
        if (gate->gate_fd < 0 && errno == EEXIST)
            gate->gate_fd = openat(gate->parent_fd, "kernel-global-v1.lock",
                O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    } else {
        gate->gate_fd = openat(gate->parent_fd, "kernel-global-v1.lock",
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    }
    if (gate->gate_fd < 0) { absent = !create && errno == ENOENT; goto failed; }
    if (fstat(gate->gate_fd, &gate->file) != 0 || !kernel_global_file(gate, &gate->file)) goto failed;
    int status;
    do { status = flock(gate->gate_fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB); }
    while (status < 0 && errno == EINTR);
    if (status != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EACCES)
            *code = "ERR_CLIQ_KERNEL_GLOBAL_BUSY";
        goto failed;
    }
    if (kernel_global_check(gate, env) != 0 ||
        (file_created && (fsync(gate->gate_fd) != 0 || fsync(gate->parent_fd) != 0)) ||
        (parent_created && (fsync(gate->parent_fd) != 0 || fsync(gate->home_fd) != 0))) goto failed;
    *output = gate;
    return 1;
failed:
    if (kernel_global_retire(gate) != 0) {
        *code = "ERR_CLIQ_RESOURCE_RETIREMENT"; return -1;
    }
    free(gate);
    return absent ? 0 : -1;
}
static kernel_global_gate *kernel_global_receiver(napi_env env, napi_callback_info info) {
    size_t count = 1;
    napi_value self, argument;
    bool tagged = false;
    kernel_global_gate *gate = NULL;
    if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
        napi_check_object_type_tag(env, self, &kernel_global_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&gate) != napi_ok || !kernel_global_context(gate, env)) {
        kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "invalid original account gate or context"); return NULL;
    }
    return gate;
}
static napi_value kernel_global_assert(napi_env env, napi_callback_info info) {
    kernel_global_gate *gate = kernel_global_receiver(env, info);
    if (!gate) return NULL;
    if (kernel_global_check(gate, env) != 0)
        return kernel_global_error(env, gate->uncertain || atomic_load(&kernel_global_poisoned) ? "ERR_CLIQ_RESOURCE_RETIREMENT" : "ERR_CLIQ_KERNEL_GLOBAL_GATE",
            "account gate identity changed, closed or uncertain");
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value kernel_global_close(napi_env env, napi_callback_info info) {
    kernel_global_gate *gate = kernel_global_receiver(env, info);
    if (!gate) return NULL;
    if (gate->borrowers || gate->uncertain)
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "account gate has live or uncertain original borrowers");
    if (!gate->retired && (kernel_global_check(gate, env) != 0 || kernel_global_retire(gate) != 0))
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "account gate did not retire; original custody retained");
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void kernel_global_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    kernel_global_gate *gate = data;
    if (!kernel_global_context(gate, env) || gate->borrowers || gate->uncertain) return;
    gate->finalized = 1;
    if (gate->retired || (kernel_global_check(gate, env) == 0 && kernel_global_retire(gate) == 0)) kernel_global_free(gate);
}
static napi_value kernel_global_factory(napi_env env, napi_callback_info info, int create, int exclusive) {
    size_t count = 1; napi_value argument;
    if (napi_get_cb_info(env, info, &count, &argument, NULL, NULL) != napi_ok || count)
        return kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "account gate accepts no locator or arguments");
    kernel_global_gate *gate; const char *code;
    int status = kernel_global_acquire(env, create, exclusive, &gate, &code);
    if (status < 0) return kernel_global_error(env, code, "fixed account gate acquisition refused");
    napi_value result;
    if (!status) return napi_get_null(env, &result) == napi_ok ? result : NULL;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, kernel_global_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, kernel_global_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok ||
        napi_type_tag_object(env, result, &kernel_global_tag) != napi_ok ||
        napi_define_properties(env, result, 2, methods) != napi_ok ||
        napi_wrap(env, result, gate, kernel_global_finalize, NULL, NULL) != napi_ok) {
        int retired = kernel_global_retire(gate) == 0;
        if (retired) free(gate);
        return kernel_global_error(env, retired ? "ERR_CLIQ_KERNEL_GLOBAL_GATE" : "ERR_CLIQ_RESOURCE_RETIREMENT",
            "account gate construction or retirement failed");
    }
    return result;
}
static napi_value inspect_kernel_global_gate(napi_env env, napi_callback_info info) { return kernel_global_factory(env, info, 0, 0); }
static napi_value acquire_kernel_global_shared(napi_env env, napi_callback_info info) { return kernel_global_factory(env, info, 1, 0); }
static napi_value acquire_kernel_global_exclusive(napi_env env, napi_callback_info info) { return kernel_global_factory(env, info, 1, 1); }

static int migration_credential_check(migration_credential_gate *bound, napi_env env) {
    if (!kernel_global_main_thread() || !bound || bound->env != env || bound->retired || bound->uncertain) return -1;
    kernel_global_gate *gate = bound->gate;
    state_lock *owner = bound->owner;
    int retirement_failed = 0;
    if (!gate || !owner || !gate->exclusive || bound->gate_generation != gate->generation ||
        !gate->borrowers || !owner->migration_bindings || owner->migration_retirement_error ||
        owner->owner_env != env || owner->owner_pid != getpid() ||
        owner->owner_uid != gate->uid || owner->owner_gid != gate->gid ||
        !pthread_equal(owner->owner_thread, pthread_self()) ||
        kernel_global_check(gate, env) != 0 ||
        !lock_is_held_with_retirement(owner, &retirement_failed) || retirement_failed) {
        bound->uncertain = 1;
        if (owner) owner->migration_retirement_error = 1;
        return -1;
    }
    return 0;
}
static int migration_credential_retire(migration_credential_gate *bound, napi_env env) {
    if (bound->retired) return 0;
    if (bound->borrowers || migration_credential_check(bound, env) != 0) return -1;
    /* No LOCK_UN or close of either parent descriptor. Removing references is
     * not counted as success unless both original references actually retire. */
    napi_ref gate_reference = bound->gate_reference, owner_reference = bound->owner_reference;
    bound->gate_reference = bound->owner_reference = NULL;
    if (napi_delete_reference(env, gate_reference) != napi_ok || napi_delete_reference(env, owner_reference) != napi_ok) {
        bound->uncertain = 1; bound->owner->migration_retirement_error = 1; return -1;
    }
    bound->gate->borrowers--; bound->owner->migration_bindings--;
    bound->retired = 1;
    return 0;
}
static migration_credential_gate *migration_credential_receiver(napi_env env, napi_callback_info info) {
    size_t count = 1; napi_value self, argument; bool tagged = false;
    migration_credential_gate *bound = NULL;
    if (napi_get_cb_info(env, info, &count, &argument, &self, NULL) != napi_ok || count ||
        napi_check_object_type_tag(env, self, &migration_credential_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, (void **)&bound) != napi_ok || !bound || bound->env != env || !kernel_global_main_thread()) {
        kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "invalid original migration credential binding"); return NULL;
    }
    return bound;
}
static napi_value migration_credential_assert(napi_env env, napi_callback_info info) {
    migration_credential_gate *bound = migration_credential_receiver(env, info);
    if (!bound) return NULL;
    if (migration_credential_check(bound, env) != 0)
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "migration credential parents changed or retired");
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static napi_value migration_credential_close(napi_env env, napi_callback_info info) {
    migration_credential_gate *bound = migration_credential_receiver(env, info);
    if (!bound) return NULL;
    if (migration_credential_retire(bound, env) != 0)
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "migration credential borrowers did not retire");
    napi_value result; return napi_get_undefined(env, &result) == napi_ok ? result : NULL;
}
static void migration_credential_finalize(napi_env env, void *data, void *hint) {
    (void)hint;
    migration_credential_gate *bound = data;
    if (migration_credential_retire(bound, env) == 0) free(bound);
}
static napi_value bind_migration_credential_gate(napi_env env, napi_callback_info info) {
    size_t count = 3; napi_value arguments[3]; bool tagged = false;
    state_lock *owner = NULL; kernel_global_gate *gate = NULL;
    int retirement_failed = 0;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 2 ||
        napi_check_object_type_tag(env, arguments[0], &lock_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&owner) != napi_ok || !owner ||
        napi_check_object_type_tag(env, arguments[1], &kernel_global_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[1], (void **)&gate) != napi_ok || !gate || !gate->exclusive ||
        owner->owner_env != env || owner->owner_pid != getpid() ||
        owner->owner_uid != gate->uid || owner->owner_gid != gate->gid ||
        !pthread_equal(owner->owner_thread, pthread_self()) ||
        owner->migration_retirement_error || !lock_is_held_with_retirement(owner, &retirement_failed) ||
        retirement_failed || kernel_global_check(gate, env) != 0 ||
        owner->migration_bindings == UINT_MAX || gate->borrowers == UINT_MAX) {
        if (owner && retirement_failed) {
            owner->migration_retirement_error = 1;
            return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "migration StateOwner check did not retire");
        }
        return kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "exclusive credential binding requires original same-account StateOwner and gate");
    }
    migration_credential_gate *bound = calloc(1, sizeof(*bound));
    if (!bound) return kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "migration credential allocation failed");
    bound->gate = gate; bound->owner = owner; bound->env = env; bound->gate_generation = gate->generation;
    if (napi_create_reference(env, arguments[0], 1, &bound->owner_reference) != napi_ok ||
        napi_create_reference(env, arguments[1], 1, &bound->gate_reference) != napi_ok) {
        /* Retain on uncertain reference construction; never close parents. */
        owner->migration_retirement_error = 1; bound->uncertain = 1;
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "migration credential parent retention failed");
    }
    owner->migration_bindings++; gate->borrowers++;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, migration_credential_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, migration_credential_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok ||
        napi_type_tag_object(env, result, &migration_credential_tag) != napi_ok ||
        napi_define_properties(env, result, 2, methods) != napi_ok ||
        napi_wrap(env, result, bound, migration_credential_finalize, NULL, NULL) != napi_ok) {
        int retired = migration_credential_retire(bound, env) == 0;
        if (retired) free(bound);
        return kernel_global_error(env, retired ? "ERR_CLIQ_KERNEL_GLOBAL_GATE" : "ERR_CLIQ_RESOURCE_RETIREMENT",
            "migration credential construction or retirement failed");
    }
    return result;
}
