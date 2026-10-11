/* The fixed selected keeper role owns only its native image and the original
 * delegated root pin. It never acquires StateOwner or transfers its root pin. */
#ifdef __linux__
#include <dirent.h>

#define INSTALLED_KEEPER_INVENTORY_LIMIT 4096
static atomic_int installed_keeper_started = 0;
static const napi_type_tag installed_keeper_tag = {0x793077eae7774bcbULL, 0x8f09b3310bd35de7ULL};

typedef struct {
    current_process_observation process;
    int root_pin, closed;
    struct stat root, leaf;
    uint64_t state_root_identity[5];
    char state_root[PATH_MAX], bundle[65], root_path[PATH_MAX], membership[PATH_MAX];
} installed_keeper;

static void installed_keeper_retire_directory(DIR **directory, int *retirement_failed) {
    DIR *owned = *directory; *directory = NULL;
    if (owned && closedir(owned) != 0) record_process_retirement_failure(retirement_failed);
}

static napi_value installed_keeper_error(napi_env env, const char *message, int retirement_failed) {
    if (retirement_failed || atomic_load(&current_process_retirement_failed)) {
        bool pending = false;
        napi_value discarded;
        if (napi_is_exception_pending(env, &pending) == napi_ok && pending)
            napi_get_and_clear_last_exception(env, &discarded);
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "installed keeper resources did not retire");
        return NULL;
    }
    return native_error(env, message);
}

static int installed_keeper_read(int directory, const char *name, char *value, size_t capacity,
    size_t *length, int *retirement_failed) {
    int file = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0) return 0;
    struct stat metadata;
    size_t used = 0;
    int valid = fstat(file, &metadata) == 0 && S_ISREG(metadata.st_mode);
    while (valid && used < capacity - 1) {
        ssize_t bytes = read(file, value + used, capacity - 1 - used);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) { valid = 0; break; }
        if (bytes == 0) break;
        used += (size_t)bytes;
    }
    if (valid && used == capacity - 1) {
        char extra;
        ssize_t bytes;
        do { bytes = read(file, &extra, 1); } while (bytes < 0 && errno == EINTR);
        if (bytes != 0) valid = 0;
    }
    /* Text controls cannot hide bytes behind a NUL; raw cmdline callers need
     * the measured binary length and validate every byte independently. */
    if (valid && !length && memchr(value, '\0', used)) valid = 0;
    retire_process_fd(&file, retirement_failed);
    value[used] = '\0';
    if (length) *length = used;
    return valid && !*retirement_failed;
}

/* Only the kernel's own self link selects the process; no PID is an input. */
static int installed_keeper_open_self(int *retirement_failed) {
    int proc = open("/proc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), process = -1;
    char name[32], self[32];
    struct statfs filesystem;
    int length = snprintf(name, sizeof(name), "%ld", (long)getpid());
    ssize_t bytes = proc < 0 ? -1 : readlinkat(proc, "self", self, sizeof(self) - 1);
    if (length > 0 && (size_t)length < sizeof(name) && bytes > 0 && (size_t)bytes < sizeof(self) - 1 &&
        fstatfs(proc, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC) {
        self[bytes] = '\0';
        if (strcmp(name, self) == 0) process = openat(proc, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    retire_process_fd(&proc, retirement_failed);
    if (process >= 0 && (fstatfs(process, &filesystem) != 0 || filesystem.f_type != PROC_SUPER_MAGIC))
        retire_process_fd(&process, retirement_failed);
    if (*retirement_failed) retire_process_fd(&process, retirement_failed);
    return process;
}

static int installed_keeper_credentials(int process, uid_t uid, gid_t gid, int *retirement_failed) {
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    if (uid == 0 || gid == 0 || getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid != uid || effective_uid != uid || saved_uid != uid ||
        real_gid != gid || effective_gid != gid || saved_gid != gid) return 0;
    char status[16384];
    if (!installed_keeper_read(process, "status", status, sizeof(status), NULL, retirement_failed)) return 0;
    int uid_matches = 0, gid_matches = 0;
    for (char *line = status; line && *line;) {
        char *next = strchr(line, '\n');
        if (next) *next++ = '\0';
        unsigned long first, effective, saved, filesystem_id;
        if (strncmp(line, "Uid:", 4) == 0 && sscanf(line + 4, "%lu %lu %lu %lu", &first, &effective, &saved, &filesystem_id) == 4)
            uid_matches = first == uid && effective == uid && saved == uid && filesystem_id == uid;
        if (strncmp(line, "Gid:", 4) == 0 && sscanf(line + 4, "%lu %lu %lu %lu", &first, &effective, &saved, &filesystem_id) == 4)
            gid_matches = first == gid && effective == gid && saved == gid && filesystem_id == gid;
        line = next;
    }
    return uid_matches && gid_matches;
}

static int installed_keeper_cmdline(int process, const char *target, const char *root, const char *bundle,
    const uint64_t identity[5], int *retirement_failed) {
    char actual[PATH_MAX * 2 + 256], locator[96];
    int count = snprintf(locator, sizeof(locator), "%llu:%llu:%llu", (unsigned long long)identity[0],
        (unsigned long long)identity[1], (unsigned long long)identity[2]);
    size_t length;
    if (count <= 0 || (size_t)count >= sizeof(locator) ||
        !installed_keeper_read(process, "cmdline", actual, sizeof(actual), &length, retirement_failed)) return 0;
    const char *arguments[] = {target, "--installed-keeper", root, bundle, locator};
    size_t offset = 0;
    for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); i++) {
        size_t bytes = strlen(arguments[i]) + 1;
        if (bytes > length - offset || memcmp(actual + offset, arguments[i], bytes) != 0) return 0;
        offset += bytes;
    }
    return offset == length;
}

/* An inherited O_PATH cgroup directory, even in stdio, could otherwise pass
 * for the original pin. This complete inventory precedes the only producer. */
static int installed_keeper_inventory(int process, int *retirement_failed) {
    int descriptor = openat(process, "fd", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *directory = descriptor < 0 ? NULL : fdopendir(descriptor);
    if (!directory) { retire_process_fd(&descriptor, retirement_failed); return 0; }
    descriptor = -1;
    unsigned int count = 0;
    int valid = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) valid = 0; break; }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char *end;
        errno = 0;
        unsigned long number = strtoul(entry->d_name, &end, 10);
        if (++count > INSTALLED_KEEPER_INVENTORY_LIMIT || errno || *end || !*entry->d_name || number > INT_MAX ||
            entry->d_name[0] < '0' || entry->d_name[0] > '9') { valid = 0; break; }
        int flags = fcntl((int)number, F_GETFL);
        if (flags < 0) { valid = 0; break; }
        if (flags & O_PATH) {
            struct stat metadata;
            struct statfs filesystem;
            if (fstat((int)number, &metadata) != 0 || fstatfs((int)number, &filesystem) != 0 ||
                (S_ISDIR(metadata.st_mode) && filesystem.f_type == CGROUP2_SUPER_MAGIC)) { valid = 0; break; }
        }
    }
    installed_keeper_retire_directory(&directory, retirement_failed);
    return valid && !*retirement_failed;
}

static int installed_keeper_cgroup_identity(int descriptor, uid_t uid, gid_t gid, struct stat *identity, int private) {
    struct statfs filesystem;
    return fstat(descriptor, identity) == 0 && S_ISDIR(identity->st_mode) && identity->st_uid == uid && identity->st_gid == gid &&
        ((identity->st_mode & 07777) == 0700 || (!private && (identity->st_mode & 07777) == 0755)) &&
        fstatfs(descriptor, &filesystem) == 0 && filesystem.f_type == CGROUP2_SUPER_MAGIC;
}

static int installed_keeper_same_directory(const struct stat *expected, const struct stat *actual) {
    return S_ISDIR(actual->st_mode) && same_inode(expected, actual) && expected->st_uid == actual->st_uid &&
        expected->st_gid == actual->st_gid && expected->st_mode == actual->st_mode;
}

static int installed_keeper_pin_current(installed_keeper *keeper) {
    struct stat actual;
    struct statfs filesystem;
    int flags = fcntl(keeper->root_pin, F_GETFL);
    return flags >= 0 && (flags & O_PATH) != 0 && fstat(keeper->root_pin, &actual) == 0 &&
        installed_keeper_same_directory(&keeper->root, &actual) &&
        fstatfs(keeper->root_pin, &filesystem) == 0 && filesystem.f_type == CGROUP2_SUPER_MAGIC;
}

static int installed_keeper_children(int root, const struct stat *keeper_leaf, int *retirement_failed) {
    int descriptor = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *directory = descriptor < 0 ? NULL : fdopendir(descriptor);
    if (!directory) { retire_process_fd(&descriptor, retirement_failed); return 0; }
    descriptor = -1;
    unsigned int count = 0;
    int valid = 1, saw_keeper = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) valid = 0; break; }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        struct stat metadata;
        if (++count > INSTALLED_KEEPER_INVENTORY_LIMIT || fstatat(dirfd(directory), entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
            valid = 0; break;
        }
        if (S_ISDIR(metadata.st_mode)) {
            if (!keeper_leaf || strcmp(entry->d_name, "keeper") != 0 ||
                !installed_keeper_same_directory(keeper_leaf, &metadata)) { valid = 0; break; }
            saw_keeper = 1;
        }
    }
    installed_keeper_retire_directory(&directory, retirement_failed);
    return valid && (!keeper_leaf || saw_keeper) && !*retirement_failed;
}

static int installed_keeper_domain(int root, int *retirement_failed) {
    char value[512];
    return installed_keeper_read(root, "cgroup.type", value, sizeof(value), NULL, retirement_failed) && strcmp(value, "domain\n") == 0;
}

static int installed_keeper_empty_subtree(int root, int *retirement_failed) {
    char value[512];
    if (!installed_keeper_read(root, "cgroup.subtree_control", value, sizeof(value), NULL, retirement_failed)) return 0;
    for (char *part = value; *part; part++) if (*part != ' ' && *part != '\t' && *part != '\n') return 0;
    return 1;
}

static int installed_keeper_processes(int root, pid_t pid, int *retirement_failed) {
    char value[512], expected[32];
    if (!installed_keeper_read(root, "cgroup.procs", value, sizeof(value), NULL, retirement_failed)) return 0;
    if (pid) {
        int length = snprintf(expected, sizeof(expected), "%ld\n", (long)pid);
        return length > 0 && (size_t)length < sizeof(expected) && strcmp(value, expected) == 0;
    }
    for (char *part = value; *part; part++) if (*part != ' ' && *part != '\t' && *part != '\n') return 0;
    return 1;
}

static int installed_keeper_controllers(int root, const char *name, int *retirement_failed) {
    char value[4096];
    if (!installed_keeper_read(root, name, value, sizeof(value), NULL, retirement_failed)) return 0;
    int controllers = 0;
    char *save;
    for (char *part = strtok_r(value, " \t\n", &save); part; part = strtok_r(NULL, " \t\n", &save)) {
        if (strcmp(part, "cpu") == 0) controllers |= 1;
        if (strcmp(part, "memory") == 0) controllers |= 2;
        if (strcmp(part, "pids") == 0) controllers |= 4;
    }
    return controllers == 7;
}

/* A control operation is exactly one complete write, never a short-write
 * continuation that the kernel could interpret as another PID or operation. */
static int installed_keeper_write(int root, const char *name, const char *value, int *retirement_failed) {
    int file = openat(root, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0) return 0;
    ssize_t bytes;
    size_t length = strlen(value);
    do { bytes = write(file, value, length); } while (bytes < 0 && errno == EINTR);
    retire_process_fd(&file, retirement_failed);
    return bytes == (ssize_t)length && !*retirement_failed;
}

static int installed_keeper_current(installed_keeper *keeper, int *retirement_failed) {
    if (keeper->closed || keeper->root_pin < 0 || current_process_is_held(&keeper->process) != 1) return 0;
    int process = installed_keeper_open_self(retirement_failed), state = -1, root = -1, leaf = -1;
    struct stat held, named;
    char membership[PATH_MAX + 8], expected[PATH_MAX + 8];
    int length = snprintf(expected, sizeof(expected), "0::%s\n", keeper->membership);
    int valid = process >= 0 && installed_keeper_credentials(process, keeper->process.uid, keeper->process.gid, retirement_failed) &&
        installed_keeper_cmdline(process, keeper->process.image_path, keeper->state_root, keeper->bundle,
            keeper->state_root_identity, retirement_failed) &&
        length > 0 && (size_t)length < sizeof(expected) &&
        installed_keeper_read(process, "cgroup", membership, sizeof(membership), NULL, retirement_failed) && strcmp(membership, expected) == 0;
    if (valid) state = open_root_with_retirement(keeper->state_root, retirement_failed);
    valid = valid && state >= 0 && fstat(state, &held) == 0 && installed_root_matches(&held, keeper->state_root_identity);
    if (valid) root = open_root_with_retirement(keeper->root_path, retirement_failed);
    valid = valid && root >= 0 && installed_keeper_cgroup_identity(root, keeper->process.uid, keeper->process.gid, &held, 1) &&
        installed_keeper_same_directory(&keeper->root, &held) &&
        installed_keeper_pin_current(keeper) &&
        installed_keeper_domain(root, retirement_failed) && installed_keeper_processes(root, 0, retirement_failed) &&
        installed_keeper_controllers(root, "cgroup.controllers", retirement_failed) &&
        installed_keeper_controllers(root, "cgroup.subtree_control", retirement_failed);
    if (valid) leaf = openat(keeper->root_pin, "keeper", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    valid = valid && leaf >= 0 && installed_keeper_cgroup_identity(leaf, keeper->process.uid, keeper->process.gid, &held, 1) &&
        installed_keeper_same_directory(&keeper->leaf, &held) &&
        fstatat(keeper->root_pin, "keeper", &named, AT_SYMLINK_NOFOLLOW) == 0 && installed_keeper_same_directory(&keeper->leaf, &named) &&
        installed_keeper_domain(leaf, retirement_failed) && installed_keeper_processes(leaf, keeper->process.pid, retirement_failed) &&
        installed_keeper_empty_subtree(leaf, retirement_failed) && installed_keeper_children(leaf, NULL, retirement_failed);
    retire_process_fd(&leaf, retirement_failed);
    retire_process_fd(&root, retirement_failed);
    retire_process_fd(&state, retirement_failed);
    retire_process_fd(&process, retirement_failed);
    return valid && !*retirement_failed && !atomic_load(&current_process_retirement_failed) &&
        current_process_is_held(&keeper->process) == 1 && installed_keeper_pin_current(keeper);
}

static int installed_keeper_close(installed_keeper *keeper) {
    keeper->closed = 1;
    int retired = close_current_process_image(&keeper->process);
    retire_process_fd(&keeper->root_pin, &keeper->process.retirement_failed);
    return retired && !keeper->process.retirement_failed && !atomic_load(&current_process_retirement_failed);
}

static void installed_keeper_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    installed_keeper *keeper = data;
    installed_keeper_close(keeper);
    free(keeper);
}

static napi_value installed_keeper_assert(napi_env env, napi_callback_info info) {
    installed_keeper *keeper = unwrap_control(env, info, &installed_keeper_tag, "invalid installed keeper handle");
    if (!keeper) return NULL;
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "installed keeper requires the process main thread");
    int retirement_failed = 0;
    if (!installed_keeper_current(keeper, &retirement_failed))
        return installed_keeper_error(env, "installed keeper image, original root, credentials, membership, or delegation changed", retirement_failed);
    return undefined_result(env);
}

/* Read only the kernel's fixed boot UUID, then retire every temporary before
 * constructing a locator. UUID bytes follow textual order, not UUID_LE. */
static int installed_keeper_boot(unsigned char uuid[16], int *retirement_failed) {
    int directory = open_root_with_retirement("/proc/sys/kernel/random", retirement_failed), file = -1;
    struct stat metadata;
    struct statfs filesystem;
    int valid = directory >= 0 && fstatfs(directory, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC;
    if (valid) file = openat(directory, "boot_id", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    valid = valid && file >= 0 && fstat(file, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
        fstatfs(file, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC;
    char text[37];
    size_t used = 0;
    while (valid && used < sizeof(text)) {
        ssize_t bytes = read(file, text + used, sizeof(text) - used);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes < 0) { valid = 0; break; }
        if (bytes == 0) break;
        used += (size_t)bytes;
    }
    if (valid && used == sizeof(text)) {
        char extra;
        ssize_t bytes;
        do { bytes = read(file, &extra, 1); } while (bytes < 0 && errno == EINTR);
        if (bytes != 0) valid = 0;
    }
    retire_process_fd(&file, retirement_failed);
    retire_process_fd(&directory, retirement_failed);
    if (!valid || *retirement_failed || used != sizeof(text) || text[36] != '\n') return 0;
    unsigned int digits = 0;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (text[i] != '-') return 0; continue; }
        int nibble = text[i] >= '0' && text[i] <= '9' ? text[i] - '0' :
            text[i] >= 'a' && text[i] <= 'f' ? text[i] - 'a' + 10 : -1;
        if (nibble < 0) return 0;
        if (digits % 2 == 0) uuid[digits / 2] = (unsigned char)(nibble << 4);
        else uuid[digits / 2] |= (unsigned char)nibble;
        digits++;
    }
    return digits == 32;
}

/* Private publication bytes locate a still-owned original pin; they never
 * transfer it or certify its authority to a consumer. No caller input. */
static napi_value installed_keeper_ready_locator(napi_env env, napi_callback_info info) {
    installed_keeper *keeper = unwrap_control(env, info, &installed_keeper_tag, "invalid installed keeper handle");
    if (!keeper) return NULL;
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "installed keeper requires the process main thread");
    int retirement_failed = 0;
    if (!installed_keeper_current(keeper, &retirement_failed))
        return installed_keeper_error(env, "installed keeper source is unavailable for publication", retirement_failed);
    uint64_t pid = (uint64_t)keeper->process.pid, descriptor = (uint64_t)keeper->root_pin, ticks = 0;
    const char prefix[] = "linux-proc-start-ticks:";
    const char *part = keeper->process.start_token;
    if (pid == 0 || pid > INT_MAX || descriptor < 3 || descriptor > INT_MAX ||
        strncmp(part, prefix, sizeof(prefix) - 1) != 0)
        return installed_keeper_error(env, "installed keeper source locator is invalid", retirement_failed);
    part += sizeof(prefix) - 1;
    if (*part < '1' || *part > '9')
        return installed_keeper_error(env, "installed keeper start ticks are invalid", retirement_failed);
    for (; *part; part++) {
        if (*part < '0' || *part > '9' || ticks > (UINT64_MAX - (uint64_t)(*part - '0')) / 10)
            return installed_keeper_error(env, "installed keeper start ticks are invalid", retirement_failed);
        ticks = ticks * 10 + (uint64_t)(*part - '0');
    }
    unsigned char locator[40];
    if (!installed_keeper_boot(locator + 24, &retirement_failed))
        return installed_keeper_error(env, "installed keeper actual boot identity is unavailable", retirement_failed);
    memcpy(locator, "cliq-ak1", 8);
    for (unsigned int i = 0; i < 4; i++) {
        locator[8 + i] = (unsigned char)(pid >> (8 * i));
        locator[12 + i] = (unsigned char)(descriptor >> (8 * i));
    }
    for (unsigned int i = 0; i < 8; i++) locator[16 + i] = (unsigned char)(ticks >> (8 * i));
    napi_value result;
    if (napi_create_buffer_copy(env, sizeof(locator), locator, NULL, &result) != napi_ok)
        return installed_keeper_error(env, "installed keeper locator buffer construction failed", retirement_failed);
    if (!installed_keeper_current(keeper, &retirement_failed))
        return installed_keeper_error(env, "installed keeper source changed during publication", retirement_failed);
    return result;
}

static napi_value installed_keeper_release(napi_env env, napi_callback_info info) {
    installed_keeper *keeper = unwrap_control(env, info, &installed_keeper_tag, "invalid installed keeper handle");
    if (!keeper) return NULL;
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "installed keeper requires the process main thread");
    if (!installed_keeper_close(keeper)) return installed_keeper_error(env, "installed keeper close failed", 1);
    return undefined_result(env);
}

static napi_value initialize_installed_keeper(napi_env env, napi_callback_info info) {
    if (atomic_load(&current_process_retirement_failed)) return installed_keeper_error(env, "installed keeper retirement failed", 1);
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "installed keeper requires the process main thread");
    if (geteuid() == 0 || getegid() == 0) return native_error(env, "installed keeper requires a nonroot process");
    /* The guard belongs to this loaded image, not a JS environment or handle.
     * Mark spent before any array getter; neither failure nor close resets it. */
    if (atomic_exchange(&installed_keeper_started, 1)) return native_error(env, "installed keeper initialization is already consumed");
    size_t argc = 6;
    napi_value args[6];
    char state_root[PATH_MAX], bundle[65], relative[PATH_MAX];
    installed_image_stat image_expected;
    uint64_t root_expected[5];
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 5 ||
        !installed_string(env, args[0], state_root, sizeof(state_root)) || !installed_path(state_root, 1) ||
        !installed_string(env, args[1], bundle, sizeof(bundle)) || strlen(bundle) != 64 || strspn(bundle, "0123456789abcdef") != 64 ||
        !installed_string(env, args[2], relative, sizeof(relative)) || !installed_path(relative, 0) ||
        !installed_stat_array(env, args[3], image_expected.field, 9, &image_expected.modified, &image_expected.changed) ||
        !installed_stat_array(env, args[4], root_expected, 5, NULL, NULL))
        return native_error(env, "invalid fixed installed keeper input");

    installed_keeper *keeper = calloc(1, sizeof(*keeper));
    if (!keeper) return native_error(env, "installed keeper allocation failed");
    keeper->root_pin = keeper->process.image_fd = -1;
    keeper->process.pid = getpid(); keeper->process.uid = geteuid(); keeper->process.gid = getegid();
    memcpy(keeper->state_root, state_root, strlen(state_root) + 1);
    memcpy(keeper->bundle, bundle, strlen(bundle) + 1);
    memcpy(keeper->state_root_identity, root_expected, sizeof(root_expected));
    int process = -1, state = -1, named_image = -1, root = -1, leaf = -1, retirement_failed = 0;
    char target[PATH_MAX], target_relative[PATH_MAX], membership[PATH_MAX + 8];
    struct stat held, named;
    const char *error = "installed keeper selected image or fixed role identity is unavailable";
    int length = snprintf(target_relative, sizeof(target_relative), "runtime/bundles/%s/%s", bundle, relative);
    if (length <= 0 || (size_t)length >= sizeof(target_relative)) goto fail;
    length = snprintf(target, sizeof(target), "%s/%s", state_root, target_relative);
    if (length <= 0 || (size_t)length >= sizeof(target)) goto fail;
    process = installed_keeper_open_self(&retirement_failed);
    if (process < 0 || !installed_keeper_credentials(process, keeper->process.uid, keeper->process.gid, &retirement_failed) ||
        !installed_keeper_cmdline(process, target, state_root, bundle, root_expected, &retirement_failed) ||
        observe_process_with_retirement(keeper->process.pid, keeper->process.start_token, &keeper->process.retirement_failed) != 1) goto fail;
    keeper->process.image_fd = open_process_image(keeper->process.pid, keeper->process.uid, keeper->process.gid,
        keeper->process.image_path, &keeper->process.image, &keeper->process.retirement_failed);
    if (keeper->process.image_fd < 0 || strcmp(keeper->process.image_path, target) != 0 ||
        !installed_executable(&keeper->process.image) || !installed_image_matches(&keeper->process.image, &image_expected) ||
        current_process_is_held(&keeper->process) != 1) goto fail;
    unsigned char elf[4];
    ssize_t bytes;
    do { bytes = pread(keeper->process.image_fd, elf, sizeof(elf), 0); } while (bytes < 0 && errno == EINTR);
    if (bytes != (ssize_t)sizeof(elf) || memcmp(elf, "\177ELF", sizeof(elf)) != 0) goto fail;
    error = "installed keeper StateRoot or held selected image identity changed";
    state = open_root_with_retirement(state_root, &retirement_failed);
    if (state < 0 || fstat(state, &held) != 0 || !installed_root_matches(&held, root_expected)) goto fail;
    named_image = installed_open_image(state, target_relative, &retirement_failed);
    if (named_image < 0 || fstat(named_image, &named) != 0 || !installed_image_matches(&named, &image_expected) ||
        !same_image(&named, &keeper->process.image)) goto fail;
    retire_process_fd(&named_image, &retirement_failed);
    retire_process_fd(&state, &retirement_failed);
    error = "installed keeper inherited cgroup path descriptors or incomplete descriptor inventory";
    if (retirement_failed || !installed_keeper_inventory(process, &retirement_failed)) goto fail;
    error = "installed keeper requires its own empty delegated service root";
    size_t membership_length;
    if (!installed_keeper_read(process, "cgroup", membership, sizeof(membership), &membership_length, &retirement_failed) ||
        membership_length < 5 || memchr(membership, '\0', membership_length) || strncmp(membership, "0::", 3) != 0 ||
        membership[membership_length - 1] != '\n') goto fail;
    membership[membership_length - 1] = '\0';
    const char *cgroup_path = membership + 3;
    const char *unit = strrchr(cgroup_path, '/');
    size_t unit_length = unit ? strlen(unit + 1) : 0;
    if (!installed_path(cgroup_path, 1) || strchr(cgroup_path, '\n') || strchr(cgroup_path, '\r') ||
        unit_length <= 8 || strcmp(unit + 1 + unit_length - 8, ".service") != 0) goto fail;
    for (const unsigned char *part = (const unsigned char *)cgroup_path; *part; part++)
        if (*part < 32 || *part == 127) goto fail;
    length = snprintf(keeper->root_path, sizeof(keeper->root_path), "/sys/fs/cgroup%s", cgroup_path);
    if (length <= 0 || (size_t)length >= sizeof(keeper->root_path)) goto fail;
    length = snprintf(keeper->membership, sizeof(keeper->membership), "%s/keeper", cgroup_path);
    if (length <= 0 || (size_t)length >= sizeof(keeper->membership)) goto fail;
    root = open_root_with_retirement(keeper->root_path, &retirement_failed);
    if (root < 0 || !installed_keeper_cgroup_identity(root, keeper->process.uid, keeper->process.gid, &keeper->root, 0) ||
        !installed_keeper_domain(root, &retirement_failed) || !installed_keeper_processes(root, keeper->process.pid, &retirement_failed) ||
        !installed_keeper_children(root, NULL, &retirement_failed) ||
        !installed_keeper_controllers(root, "cgroup.controllers", &retirement_failed) ||
        lstat(keeper->root_path, &named) != 0 || !installed_keeper_same_directory(&keeper->root, &named)) goto fail;
    /* This is the sole cgroup O_PATH producer for the entire keeper lifetime,
     * before chmod/mkdir/migration. All other cgroup descriptors are O_RDONLY. */
    keeper->root_pin = openat(root, ".", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (keeper->root_pin < 0 || !installed_keeper_pin_current(keeper)) goto fail;
    if (fchmod(root, 0700) != 0 || !installed_keeper_cgroup_identity(root, keeper->process.uid, keeper->process.gid, &held, 1) ||
        !same_inode(&held, &keeper->root) || held.st_uid != keeper->root.st_uid || held.st_gid != keeper->root.st_gid) goto fail;
    keeper->root = held;
    if (mkdirat(root, "keeper", 0700) != 0) goto fail;
    leaf = openat(root, "keeper", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (leaf < 0 || fchmod(leaf, 0700) != 0 ||
        !installed_keeper_cgroup_identity(leaf, keeper->process.uid, keeper->process.gid, &keeper->leaf, 1) ||
        fstatat(root, "keeper", &named, AT_SYMLINK_NOFOLLOW) != 0 || !installed_keeper_same_directory(&keeper->leaf, &named) ||
        !installed_keeper_domain(leaf, &retirement_failed) || !installed_keeper_processes(leaf, 0, &retirement_failed) ||
        !installed_keeper_empty_subtree(leaf, &retirement_failed) || !installed_keeper_children(leaf, NULL, &retirement_failed)) goto fail;
    char pid[32];
    length = snprintf(pid, sizeof(pid), "%ld\n", (long)keeper->process.pid);
    if (length <= 0 || (size_t)length >= sizeof(pid) ||
        !installed_keeper_write(leaf, "cgroup.procs", pid, &retirement_failed) ||
        !installed_keeper_processes(root, 0, &retirement_failed) || !installed_keeper_processes(leaf, keeper->process.pid, &retirement_failed) ||
        !installed_keeper_domain(root, &retirement_failed) || !installed_keeper_domain(leaf, &retirement_failed) ||
        !installed_keeper_write(root, "cgroup.subtree_control", "+cpu +memory +pids\n", &retirement_failed) ||
        !installed_keeper_controllers(root, "cgroup.subtree_control", &retirement_failed) ||
        !installed_keeper_children(root, &keeper->leaf, &retirement_failed)) goto fail;
    retire_process_fd(&leaf, &retirement_failed);
    retire_process_fd(&root, &retirement_failed);
    retire_process_fd(&process, &retirement_failed);
    error = "installed keeper image, original root, credentials, membership, or delegation changed during initialization";
    if (retirement_failed || !installed_keeper_current(keeper, &retirement_failed)) goto fail;
    napi_value result;
    const napi_property_descriptor methods[] = {
        {"assertHeld", NULL, installed_keeper_assert, NULL, NULL, NULL, napi_default, NULL},
        {"readyLocator", NULL, installed_keeper_ready_locator, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, installed_keeper_release, NULL, NULL, NULL, napi_default, NULL}
    };
    error = "installed keeper handle construction failed";
    if (napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, 3, methods) != napi_ok ||
        napi_type_tag_object(env, result, &installed_keeper_tag) != napi_ok || napi_object_freeze(env, result) != napi_ok ||
        atomic_load(&current_process_retirement_failed) ||
        napi_wrap(env, result, keeper, installed_keeper_finalize, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    retire_process_fd(&named_image, &retirement_failed);
    retire_process_fd(&leaf, &retirement_failed);
    retire_process_fd(&root, &retirement_failed);
    retire_process_fd(&state, &retirement_failed);
    retire_process_fd(&process, &retirement_failed);
    if (!installed_keeper_close(keeper)) retirement_failed = 1;
    free(keeper);
    return installed_keeper_error(env, error, retirement_failed);
}
#else
static napi_value initialize_installed_keeper(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "installed keeper requires Linux");
}
#endif
