/* A private Linux process/descriptor observation while the original migration
 * scope holds the account EX and its actual Legacy directory. No process,
 * pathname or UID is supplied by a caller. The scan retires every descriptor
 * before publishing its data result. This is only one part of quiescence:
 * package classification and the original Legacy locks are separate checks. */
#ifndef CLIQ_MIGRATION_PROCESS_QUIESCENCE_H
#define CLIQ_MIGRATION_PROCESS_QUIESCENCE_H
#ifdef __linux__
#include <sys/sysmacros.h>

#define MQ_PROCESSES 32768U
#define MQ_SAME_UID 4096U
#define MQ_FDS 65536U
#define MQ_SCAN_PAGE 32U
#define MQ_ARGV_BYTES (128U * 1024U)
#define MQ_MOUNT_BYTES (512U * 1024U)
#define MQ_PACKAGE_BYTES (128U * 1024U)
#define MQ_ENTRY_BYTES (1024U * 1024U)

enum mq_result { MQ_UNAVAILABLE = -1, MQ_MORE = 0, MQ_COMPLETE = 1, MQ_LEGACY_OPEN = 2, MQ_PACKAGE = 3 };
typedef struct { pid_t pid; char digest[65]; } mq_member;
typedef struct migration_process_cut {
    int proc, process, directory_fd, package_pending, package_managed;
    DIR *processes, *descriptors;
    struct stat proc_info, process_info, executable, mount_namespace, original_image, process_root;
    char legacy[PATH_MAX], kernel[PATH_MAX], executable_path[PATH_MAX], working[PATH_MAX], process_name[32], start[128];
    char command[MQ_ARGV_BYTES + 1];
    char command_digest[65], mount_digest[65];
    char package_digest[65], entry_digest[65];
    mq_member members[MQ_SAME_UID];
    size_t member_count;
    pid_t pid;
    size_t process_count, own_count, fd_count, command_length;
    int owned_role, unclassified_package;
} migration_process_cut;
static inline int mq_canonical(const char *path) {
    if (path[0] != '/' || !utf8_valid((const unsigned char *)path) || strchr(path, '\\')) return 0;
    for (const char *part = path + 1; *part;) {
        const char *next = strchr(part, '/');
        size_t size = next ? (size_t)(next - part) : strlen(part);
        if (!size || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.') || (next && !next[1])) return 0;
        if (!next) return 1;
        part = next + 1;
    }
    return path[1] == '\0';
}

static inline int mq_read_link(int fd, const char *leaf, char *value, size_t size) {
    ssize_t length = readlinkat(fd, leaf, value, size - 1);
    if (length <= 0 || (size_t)length >= size - 1) return -1;
    value[length] = 0;
    return 0;
}
static inline int mq_named_fd(int fd, char value[PATH_MAX]) {
    char leaf[48];
    int length = snprintf(leaf, sizeof(leaf), "/proc/self/fd/%d", fd);
    return length <= 0 || (size_t)length >= sizeof(leaf) ? -1 : mq_read_link(AT_FDCWD, leaf, value, PATH_MAX);
}
static inline int mq_under(const char *root, const char *path) {
    size_t length = strlen(root);
    return !strncmp(root, path, length) && (path[length] == '\0' || path[length] == '/' || !strcmp(path + length, " (deleted)"));
}
static inline int mq_number(const char *text, unsigned long limit, unsigned long *number) {
    if (!*text || (*text == '0' && text[1])) return 0;
    unsigned long value = 0;
    for (const char *digit = text; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' || value > (limit - (unsigned long)(*digit - '0')) / 10) return 0;
        value = value * 10 + (unsigned long)(*digit - '0');
    }
    *number = value;
    return 1;
}
static inline int mq_procfs(int fd, const struct stat *original) {
    struct stat actual;
    struct statfs filesystem;
    return fstat(fd, &actual) == 0 && actual.st_dev == original->st_dev &&
        fstatfs(fd, &filesystem) == 0 && filesystem.f_type == PROC_SUPER_MAGIC;
}
static inline int mq_close_dir(migration_filesystem *scope, DIR **directory) {
    DIR *original = *directory; *directory = NULL;
    if (!original || closedir(original) == 0) return 0;
    migrate_scope_poison(scope); return -1;
}
static inline int mq_retire_process(migration_filesystem *scope, migration_process_cut *cut) {
    int failed = mq_close_dir(scope, &cut->descriptors) != 0;
    if (migrate_scope_close_fd(scope, &cut->process) != 0) failed = 1;
    cut->directory_fd = -1; cut->package_pending = 0;
    cut->package_managed = 0;
    explicit_bzero(cut->command, sizeof(cut->command)); cut->command_length = 0;
    return failed ? -1 : 0;
}
static inline int mq_retire(migration_filesystem *scope, migration_process_cut *cut) {
    if (!cut) return 0;
    int failed = mq_retire_process(scope, cut) != 0;
    if (mq_close_dir(scope, &cut->processes) != 0) failed = 1;
    if (migrate_scope_close_fd(scope, &cut->proc) != 0) failed = 1;
    if (failed || scope->uncertain) return -1;
    free(cut); return 0;
}

/* Linux exposes the other process's FD links in its mount namespace. Only the
 * exact same visible namespace and one unaliased source filesystem mount can
 * turn those physical link targets into an all-and-only descendant check.
 * Known nonzero hidepid or a restricted proc mount cannot establish a census. */
static inline int mq_mounts(migration_filesystem *scope, int self, char digest[65]) {
    char *bytes = malloc(MQ_MOUNT_BYTES + 1);
    if (!bytes) return 0;
    int retirement = 0, valid = installed_keeper_read(self, "mountinfo", bytes, MQ_MOUNT_BYTES + 1, NULL, &retirement);
    if (retirement) migrate_scope_poison(scope);
    if (!valid) { free(bytes); return 0; }
    struct sha256_context hash;
    sha256_init(&hash); sha256_update(&hash, (const unsigned char *)bytes, strlen(bytes)); publication_hash_hex(&hash, digest);
    unsigned int source_mounts = 0, proc_mounts = 0;
    const unsigned int source_major = major(scope->legacy.st_dev), source_minor = minor(scope->legacy.st_dev);
    for (char *line = bytes, *end; *line; line = end + 1) {
        end = strchr(line, '\n');
        if (!end) { valid = 0; break; }
        *end = '\0';
        char *separator = strstr(line, " - ");
        if (!separator) { valid = 0; break; }
        *separator = '\0';
        unsigned int major_id, minor_id;
        char root[PATH_MAX], mountpoint[PATH_MAX], flags[4096], filesystem[128], source[PATH_MAX], options[4096];
        if (sscanf(line, "%*u %*u %u:%u %4095s %4095s %4095s", &major_id, &minor_id, root, mountpoint, flags) != 5 ||
            sscanf(separator + 3, "%127s %4095s %4095s", filesystem, source, options) != 3) { valid = 0; break; }
        if (major_id == source_major && minor_id == source_minor) {
            if (++source_mounts != 1 || strcmp(root, "/") || strchr(mountpoint, '\\') ||
                (strcmp(mountpoint, "/") && !mq_under(mountpoint, scope->legacy_path))) { valid = 0; break; }
        }
        if (!strcmp(mountpoint, "/proc")) {
            if (++proc_mounts != 1 || strcmp(filesystem, "proc") || strcmp(root, "/") ||
                strstr(flags, "hidepid=") || strstr(options, "hidepid=") ||
                strstr(flags, "subset=") || strstr(options, "subset=")) { valid = 0; break; }
        }
    }
    free(bytes);
    return valid && source_mounts == 1 && proc_mounts == 1;
}
static inline int mq_open(migration_filesystem *scope, migration_process_cut **output) {
    migration_process_cut *cut = calloc(1, sizeof(*cut));
    if (!cut) return -1;
    *output = cut; cut->proc = cut->process = cut->directory_fd = -1;
    cut->proc = open("/proc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cut->proc < 0 || fstat(cut->proc, &cut->proc_info) != 0 || !mq_procfs(cut->proc, &cut->proc_info) ||
        mq_named_fd(scope->legacy_fd, cut->legacy) != 0 || strcmp(cut->legacy, scope->legacy_path) ||
        mq_named_fd(scope->binding->owner->root_fd, cut->kernel) != 0 || !mq_canonical(cut->kernel)) return -1;
    int retirement = 0, self = installed_keeper_open_self(&retirement);
    if (retirement) migrate_scope_poison(scope);
    int valid = self >= 0 && mq_procfs(self, &cut->proc_info) &&
        fstatat(self, "ns/mnt", &cut->mount_namespace, 0) == 0 &&
        fstatat(self, "exe", &cut->original_image, 0) == 0 && S_ISREG(cut->original_image.st_mode) &&
        fstatat(self, "root", &cut->process_root, 0) == 0 && S_ISDIR(cut->process_root.st_mode) &&
        mq_mounts(scope, self, cut->mount_digest);
    if (migrate_scope_close_fd(scope, &self) != 0 || !valid) return -1;
    int descriptor = openat(cut->proc, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || !mq_procfs(descriptor, &cut->proc_info) || !(cut->processes = fdopendir(descriptor))) {
        migrate_scope_close_fd(scope, &descriptor); return -1;
    }
    return 0;
}
static inline int mq_same_uid(migration_filesystem *scope, int process) {
    char status[32768]; int retirement = 0;
    if (!installed_keeper_read(process, "status", status, sizeof(status), NULL, &retirement)) {
        if (retirement) migrate_scope_poison(scope);
        return -1;
    }
    char *field = strstr(status, "\nUid:\t"); unsigned long uid[4];
    if (!field || sscanf(field + 6, "%lu %lu %lu %lu", &uid[0], &uid[1], &uid[2], &uid[3]) != 4) return -1;
    unsigned int matches = 0;
    for (size_t index = 0; index < 4; ++index) if (uid[index] == geteuid()) matches++;
    return matches == 4 ? 1 : matches == 0 ? 0 : -1;
}
static inline int mq_origin_current(migration_filesystem *scope, migration_process_cut *cut) {
    struct stat named, held, image, mount, root;
    char token[128]; int retirement = 0;
    int observed = observe_process_with_retirement(cut->pid, token, &retirement);
    if (retirement) migrate_scope_poison(scope);
    return observed == 1 && !strcmp(token, cut->start) && !scope->uncertain &&
        fstat(cut->process, &held) == 0 && same_inode(&held, &cut->process_info) &&
        fstatat(cut->proc, cut->process_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&held, &named) &&
        fstatat(cut->process, "exe", &image, 0) == 0 && source_metadata_same(&image, &cut->executable) &&
        fstatat(cut->process, "ns/mnt", &mount, 0) == 0 && same_inode(&mount, &cut->mount_namespace) &&
        fstatat(cut->process, "root", &root, 0) == 0 && same_inode(&root, &cut->process_root);
}
static inline int mq_protected_path(const migration_process_cut *cut, const char *name) {
    return mq_under(cut->legacy, name) && !mq_under(cut->kernel, name);
}
/* Return a distinct original busy classification only for a live physical
 * descriptor identity. Unknown, truncated, or unrelated-looking races cannot
 * be reported as proven clear. The producer's own held Legacy descriptors
 * are excluded through its original role and exact descriptor inventory. */
static inline int mq_descriptor(migration_filesystem *scope, migration_process_cut *cut, const char *leaf,
                                int (*own_descriptor)(migration_filesystem *, unsigned long, const struct stat *)) {
    unsigned long number;
    if (!mq_number(leaf, INT_MAX, &number) || ++cut->fd_count > MQ_FDS) return MQ_UNAVAILABLE;
    struct stat named;
    char path[PATH_MAX];
    if (mq_read_link(cut->directory_fd, leaf, path, sizeof(path)) != 0 || fstatat(cut->directory_fd, leaf, &named, 0) != 0)
        return MQ_UNAVAILABLE;
    if (path[0] != '/') {
        if ((S_ISSOCK(named.st_mode) && !strncmp(path, "socket:[", 8)) ||
            (S_ISFIFO(named.st_mode) && !strncmp(path, "pipe:[", 6)) || !strncmp(path, "anon_inode:[", 12))
            return MQ_MORE;
        return MQ_UNAVAILABLE;
    }
    char repeated[PATH_MAX];
    if (mq_read_link(cut->directory_fd, leaf, repeated, sizeof(repeated)) != 0 || strcmp(path, repeated)) return MQ_UNAVAILABLE;
    if (!mq_protected_path(cut, path) && !same_inode(&named, &scope->legacy)) return MQ_MORE;
    if (cut->pid == getpid() && own_descriptor(scope, number, &named)) return MQ_MORE;
    return MQ_LEGACY_OPEN;
}
static inline int mq_command(migration_filesystem *scope, migration_process_cut *cut, char digest[65]) {
    int retirement = 0;
    size_t length = 0;
    int valid = installed_keeper_read(cut->process, "cmdline", cut->command, sizeof(cut->command), &length, &retirement);
    if (retirement) migrate_scope_poison(scope);
    if (!valid || !length || cut->command[length - 1] != '\0' || !cut->command[0]) return 0;
    cut->command_length = length;
    struct sha256_context hash;
    sha256_init(&hash); sha256_update(&hash, (const unsigned char *)cut->command, length); publication_hash_hex(&hash, digest);
    return 1;
}
static inline int mq_positive_absence(migration_filesystem *scope, pid_t pid) {
    char token[128]; int retirement = 0;
    int result = observe_process_with_retirement(pid, token, &retirement);
    if (retirement) migrate_scope_poison(scope);
    return result == 0 && !retirement;
}
static inline int mq_begin_process(migration_filesystem *scope, migration_process_cut *cut, const char *name, pid_t pid) {
    cut->pid = pid;
    snprintf(cut->process_name, sizeof(cut->process_name), "%ld", (long)pid);
    cut->process = openat(cut->proc, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cut->process < 0)
        return (errno == ENOENT || errno == ESRCH) && mq_positive_absence(scope, pid) ? MQ_MORE : MQ_UNAVAILABLE;
    if (!mq_procfs(cut->process, &cut->proc_info) || fstat(cut->process, &cut->process_info) != 0) return MQ_UNAVAILABLE;
    int same_uid = mq_same_uid(scope, cut->process);
    if (same_uid <= 0) {
        int retired = mq_retire_process(scope, cut) == 0;
        return retired && (same_uid == 0 || mq_positive_absence(scope, pid)) ? MQ_MORE : MQ_UNAVAILABLE;
    }
    int retirement = 0;
    int observed = observe_process_with_retirement(pid, cut->start, &retirement);
    if (retirement) migrate_scope_poison(scope);
    if (observed == 0) return mq_retire_process(scope, cut) == 0 ? MQ_MORE : MQ_UNAVAILABLE;
    if (observed != 1 || scope->uncertain || ++cut->own_count > MQ_SAME_UID) return MQ_UNAVAILABLE;
    struct stat mount, root;
    if (fstatat(cut->process, "ns/mnt", &mount, 0) != 0 || !same_inode(&mount, &cut->mount_namespace) ||
        fstatat(cut->process, "root", &root, 0) != 0 || !same_inode(&root, &cut->process_root) ||
        fstatat(cut->process, "exe", &cut->executable, 0) != 0 || !S_ISREG(cut->executable.st_mode) ||
        mq_read_link(cut->process, "exe", cut->executable_path, sizeof(cut->executable_path)) != 0 ||
        !mq_canonical(cut->executable_path) || strstr(cut->executable_path, " (deleted)") ||
        !mq_command(scope, cut, cut->command_digest) || !mq_origin_current(scope, cut) ||
        mq_read_link(cut->process, "cwd", cut->working, sizeof(cut->working)) != 0 || !mq_canonical(cut->working) ||
        strstr(cut->working, " (deleted)")) return MQ_UNAVAILABLE;
    if (mq_protected_path(cut, cut->executable_path) || mq_protected_path(cut, cut->working)) return MQ_LEGACY_OPEN;
    cut->owned_role = source_metadata_same(&cut->executable, &cut->original_image);
    cut->directory_fd = openat(cut->process, "fd", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cut->directory_fd < 0 || !mq_procfs(cut->directory_fd, &cut->proc_info) ||
        !(cut->descriptors = fdopendir(cut->directory_fd))) {
        migrate_scope_close_fd(scope, &cut->directory_fd); return MQ_UNAVAILABLE;
    }
    return MQ_MORE;
}

/* Read-only package observation. A signed caller can accept only a closed
 * supported argv shape and the observed package's actual declaration; a
 * filename or process title by itself cannot establish absence of Legacy. */
static inline const char *mq_script_argument(const migration_process_cut *cut) {
    const char *end = cut->command + cut->command_length;
    const char *next = cut->command + strlen(cut->command) + 1;
    const char *name = strrchr(cut->executable_path, '/');
    if (!name) return NULL;
    name++;
    if (!strcmp(name, "node") || !strcmp(name, "nodejs")) {
        while (next < end && (!strcmp(next, "--no-warnings") || !strcmp(next, "--disable-warning=ExperimentalWarning")))
            next += strlen(next) + 1;
    } else if (strcmp(name, "sh") && strcmp(name, "dash") && strcmp(name, "bash")) {
        return NULL;
    }
    if (next < end && !strcmp(next, "--")) next += 3;
    if (next >= end || !*next || *next == '-') return NULL;
    return next;
}
static inline int mq_open_canonical(migration_filesystem *scope, const char *path, struct stat *identity, int *root_managed) {
    if (!mq_canonical(path) || !path[1]) { errno = EINVAL; return -1; }
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return -1;
    struct stat root;
    *root_managed = fstat(directory, &root) == 0 && root.st_uid == 0 && !(root.st_mode & 0022);
    for (const char *part = path + 1;;) {
        const char *next = strchr(part, '/');
        size_t size = next ? (size_t)(next - part) : strlen(part);
        char leaf[NAME_MAX + 1]; memcpy(leaf, part, size); leaf[size] = 0;
        struct stat named, held;
        int opened = -1, error = 0;
        if (fstatat(directory, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0) error = errno;
        else if (next ? !S_ISDIR(named.st_mode) : !S_ISREG(named.st_mode)) error = EINVAL;
        else {
            opened = openat(directory, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (next ? O_DIRECTORY : 0));
            if (opened < 0) error = errno;
            else if (fstat(opened, &held) != 0 || !source_metadata_same(&named, &held)) error = EINVAL;
        }
        if (migrate_scope_close_fd(scope, &directory) != 0) error = EIO;
        if (error) { migrate_scope_close_fd(scope, &opened); errno = error; return -1; }
        *root_managed = *root_managed && held.st_uid == 0 && !(held.st_mode & 0022);
        if (!next) { *identity = held; return opened; }
        directory = opened; part = next + 1;
    }
}
static inline int mq_package_file(migration_filesystem *scope, const char *path, const struct stat *expected,
                                  size_t limit, unsigned char *whole, char digest[65], int *managed_file) {
    int managed = 0; struct stat before, after;
    int fd = mq_open_canonical(scope, path, &before, &managed);
    if (fd < 0) return -1;
    int valid = before.st_size > 0 && (uint64_t)before.st_size <= limit &&
        (!expected || source_metadata_same(&before, expected)) && before.st_nlink == 1;
    uint64_t offset = 0;
    struct sha256_context hash; sha256_init(&hash);
    unsigned char bytes[65536];
    while (valid && offset < (uint64_t)before.st_size) {
        size_t amount = (uint64_t)before.st_size - offset < sizeof(bytes) ?
            (size_t)((uint64_t)before.st_size - offset) : sizeof(bytes);
        ssize_t received = read(fd, bytes, amount);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) { valid = 0; break; }
        sha256_update(&hash, bytes, (size_t)received);
        if (whole) memcpy(whole + offset, bytes, (size_t)received);
        offset += (uint64_t)received;
    }
    if (valid) {
        ssize_t end;
        do { end = read(fd, bytes, 1); } while (end < 0 && errno == EINTR);
        valid = end == 0 && fstat(fd, &after) == 0 && source_metadata_same(&before, &after);
    }
    if (migrate_scope_close_fd(scope, &fd) != 0 || !valid) { errno = EINVAL; return -1; }
    if (managed_file) *managed_file = managed;
    publication_hash_hex(&hash, digest);
    return (int)offset;
}
static inline int mq_script_package(migration_filesystem *scope, migration_process_cut *cut, unsigned char *bytes,
                                    char relative[PATH_MAX], int *managed) {
    const char *argument = mq_script_argument(cut);
    if (!argument) return -1;
    char requested[PATH_MAX], script[PATH_MAX], reread[PATH_MAX];
    int count = argument[0] == '/' ? snprintf(requested, sizeof(requested), "%s", argument) :
        snprintf(requested, sizeof(requested), "%s/%s", cut->working, argument);
    if (count <= 0 || (size_t)count >= sizeof(requested) || !realpath(requested, script) || !mq_canonical(script) ||
        mq_protected_path(cut, script)) return -1;
    struct stat expected;
    int fd = mq_open_canonical(scope, script, &expected, managed);
    if (fd < 0 || migrate_scope_close_fd(scope, &fd) != 0 ||
        mq_package_file(scope, script, &expected, MQ_ENTRY_BYTES, NULL, cut->entry_digest, NULL) < 0 ||
        !realpath(requested, reread) || strcmp(reread, script)) return -1;
    char parent[PATH_MAX]; memcpy(parent, script, strlen(script) + 1);
    for (unsigned int depth = 0; depth < 32; ++depth) {
        char *slash = strrchr(parent, '/');
        if (!slash || slash == parent) return -1;
        *slash = '\0';
        char manifest[PATH_MAX];
        count = snprintf(manifest, sizeof(manifest), "%s/package.json", parent);
        if (count <= 0 || (size_t)count >= sizeof(manifest)) return -1;
        int manifest_managed = 0;
        int size = mq_package_file(scope, manifest, NULL, MQ_PACKAGE_BYTES, bytes, cut->package_digest, &manifest_managed);
        if (size > 0) {
            if (!mq_origin_current(scope, cut)) return -1;
            *managed = *managed && manifest_managed;
            memcpy(relative, script + strlen(parent) + 1, strlen(script + strlen(parent) + 1) + 1);
            return size;
        }
        if (errno != ENOENT) return -1;
    }
    return -1;
}
static inline int mq_known_platform_image(migration_filesystem *scope, migration_process_cut *cut) {
    static const char *const paths[] = { "/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-executor",
        "/usr/bin/dbus-daemon", "/usr/bin/dbus-broker", "/usr/bin/dbus-broker-launch",
        "/usr/libexec/dbus-broker-launch", "/usr/bin/gnome-keyring-daemon" };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        if (strcmp(cut->executable_path, paths[index])) continue;
        int managed = 0; struct stat info;
        int fd = mq_open_canonical(scope, paths[index], &info, &managed);
        if (fd < 0) return 0;
        int valid = managed && source_metadata_same(&info, &cut->executable);
        if (migrate_scope_close_fd(scope, &fd) != 0) valid = 0;
        return valid;
    }
    return 0;
}
static inline int mq_no_external_loaders(migration_filesystem *scope, const migration_process_cut *cut) {
    char *bytes = malloc(MQ_ARGV_BYTES + 1);
    if (!bytes) return 0;
    size_t length = 0; int retirement = 0;
    int valid = installed_keeper_read(cut->process, "environ", bytes, MQ_ARGV_BYTES + 1, &length, &retirement);
    if (retirement) migrate_scope_poison(scope);
    if (valid && length && bytes[length - 1] != 0) valid = 0;
    static const char *const loader[] = { "NODE_OPTIONS=", "NODE_PATH=", "NPM_CONFIG_NODE_OPTIONS=",
        "BASH_ENV=", "ENV=", "LD_PRELOAD=", "LD_AUDIT=" };
    for (char *field = bytes; valid && field < bytes + length; field += strlen(field) + 1) {
        for (size_t index = 0; index < sizeof(loader) / sizeof(loader[0]); ++index) {
            size_t size = strlen(loader[index]);
            if (!strncmp(field, loader[index], size) && field[size]) { valid = 0; break; }
        }
    }
    explicit_bzero(bytes, MQ_ARGV_BYTES + 1); free(bytes);
    return valid;
}
static inline int mq_record_process(migration_filesystem *scope, migration_process_cut *cut,
                                    const char *kind) {
    if (!cut->package_pending || cut->member_count >= MQ_SAME_UID || !mq_origin_current(scope, cut)) return -1;
    char identity[256];
    int length = snprintf(identity, sizeof(identity), "%ld:%s:%llu:%llu:%llu:%llu:", (long)cut->pid, cut->start,
        (unsigned long long)cut->executable.st_dev, (unsigned long long)cut->executable.st_ino,
        (unsigned long long)cut->executable.st_uid, (unsigned long long)cut->executable.st_mode);
    if (length <= 0 || (size_t)length >= sizeof(identity)) return -1;
    mq_member *member = &cut->members[cut->member_count];
    struct sha256_context hash; sha256_init(&hash);
    const char *const fields[] = { kind, identity, cut->executable_path, cut->command_digest, cut->package_digest, cut->entry_digest };
    for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); ++index)
        sha256_update(&hash, (const unsigned char *)fields[index], strlen(fields[index]) + 1);
    member->pid = cut->pid; publication_hash_hex(&hash, member->digest);
    if (mq_retire_process(scope, cut) != 0) return -1;
    cut->package_digest[0] = 0; cut->entry_digest[0] = 0;
    cut->member_count++; return 0;
}
static inline int mq_compare(const void *left, const void *right) {
    pid_t a = ((const mq_member *)left)->pid, b = ((const mq_member *)right)->pid;
    return (a > b) - (a < b);
}
static inline int mq_digest(migration_process_cut *cut, char digest[65]) {
    if (cut->member_count != cut->own_count || !cut->member_count) return -1;
    qsort(cut->members, cut->member_count, sizeof(cut->members[0]), mq_compare);
    struct sha256_context hash; sha256_init(&hash);
    sha256_update(&hash, (const unsigned char *)cut->mount_digest, 65);
    pid_t prior = 0;
    for (size_t index = 0; index < cut->member_count; ++index) {
        if (cut->members[index].pid <= prior) return -1;
        prior = cut->members[index].pid;
        sha256_update(&hash, (const unsigned char *)cut->members[index].digest, 65);
    }
    publication_hash_hex(&hash, digest); return 0;
}

/* The native phase completes physical descriptors before returning any
 * executable classification request. Application code never receives raw
 * argv, FD numbers, executable authority, or a caller-directed path lookup. */
static inline int mq_next(migration_filesystem *scope, migration_process_cut *cut,
                          int (*own_descriptor)(migration_filesystem *, unsigned long, const struct stat *)) {
    if (!cut || !cut->processes || cut->package_pending || scope->uncertain) return MQ_UNAVAILABLE;
    for (unsigned int step = 0; step < MQ_SCAN_PAGE; ++step) {
        if (cut->descriptors) {
            errno = 0;
            struct dirent *entry = readdir(cut->descriptors);
            if (!entry) {
                char digest[65]; int error = errno;
                if (mq_close_dir(scope, &cut->descriptors) != 0 || error || !mq_origin_current(scope, cut) ||
                    mq_same_uid(scope, cut->process) != 1 || !mq_command(scope, cut, digest) || strcmp(digest, cut->command_digest))
                    return MQ_UNAVAILABLE;
                cut->directory_fd = -1;
                cut->package_pending = 1; return MQ_PACKAGE;
            }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            int current = mq_descriptor(scope, cut, entry->d_name, own_descriptor);
            if (current != MQ_MORE) return current;
            continue;
        }
        errno = 0;
        struct dirent *entry = readdir(cut->processes);
        if (!entry) {
            char digest[65]; int retirement = 0, error = errno;
            int self = installed_keeper_open_self(&retirement);
            if (retirement) migrate_scope_poison(scope);
            int valid = !error && self >= 0 && mq_procfs(self, &cut->proc_info) &&
                mq_mounts(scope, self, digest) && !strcmp(digest, cut->mount_digest) && cut->own_count != 0;
            if (migrate_scope_close_fd(scope, &self) != 0 || !valid) return MQ_UNAVAILABLE;
            return MQ_COMPLETE;
        }
        if (++cut->process_count > MQ_PROCESSES) return MQ_UNAVAILABLE;
        unsigned long pid;
        if (!mq_number(entry->d_name, INT_MAX, &pid)) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') return MQ_UNAVAILABLE;
            continue;
        }
        if (!pid) return MQ_UNAVAILABLE;
        int current = mq_begin_process(scope, cut, entry->d_name, (pid_t)pid);
        if (current != MQ_MORE) return current;
    }
    return MQ_MORE;
}
static inline int mq_owned_fd(migration_filesystem *scope, unsigned long number, const struct stat *actual) {
    if ((unsigned long)scope->binding->gate->gate_fd == number && same_inode(&scope->binding->gate->file, actual)) return 1;
    for (size_t index = 0; index < scope->legacy_chain_count; ++index)
        if ((unsigned long)scope->legacy_chain[index] == number && same_inode(&scope->legacy_chain_ids[index], actual)) return 1;
    if (scope->publication) for (size_t index = 0; index < MP_FILES; ++index) {
        migration_publication_file *file = &scope->publication->files[index];
        if ((unsigned long)file->fd == number && file->identity_known && same_inode(&file->identity, actual)) return 1;
    }
    if (scope->legacy_locks) {
        migration_legacy_locks *locks = scope->legacy_locks;
        for (size_t index = 0; index < locks->parent_count; ++index)
            if ((unsigned long)locks->parents[index].fd == number && same_inode(&locks->parents[index].identity, actual)) return 1;
        for (size_t index = 0; index < locks->target_count; ++index) {
            ml_target *target = &locks->targets[index];
            if (((unsigned long)target->directory_fd == number && same_inode(&target->directory, actual)) ||
                ((unsigned long)target->owner_fd == number && same_inode(&target->owner, actual))) return 1;
        }
    }
    return 0;
}
static inline int mq_scope_retire(migration_filesystem *scope) {
    if (!scope->process_cut) return 0;
    if (mq_retire(scope, scope->process_cut) != 0) return -1;
    scope->process_cut = NULL; return 0;
}
static napi_value mq_cut_result(napi_env env, const char *kind) {
    napi_value result;
    return napi_create_object(env, &result) == napi_ok && publication_set_string(env, result, "kind", kind) ? result : NULL;
}
static napi_value mq_end_cut(migration_filesystem *scope, napi_env env, int status) {
    char digest[65];
    if (status == MQ_COMPLETE && (scope->process_cut->unclassified_package || mq_digest(scope->process_cut, digest) != 0))
        status = MQ_UNAVAILABLE;
    if (mq_scope_retire(scope) != 0) return migrate_scope_error(env, scope, "original Legacy process inspection did not retire");
    if (status == MQ_COMPLETE) {
        napi_value result = mq_cut_result(env, "complete");
        return result && publication_set_string(env, result, "digest", digest) ? result : NULL;
    }
    return mq_cut_result(env, status == MQ_LEGACY_OPEN ? "legacy_process_or_descriptor_open" : "unavailable");
}
static napi_value mq_unclassified(migration_filesystem *scope, napi_env env) {
    migration_process_cut *cut = scope->process_cut;
    cut->unclassified_package = 1;
    if (mq_record_process(scope, cut, "unclassified_package") != 0) return mq_end_cut(scope, env, MQ_UNAVAILABLE);
    return mq_cut_result(env, "progress");
}
static napi_value mq_begin_cut(migration_filesystem *scope, napi_env env) {
    if (!scope || scope->process_cut || migrate_scope_check(scope, env) != 0 || scope->failed)
        return migrate_scope_error(env, scope, "Legacy process inspection requires its current original migration scope");
    if (mq_open(scope, &scope->process_cut) != 0) return mq_end_cut(scope, env, MQ_UNAVAILABLE);
    return mq_cut_result(env, "started");
}
static napi_value mq_step_cut(migration_filesystem *scope, napi_env env) {
    if (!scope || !scope->process_cut || migrate_scope_check(scope, env) != 0 || scope->failed)
        return migrate_scope_error(env, scope, "Legacy process inspection lacks its original current cut");
    migration_process_cut *cut = scope->process_cut;
    int status = mq_next(scope, cut, mq_owned_fd);
    if (status == MQ_MORE) return mq_cut_result(env, "progress");
    if (status != MQ_PACKAGE) return mq_end_cut(scope, env, status);
    if (!mq_no_external_loaders(scope, cut)) return mq_unclassified(scope, env);
    if (cut->owned_role || mq_known_platform_image(scope, cut)) {
        if (mq_record_process(scope, cut, cut->owned_role ? "original_signed_image" : "known_platform_image") != 0)
            return mq_end_cut(scope, env, MQ_UNAVAILABLE);
        return mq_cut_result(env, "progress");
    }
    unsigned char *bytes = malloc(MQ_PACKAGE_BYTES);
    if (!bytes) return mq_end_cut(scope, env, MQ_UNAVAILABLE);
    char relative[PATH_MAX];
    int managed = 0, length = mq_script_package(scope, cut, bytes, relative, &managed);
    if (length <= 0) {
        explicit_bzero(bytes, MQ_PACKAGE_BYTES); free(bytes);
        return mq_unclassified(scope, env);
    }
    cut->package_managed = managed;
    napi_value result = mq_cut_result(env, "package"), data, immutable;
    int valid = result && napi_create_buffer_copy(env, (size_t)length, bytes, NULL, &data) == napi_ok &&
        napi_set_named_property(env, result, "bytes", data) == napi_ok &&
        napi_get_boolean(env, managed != 0, &immutable) == napi_ok && napi_set_named_property(env, result, "rootManaged", immutable) == napi_ok &&
        publication_set_string(env, result, "entrypoint", relative) &&
        publication_set_string(env, result, "packageSha256", cut->package_digest) &&
        publication_set_string(env, result, "entrySha256", cut->entry_digest);
    explicit_bzero(bytes, MQ_PACKAGE_BYTES); free(bytes);
    return valid ? result : NULL;
}
static napi_value mq_settle_package(migration_filesystem *scope, napi_env env, const char *package_sha, bool unrelated) {
    if (!scope || !scope->process_cut || migrate_scope_check(scope, env) != 0 || scope->failed ||
        !scope->process_cut->package_pending || strcmp(package_sha, scope->process_cut->package_digest))
        return migrate_scope_error(env, scope, "Legacy process package source is no longer its original exact observation");
    if (!unrelated) return mq_unclassified(scope, env);
    if (!scope->process_cut->package_managed || mq_record_process(scope, scope->process_cut, "typed_root_managed_package") != 0)
        return migrate_scope_error(env, scope, "Legacy process package could not close its original immutable source");
    return mq_cut_result(env, "progress");
}
static napi_value mq_cancel_cut(migration_filesystem *scope, napi_env env) {
    if (!scope || scope->env != env || scope->retired || scope->uncertain ||
        migration_credential_check(scope->binding, env) != 0 || mq_scope_retire(scope) != 0)
        return migrate_scope_error(env, scope, "original Legacy process inspection did not cancel and retire");
    return mq_cut_result(env, "retired");
}
#else
static inline int mq_scope_retire(migration_filesystem *scope) { (void)scope; return 0; }
static napi_value mq_begin_cut(migration_filesystem *scope, napi_env env) {
    return migrate_scope_error(env, scope, "Legacy process observation is unavailable on this platform");
}
static napi_value mq_step_cut(migration_filesystem *scope, napi_env env) { return mq_begin_cut(scope, env); }
static napi_value mq_settle_package(migration_filesystem *scope, napi_env env, const char *package_sha, bool unrelated) {
    (void)package_sha; (void)unrelated; return mq_begin_cut(scope, env);
}
static napi_value mq_cancel_cut(migration_filesystem *scope, napi_env env) { return mq_begin_cut(scope, env); }
#endif

static napi_value migrate_process_begin(napi_env env, napi_callback_info info) {
    napi_value ignored; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &ignored);
    return scope && count == 0 ? mq_begin_cut(scope, env) : migrate_scope_error(env, NULL, "invalid original process inspection entry");
}
static napi_value migrate_process_step(napi_env env, napi_callback_info info) {
    napi_value ignored; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &ignored);
    return scope && count == 0 ? mq_step_cut(scope, env) : migrate_scope_error(env, NULL, "invalid original process inspection step");
}
static napi_value migrate_process_settle_package(napi_env env, napi_callback_info info) {
    napi_value args[3]; size_t count = 3; char digest[65]; bool unrelated;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, args);
    if (!scope || count != 2 || migrate_scope_text(env, args[0], digest, sizeof(digest)) != 0 || strlen(digest) != 64 ||
        napi_get_value_bool(env, args[1], &unrelated) != napi_ok)
        return migrate_scope_error(env, NULL, "invalid original process package inspection");
    return mq_settle_package(scope, env, digest, unrelated);
}
static napi_value migrate_process_cancel(napi_env env, napi_callback_info info) {
    napi_value ignored; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &ignored);
    return scope && count == 0 ? mq_cancel_cut(scope, env) : migrate_scope_error(env, NULL, "invalid original process inspection cancellation");
}
static napi_value migrate_process_check_before_control(napi_env env, napi_callback_info info) {
    napi_value ignored, result; size_t count = 1;
    migration_filesystem *scope = migrate_scope_receiver(env, info, &count, &ignored);
    if (!scope || count || scope->process_cut || migrate_scope_check(scope, env) != 0 || scope->publication)
        return migrate_scope_error(env, NULL, "early process refusal requires exact original entry and retired scan");
    struct stat named;
    const int absent = fstatat(scope->migration_fd, "control-v1.json", &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
        fstatat(scope->migration_fd, "authority-v1.json", &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT &&
        fstatat(scope->legacy_fd, ".cliq-generation-v1.json", &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
    return napi_get_boolean(env, absent != 0, &result) == napi_ok ? result : NULL;
}
#endif
