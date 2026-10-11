/* Fixed installed-bootstrap bridge. The JavaScript producer has already
 * verified the signed selection and retired its other owning handles. This
 * callback borrows only its still-owned image FD; it never closes that FD. */
#ifdef __linux__
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/close_range.h>

typedef struct {
    uint64_t field[7]; /* dev, ino, size, uid, gid, mode, nlink */
    int64_t modified, changed;
} installed_image_stat;

static int installed_string(napi_env env, napi_value value, char *text, size_t capacity) {
    size_t length;
    return napi_get_value_string_utf8(env, value, NULL, 0, &length) == napi_ok &&
        length > 0 && length < capacity &&
        napi_get_value_string_utf8(env, value, text, capacity, &length) == napi_ok && strlen(text) == length;
}

/* Parse before opening C-owned resources: no caller getter can run during the
 * native validation/retirement/exec cut. Values never pass through doubles. */
static int installed_stat_array(napi_env env, napi_value value, uint64_t *fields, uint32_t count,
    int64_t *modified, int64_t *changed) {
    bool array, lossless;
    uint32_t length;
    if (napi_is_array(env, value, &array) != napi_ok || !array ||
        napi_get_array_length(env, value, &length) != napi_ok || length != count) return 0;
    for (uint32_t i = 0; i < count; i++) {
        napi_value member;
        if (napi_get_element(env, value, i, &member) != napi_ok) return 0;
        if (modified && i >= 7) {
            if (napi_get_value_bigint_int64(env, member, i == 7 ? modified : changed, &lossless) != napi_ok || !lossless) return 0;
        } else if (napi_get_value_bigint_uint64(env, member, &fields[i], &lossless) != napi_ok || !lossless) return 0;
    }
    return 1;
}

static int installed_path(const char *path, int absolute) {
    if ((path[0] == '/') != absolute || strchr(path, '\\')) return 0;
    const char *part = path + absolute;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (!size || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) return 1;
        part = end + 1;
    }
    return 0;
}

static int installed_time(struct timespec actual, int64_t expected) {
    int64_t seconds = expected / 1000000000, nanos = expected % 1000000000;
    if (nanos < 0) { seconds--; nanos += 1000000000; }
    return actual.tv_sec == seconds && actual.tv_nsec == nanos;
}

static int installed_image_matches(const struct stat *actual, const installed_image_stat *expected) {
    return (uint64_t)actual->st_dev == expected->field[0] && (uint64_t)actual->st_ino == expected->field[1] &&
        actual->st_size > 0 && (uint64_t)actual->st_size == expected->field[2] &&
        (uint64_t)actual->st_uid == expected->field[3] && (uint64_t)actual->st_gid == expected->field[4] &&
        (uint64_t)actual->st_mode == expected->field[5] && (uint64_t)actual->st_nlink == expected->field[6] &&
        installed_time(actual->st_mtim, expected->modified) && installed_time(actual->st_ctim, expected->changed);
}

static int installed_root_matches(const struct stat *actual, const uint64_t expected[5]) {
    return private_directory(actual) && (uint64_t)actual->st_dev == expected[0] &&
        (uint64_t)actual->st_ino == expected[1] && (uint64_t)actual->st_uid == expected[2] &&
        (uint64_t)actual->st_gid == expected[3] && (uint64_t)actual->st_mode == expected[4];
}

static int installed_executable(const struct stat *image) {
    return S_ISREG(image->st_mode) && image->st_uid == geteuid() && image->st_nlink == 1 &&
        (image->st_mode & 07777) == 0500 && image->st_size > 0 && image->st_size <= CONTROL_IMAGE_MAX_BYTES;
}

/* Walk only the fixed version-relative locator beneath the independently
 * held StateRoot. Each C-owned directory is consumed before retirement. */
static int installed_open_image(int root, const char *relative, int *retirement_failed) {
    char locator[PATH_MAX];
    memcpy(locator, relative, strlen(relative) + 1);
    int parent = root, owned_parent = -1, image = -1;
    char *part = locator;
    for (;;) {
        char *end = strchr(part, '/');
        if (!end) { image = openat(parent, part, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC); break; }
        *end = '\0';
        int next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat held, named;
        int valid = next >= 0 && fstat(next, &held) == 0 && private_directory(&held) &&
            fstatat(parent, part, &named, AT_SYMLINK_NOFOLLOW) == 0 && private_directory(&named) &&
            same_inode(&held, &named) && held.st_gid == named.st_gid && held.st_mode == named.st_mode;
        retire_process_fd(&owned_parent, retirement_failed);
        if (!valid || *retirement_failed) { retire_process_fd(&next, retirement_failed); break; }
        parent = owned_parent = next; part = end + 1;
    }
    retire_process_fd(&owned_parent, retirement_failed);
    if (*retirement_failed) retire_process_fd(&image, retirement_failed);
    return image;
}

static napi_value installed_exec_error(napi_env env, const char *message, int retirement_failed) {
    if (retirement_failed || atomic_load(&current_process_retirement_failed)) return current_process_retirement_error(env);
    return native_error(env, message);
}

static napi_value execute_installed_image(napi_env env, napi_callback_info info) {
    if (atomic_load(&current_process_retirement_failed)) return current_process_retirement_error(env);
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "installed image exec requires the process main thread");
    size_t argc = 9;
    napi_value args[9];
    double descriptor;
    installed_image_stat image_expected, bootstrap_expected;
    uint64_t root_expected[5];
    char root_path[PATH_MAX], bundle[65], relative[PATH_MAX], role[11];
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 8 ||
        napi_get_value_double(env, args[0], &descriptor) != napi_ok ||
        !(descriptor >= 3 && descriptor <= INT_MAX) || descriptor != (double)(int)descriptor ||
        !installed_stat_array(env, args[1], image_expected.field, 9, &image_expected.modified, &image_expected.changed) ||
        !installed_stat_array(env, args[2], bootstrap_expected.field, 9, &bootstrap_expected.modified, &bootstrap_expected.changed) ||
        !installed_stat_array(env, args[3], root_expected, 5, NULL, NULL) ||
        !installed_string(env, args[4], root_path, sizeof(root_path)) || !installed_path(root_path, 1) ||
        !installed_string(env, args[5], bundle, sizeof(bundle)) || strlen(bundle) != 64 ||
        strspn(bundle, "0123456789abcdef") != 64 ||
        !installed_string(env, args[6], relative, sizeof(relative)) || !installed_path(relative, 0) ||
        !installed_string(env, args[7], role, sizeof(role)) ||
        (strcmp(role, "keeper") != 0 && strcmp(role, "supervisor") != 0))
        return installed_exec_error(env, "invalid fixed installed image exec input", 0);

    char bootstrap_path[PATH_MAX], target_path[PATH_MAX], target_relative[PATH_MAX], root_locator[96];
    int length = snprintf(bootstrap_path, sizeof(bootstrap_path), "%s/runtime/bootstrap", root_path);
    if (length <= 0 || (size_t)length >= sizeof(bootstrap_path)) return installed_exec_error(env, "installed bootstrap locator exceeds platform limit", 0);
    length = snprintf(target_relative, sizeof(target_relative), "runtime/bundles/%s/%s", bundle, relative);
    if (length <= 0 || (size_t)length >= sizeof(target_relative)) return installed_exec_error(env, "installed selected locator exceeds platform limit", 0);
    length = snprintf(target_path, sizeof(target_path), "%s/%s", root_path, target_relative);
    if (length <= 0 || (size_t)length >= sizeof(target_path)) return installed_exec_error(env, "installed selected path exceeds platform limit", 0);
    length = snprintf(root_locator, sizeof(root_locator), "%llu:%llu:%llu",
        (unsigned long long)root_expected[0], (unsigned long long)root_expected[1], (unsigned long long)root_expected[2]);
    if (length <= 0 || (size_t)length >= sizeof(root_locator)) return installed_exec_error(env, "installed root identity exceeds platform limit", 0);

    int image_fd = (int)descriptor, root = -1, named_image = -1, independent_image = -1, retirement_failed = 0;
    current_process_observation bootstrap;
    memset(&bootstrap, 0, sizeof(bootstrap)); bootstrap.image_fd = -1;
    bootstrap.pid = getpid(); bootstrap.uid = geteuid(); bootstrap.gid = getegid();
    uid_t real_uid, effective_uid, saved_uid, final_real_uid, final_effective_uid, final_saved_uid;
    gid_t real_gid, effective_gid, saved_gid, final_real_gid, final_effective_gid, final_saved_gid;
    struct stat actual, named, held;
    char final_start[128], final_path[PATH_MAX];
    const char *error = "installed exec process credentials or start identity are unavailable";
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        observe_process_with_retirement(bootstrap.pid, bootstrap.start_token, &bootstrap.retirement_failed) != 1) goto done;
    error = "installed exec requires the exact signed StateRoot bootstrap image";
    bootstrap.image_fd = open_process_image(bootstrap.pid, bootstrap.uid, bootstrap.gid,
        bootstrap.image_path, &bootstrap.image, &bootstrap.retirement_failed);
    if (bootstrap.image_fd < 0 || strcmp(bootstrap.image_path, bootstrap_path) != 0 ||
        !installed_executable(&bootstrap.image) || !installed_image_matches(&bootstrap.image, &bootstrap_expected) ||
        current_process_is_held(&bootstrap) != 1) goto done;
    error = "installed exec StateRoot identity is unavailable or changed";
    root = open_root_with_retirement(root_path, &retirement_failed);
    if (root < 0 || fstat(root, &actual) != 0 || !installed_root_matches(&actual, root_expected)) goto done;
    error = "installed exec selected image is unavailable or changed";
    named_image = installed_open_image(root, target_relative, &retirement_failed);
    independent_image = open_image_path(target_path, &retirement_failed);
    if (named_image < 0 || independent_image < 0 ||
        fstat(image_fd, &held) != 0 || !installed_executable(&held) || !installed_image_matches(&held, &image_expected) ||
        fstat(named_image, &actual) != 0 || !installed_image_matches(&actual, &image_expected) || !same_image(&held, &actual) ||
        fstat(independent_image, &named) != 0 || !same_image(&held, &named)) goto done;
    unsigned char elf[4];
    ssize_t bytes;
    do { bytes = pread(image_fd, elf, sizeof(elf), 0); } while (bytes < 0 && errno == EINTR);
    error = "installed exec accepts only the held on-disk ELF image";
    if (bytes != (ssize_t)sizeof(elf) || memcmp(elf, "\177ELF", sizeof(elf)) != 0) goto done;
    error = "installed exec bootstrap or StateRoot changed during validation";
    if (current_process_is_held(&bootstrap) != 1 || fstat(root, &actual) != 0 ||
        !installed_root_matches(&actual, root_expected) || lstat(root_path, &named) != 0 ||
        !installed_root_matches(&named, root_expected)) goto done;
    error = NULL;
done:
    retire_process_fd(&independent_image, &retirement_failed);
    retire_process_fd(&named_image, &retirement_failed);
    retire_process_fd(&root, &retirement_failed);
    if (!close_current_process_image(&bootstrap)) retirement_failed = 1;
    if (retirement_failed || atomic_load(&current_process_retirement_failed)) return current_process_retirement_error(env);
    if (error) return native_error(env, error);

    /* Close the cut after every temporary resource has been consumed. The
     * final process sample retires its own temporary descriptor before return.
     * The actual /proc/self/exe magic link is intentional, never caller input. */
    ssize_t path_length = readlink("/proc/self/exe", final_path, sizeof(final_path) - 1);
    if (path_length > 0 && (size_t)path_length < sizeof(final_path) - 1) final_path[path_length] = '\0';
    int valid = path_length > 0 && (size_t)path_length < sizeof(final_path) - 1 && strcmp(final_path, bootstrap_path) == 0 &&
        stat("/proc/self/exe", &actual) == 0 && installed_image_matches(&actual, &bootstrap_expected) && installed_executable(&actual) &&
        lstat(root_path, &actual) == 0 && installed_root_matches(&actual, root_expected) &&
        lstat(target_path, &actual) == 0 && installed_image_matches(&actual, &image_expected) &&
        getresuid(&final_real_uid, &final_effective_uid, &final_saved_uid) == 0 &&
        getresgid(&final_real_gid, &final_effective_gid, &final_saved_gid) == 0 &&
        final_real_uid == real_uid && final_effective_uid == effective_uid && final_saved_uid == saved_uid &&
        final_real_gid == real_gid && final_effective_gid == effective_gid && final_saved_gid == saved_gid &&
        observe_process_with_retirement(bootstrap.pid, final_start, &retirement_failed) == 1 &&
        strcmp(final_start, bootstrap.start_token) == 0 &&
        fstat(image_fd, &held) == 0 && installed_executable(&held) && installed_image_matches(&held, &image_expected);
    if (!valid || retirement_failed || atomic_load(&current_process_retirement_failed))
        return installed_exec_error(env, "installed exec final process, root, or held image identity changed", retirement_failed);

    char *const arguments[] = {target_path, strcmp(role, "keeper") == 0 ? "--installed-keeper" : "--installed-supervisor",
        root_path, bundle, root_locator, NULL};
    char *const environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
    /* This is a terminal FD whitelist, not a per-FD successful-close proof.
     * After unsharing/changing the table, never resume Node or run finalizers. */
    if (syscall(SYS_close_range, 3u, UINT_MAX, CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0) _exit(70);
    syscall(SYS_execveat, image_fd, "", arguments, environment, AT_EMPTY_PATH);
    _exit(70);
}
#else
static napi_value execute_installed_image(napi_env env, napi_callback_info info) {
    (void)info;
    return native_error(env, "installed image exec requires Linux");
}
#endif
