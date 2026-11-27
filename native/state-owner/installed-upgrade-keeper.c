/* A current upgrade controller checks an original keeper. This is deliberately
 * not an installed_anchor: it cannot borrow or expose the old cgroup root. The
 * ordinary Supervisor anchor and its exact role/image guards stay unchanged. */
static const napi_type_tag installed_upgrade_keeper_tag = {0x91a497709de649bfULL, 0xa08a921890e11c36ULL};
typedef struct {
    installed_anchor original;
    installed_image_stat controller_image;
    uint64_t package_identity[5];
    char package_root[PATH_MAX], controller_relative[PATH_MAX], controller_path[PATH_MAX];
} installed_upgrade_keeper;

static int installed_upgrade_controller_cmdline(int process, installed_upgrade_keeper *check, int *failed) {
    char actual[PATH_MAX * 3 + 128]; size_t length;
    if (!installed_keeper_read(process, "cmdline", actual, sizeof(actual), &length, failed)) return 0;
    const char *arguments[] = {check->controller_path, "--upgrade-runtime", check->original.state_root, check->package_root};
    size_t offset = 0;
    for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); i++) {
        size_t count = strlen(arguments[i]) + 1;
        if (offset > length || count > length - offset || memcmp(actual + offset, arguments[i], count)) return 0;
        offset += count;
    }
    return offset == length;
}

static int installed_upgrade_controller_current(installed_upgrade_keeper *check, int process, int *failed) {
    installed_anchor *original = &check->original;
    int package = -1, image = -1; struct stat metadata;
    int valid = process >= 0 && installed_keeper_credentials(process, original->process.uid, original->process.gid, failed) &&
        installed_upgrade_controller_cmdline(process, check, failed) && current_process_is_held(&original->process) == 1 &&
        strcmp(original->process.image_path, check->controller_path) == 0 &&
        installed_executable(&original->process.image) && installed_image_matches(&original->process.image, &check->controller_image);
    if (valid) package = open_root_with_retirement(check->package_root, failed);
    valid = valid && package >= 0 && fstat(package, &metadata) == 0 && installed_root_matches(&metadata, check->package_identity);
    if (valid) image = installed_open_image(package, check->controller_relative, failed);
    valid = valid && image >= 0 && fstat(image, &metadata) == 0 && installed_executable(&metadata) &&
        installed_image_matches(&metadata, &check->controller_image);
    retire_process_fd(&image, failed); retire_process_fd(&package, failed);
    return valid && !*failed;
}

static int installed_upgrade_keeper_current(installed_upgrade_keeper *check, int *failed) {
    installed_anchor *original = &check->original;
    if (original->closed || original->retirement_failed || original->root_fd < 0) return 0;
    int process = installed_keeper_open_self(failed), state = -1, image = -1; struct stat metadata; unsigned char boot[16];
    installed_anchor_fd_info before, after;
    int valid = installed_upgrade_controller_current(check, process, failed) && installed_anchor_peer_current(original, failed) &&
        installed_anchor_namespaces(original, process, 0, failed) && installed_keeper_boot(boot, failed) &&
        memcmp(boot, original->boot, sizeof(boot)) == 0;
    if (valid) state = open_root_with_retirement(original->state_root, failed);
    valid = valid && state >= 0 && fstat(state, &metadata) == 0 && installed_root_matches(&metadata, original->state_root_identity);
    if (valid) image = installed_open_image(state, original->target_relative, failed);
    valid = valid && image >= 0 && fstat(image, &metadata) == 0 && installed_executable(&metadata) &&
        installed_image_matches(&metadata, &original->expected_image) && installed_anchor_membership(original, 0, failed) &&
        installed_anchor_fdinfo(original->peer_process, original->source_fd, &before, failed) &&
        installed_anchor_same_source(&before, &original->source) && installed_anchor_root_current(original, process, 0, failed) &&
        installed_anchor_fdinfo(original->peer_process, original->source_fd, &after, failed) && installed_anchor_same_source(&after, &before) &&
        installed_anchor_peer_current(original, failed) && installed_anchor_namespaces(original, process, 0, failed) &&
        installed_upgrade_controller_current(check, process, failed);
    retire_process_fd(&image, failed); retire_process_fd(&state, failed); retire_process_fd(&process, failed);
    return valid && !*failed && !atomic_load(&current_process_retirement_failed) &&
        current_process_is_held(&original->process) == 1 &&
        installed_anchor_start(original->peer_process, original->peer_pid, original->peer_ticks, failed) && !*failed;
}
static void installed_upgrade_keeper_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    installed_upgrade_keeper *check = data;
    if (check) { installed_anchor_close(&check->original); free(check); }
}
static napi_value installed_upgrade_keeper_assert(napi_env env, napi_callback_info info) {
    installed_upgrade_keeper *check = unwrap_control(env, info, &installed_upgrade_keeper_tag, "invalid current keeper check");
    if (!check) return NULL;
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "current keeper check requires the main thread");
    int failed = 0;
    if (!installed_upgrade_keeper_current(check, &failed))
        return installed_keeper_error(env, "current keeper check source or controller changed", failed);
    return undefined_result(env);
}
static napi_value installed_upgrade_keeper_close(napi_env env, napi_callback_info info) {
    installed_upgrade_keeper *check = unwrap_control(env, info, &installed_upgrade_keeper_tag, "invalid current keeper check");
    if (!check) return NULL;
    if (syscall(SYS_gettid) != getpid()) return native_error(env, "current keeper check requires the main thread");
    if (!installed_anchor_close(&check->original)) return installed_keeper_error(env, "current keeper check close failed", 1);
    return undefined_result(env);
}

static napi_value check_installed_upgrade_keeper(napi_env env, napi_callback_info info) {
    if (atomic_load(&current_process_retirement_failed)) return installed_keeper_error(env, "current keeper check retirement failed", 1);
    if (syscall(SYS_gettid) != getpid() || geteuid() == 0 || getegid() == 0)
        return native_error(env, "current keeper check requires the nonroot main thread");
    size_t argc = 11, locator_length; napi_value args[11]; bool buffer; void *locator_data;
    installed_upgrade_keeper *check = calloc(1, sizeof(*check));
    if (!check) return native_error(env, "current keeper check allocation failed");
    installed_anchor *original = &check->original;
    original->process.image_fd = original->peer_process = original->peer_image = original->root_fd = -1;
    original->process.pid = getpid(); original->process.uid = geteuid(); original->process.gid = getegid();
    int process = -1, proc = -1, state = -1, image = -1, source = -1, failed = 0;
    const char *error = "invalid current keeper check input";
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 10 ||
        !installed_string(env, args[0], original->state_root, sizeof(original->state_root)) || !installed_path(original->state_root, 1) ||
        !installed_string(env, args[1], original->bundle, sizeof(original->bundle)) || strlen(original->bundle) != 64 || strspn(original->bundle, "0123456789abcdef") != 64 ||
        !installed_string(env, args[2], original->target_relative, sizeof(original->target_relative)) || !installed_path(original->target_relative, 0) ||
        !installed_stat_array(env, args[3], original->expected_image.field, 9, &original->expected_image.modified, &original->expected_image.changed) ||
        !installed_stat_array(env, args[4], original->state_root_identity, 5, NULL, NULL) ||
        napi_is_buffer(env, args[5], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[5], &locator_data, &locator_length) != napi_ok || locator_length != 40 ||
        !installed_string(env, args[6], check->package_root, sizeof(check->package_root)) || !installed_path(check->package_root, 1) ||
        !installed_string(env, args[7], check->controller_relative, sizeof(check->controller_relative)) || !installed_path(check->controller_relative, 0) ||
        !installed_stat_array(env, args[8], check->controller_image.field, 9, &check->controller_image.modified, &check->controller_image.changed) ||
        !installed_stat_array(env, args[9], check->package_identity, 5, NULL, NULL)) goto fail;
    unsigned char locator[40]; memcpy(locator, locator_data, sizeof(locator));
    uint64_t pid = 0, descriptor = 0, ticks = 0;
    for (unsigned int i = 0; i < 4; i++) { pid |= (uint64_t)locator[8 + i] << (8 * i); descriptor |= (uint64_t)locator[12 + i] << (8 * i); }
    for (unsigned int i = 0; i < 8; i++) ticks |= (uint64_t)locator[16 + i] << (8 * i);
    if (memcmp(locator, "cliq-ak1", 8) || !pid || pid > INT_MAX || pid == (uint64_t)getpid() || descriptor < 3 || descriptor > INT_MAX || !ticks) goto fail;
    original->peer_pid = (pid_t)pid; original->source_fd = (int)descriptor; original->peer_ticks = ticks;
    memcpy(original->boot, locator + 24, sizeof(original->boot));
    char relative[PATH_MAX]; memcpy(relative, original->target_relative, strlen(original->target_relative) + 1);
    int length = snprintf(original->target_relative, sizeof(original->target_relative), "runtime/bundles/%s/%s", original->bundle, relative);
    if (length <= 0 || (size_t)length >= sizeof(original->target_relative)) goto fail;
    length = snprintf(original->target, sizeof(original->target), "%s/%s", original->state_root, original->target_relative);
    if (length <= 0 || (size_t)length >= sizeof(original->target)) goto fail;
    length = snprintf(check->controller_path, sizeof(check->controller_path), "%s/%s", check->package_root, check->controller_relative);
    if (length <= 0 || (size_t)length >= sizeof(check->controller_path)) goto fail;
    error = "current upgrade controller identity is unavailable";
    process = installed_keeper_open_self(&failed);
    if (process < 0 || observe_process_with_retirement(original->process.pid, original->process.start_token, &original->process.retirement_failed) != 1) goto fail;
    original->process.image_fd = open_process_image(original->process.pid, original->process.uid, original->process.gid,
        original->process.image_path, &original->process.image, &original->process.retirement_failed);
    if (original->process.image_fd < 0 || !installed_upgrade_controller_current(check, process, &failed)) goto fail;
    error = "original keeper process or image is unavailable";
    proc = open("/proc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct statfs filesystem; struct stat metadata;
    char name[32]; length = snprintf(name, sizeof(name), "%ld", (long)original->peer_pid);
    if (proc < 0 || fstatfs(proc, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC || length <= 0 || (size_t)length >= sizeof(name)) goto fail;
    original->peer_process = openat(proc, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (original->peer_process < 0 || fstat(original->peer_process, &original->peer_directory) ||
        fstatfs(original->peer_process, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC ||
        !installed_anchor_start(original->peer_process, original->peer_pid, ticks, &failed)) goto fail;
    original->peer_image = installed_anchor_peer_image(original, &failed); unsigned char boot[16];
    if (original->peer_image < 0 || !installed_anchor_peer_current(original, &failed) || !installed_anchor_namespaces(original, process, 1, &failed) ||
        !installed_keeper_boot(boot, &failed) || memcmp(boot, original->boot, sizeof(boot))) goto fail;
    state = open_root_with_retirement(original->state_root, &failed);
    if (state < 0 || fstat(state, &metadata) || !installed_root_matches(&metadata, original->state_root_identity)) goto fail;
    image = installed_open_image(state, original->target_relative, &failed);
    if (image < 0 || fstat(image, &metadata) || !installed_executable(&metadata) || !installed_image_matches(&metadata, &original->expected_image)) goto fail;
    error = "original keeper held source is unavailable";
    if (!installed_anchor_fdinfo(original->peer_process, original->source_fd, &original->source, &failed) ||
        original->source.flags != (uint64_t)(O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) goto fail;
    source = openat(original->peer_process, "fd", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    length = snprintf(name, sizeof(name), "%d", original->source_fd);
    if (source < 0 || fstatfs(source, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC || length <= 0 || (size_t)length >= sizeof(name)) goto fail;
    original->root_fd = openat(source, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (original->root_fd < 0 || !installed_keeper_cgroup_identity(original->root_fd, original->process.uid, original->process.gid, &original->root, 1) ||
        (uint64_t)original->root.st_ino != original->source.inode || !installed_anchor_membership(original, 1, &failed) ||
        !installed_anchor_root_current(original, process, 1, &failed)) goto fail;
    installed_anchor_fd_info after;
    if (!installed_anchor_fdinfo(original->peer_process, original->source_fd, &after, &failed) || !installed_anchor_same_source(&original->source, &after)) goto fail;
    retire_process_fd(&source, &failed); retire_process_fd(&image, &failed); retire_process_fd(&state, &failed);
    retire_process_fd(&proc, &failed); retire_process_fd(&process, &failed);
    error = "current keeper check source changed during acquisition";
    if (failed || !installed_upgrade_keeper_current(check, &failed)) goto fail;
    napi_value result; const napi_property_descriptor methods[] = {
        {"assertCurrent", NULL, installed_upgrade_keeper_assert, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, installed_upgrade_keeper_close, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_create_object(env, &result) != napi_ok || napi_define_properties(env, result, 2, methods) != napi_ok ||
        napi_type_tag_object(env, result, &installed_upgrade_keeper_tag) != napi_ok || napi_object_freeze(env, result) != napi_ok ||
        !installed_upgrade_keeper_current(check, &failed) || napi_wrap(env, result, check, installed_upgrade_keeper_finalize, NULL, NULL) != napi_ok) goto fail;
    return result;
fail:
    retire_process_fd(&source, &failed); retire_process_fd(&image, &failed); retire_process_fd(&state, &failed);
    retire_process_fd(&proc, &failed); retire_process_fd(&process, &failed);
    if (!installed_anchor_close(original)) failed = 1;
    free(check); return installed_keeper_error(env, error, failed);
}
