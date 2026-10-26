/* Client-owned duplicates of inherited standard output only. No arbitrary FD,
 * path, StateOwner, execution or recovery authority is accepted here. */
static int client_stdio_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode;
}

static int client_stdio_duplicate(int original, int *retirement_failed) {
    struct stat before, held, after;
    int flags = fcntl(original, F_GETFL);
    if (flags < 0 || !(flags & O_NONBLOCK) || (flags & O_ACCMODE) == O_RDONLY ||
        fstat(original, &before) != 0 || (!S_ISFIFO(before.st_mode) && !S_ISSOCK(before.st_mode))) return -1;
    int duplicate = fcntl(original, F_DUPFD_CLOEXEC, 3);
    int descriptor_flags = duplicate < 0 ? -1 : fcntl(duplicate, F_GETFD);
    if (duplicate >= 0 && fstat(duplicate, &held) == 0 && fstat(original, &after) == 0 &&
        client_stdio_same(&before, &held) && client_stdio_same(&before, &after) &&
        fcntl(original, F_GETFL) == flags && fcntl(duplicate, F_GETFL) == flags &&
        descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0) return duplicate;
    if (duplicate >= 0 && close(duplicate) != 0) *retirement_failed = 1;
    return -1;
}

#ifndef CLIQ_CLIENT_STDIO_COMPONENT
static napi_value duplicate_client_stdio(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1]; void *data = NULL;
    if (napi_get_cb_info(env, info, &argc, argv, NULL, &data) != napi_ok || argc != 0)
        return native_error(env, "client stdio duplication takes no arguments");
    int retirement_failed = 0, duplicate = client_stdio_duplicate(data == (void *)1 ? STDOUT_FILENO : STDERR_FILENO, &retirement_failed);
    napi_value value;
    if (duplicate >= 0 && napi_create_int32(env, duplicate, &value) == napi_ok) return value;
    if (duplicate >= 0 && close(duplicate) != 0) retirement_failed = 1;
    if (retirement_failed) {
        napi_throw_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "client stdio duplicate did not retire");
        return NULL;
    }
    return native_error(env, "client stdio is not a stable inherited nonblocking pipe or socket");
}
#endif
