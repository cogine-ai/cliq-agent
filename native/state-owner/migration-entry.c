/* Read-only fixed Legacy rendezvous. The actual account SH prevents supported
 * cutover writers for the complete entry lifetime. No caller-selected leaf,
 * output path, mode, FD or publication operation exists. */
typedef struct migration_entry_read {
    int fds[65], file;
    struct stat ids[65], entry;
    char names[64][NAME_MAX + 1];
    size_t count;
    unsigned char *bytes;
    size_t size;
    int uncertain;
} migration_entry_read;

static int migration_entry_join(migration_entry_read *read, kernel_global_gate *gate) {
    int descriptor = read->file; read->file = -1;
    if (descriptor >= 0 && close(descriptor) != 0) read->uncertain = 1;
    for (size_t index = read->count; index > 0; --index) {
        descriptor = read->fds[index - 1]; read->fds[index - 1] = -1;
        if (descriptor >= 0 && close(descriptor) != 0) read->uncertain = 1;
    }
    if (read->uncertain) { gate->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return -1; }
    return 0;
}
static int migration_entry_chain_held(const migration_entry_read *read) {
    struct stat held, named;
    for (size_t index = 0; index < read->count; ++index) {
        const struct stat *original = &read->ids[index];
        if (read->fds[index] < 0 || fstat(read->fds[index], &held) != 0 || !S_ISDIR(held.st_mode) ||
            !same_inode(&held, original) || held.st_uid != original->st_uid || held.st_gid != original->st_gid ||
            held.st_mode != original->st_mode) return -1;
        if (index && (fstatat(read->fds[index - 1], read->names[index - 1], &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(named.st_mode) || !same_inode(&held, &named) || named.st_uid != held.st_uid ||
            named.st_gid != held.st_gid || named.st_mode != held.st_mode)) return -1;
    }
    return 0;
}
static napi_value migration_entry_inspect(napi_env env, napi_callback_info info, int auth_marker) {
    size_t count = 5; napi_value arguments[5]; bool tagged = false;
    kernel_global_gate *gate = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != (auth_marker ? 4U : 2U) ||
        napi_check_object_type_tag(env, arguments[0], &kernel_global_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&gate) != napi_ok || !gate || gate->exclusive ||
        kernel_global_check(gate, env) != 0)
        return kernel_global_error(env, "ERR_CLIQ_KERNEL_GLOBAL_GATE", "Legacy entry requires its genuine same-account shared gate");
    char expected_digest[65] = {0}; uint32_t expected_count = 0; double exact_count = 0;
    if (auth_marker && (migrate_scope_text(env, arguments[2], expected_digest, sizeof(expected_digest)) != 0 ||
        strlen(expected_digest) != 64 || strspn(expected_digest, "0123456789abcdef") != 64 ||
        napi_get_value_uint32(env, arguments[3], &expected_count) != napi_ok ||
        napi_get_value_double(env, arguments[3], &exact_count) != napi_ok || exact_count != (double)expected_count ||
        !expected_count || expected_count > 1048576))
        return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "Legacy auth observation requires its complete retained marker identity");
    const char *leaf = auth_marker ? "auth.json" : ".cliq-generation-v1.json";
    char path[PATH_MAX];
    if (migrate_scope_text(env, arguments[1], path, sizeof(path)) != 0 || path[0] != '/' || !path[1] ||
        path[strlen(path) - 1] == '/')
        return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "Legacy entry root is not a fixed canonical locator");
    migration_entry_read *read = calloc(1, sizeof(*read));
    if (!read) return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "Legacy entry allocation failed");
    read->file = -1;
    for (size_t index = 0; index < sizeof(read->fds) / sizeof(read->fds[0]); ++index) read->fds[index] = -1;
    const char *error = "Legacy rendezvous root or fixed entry is unavailable";
    const char *kind = NULL;
    read->fds[0] = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); read->count = 1;
    if (read->fds[0] < 0 || fstat(read->fds[0], &read->ids[0]) != 0) goto done;
    char *part = path + 1;
    for (;;) {
        char *end = strchr(part, '/'); if (end) *end = '\0';
        size_t length = strlen(part), index = read->count;
        if (!length || length > NAME_MAX || index >= 65 || !strcmp(part, ".") || !strcmp(part, "..")) goto done;
        memcpy(read->names[index - 1], part, length + 1);
        int next = openat(read->fds[index - 1], part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            if (errno == ENOENT && migration_entry_chain_held(read) == 0) kind = "legacy_root_absent";
            goto done;
        }
        read->fds[index] = next; read->count++;
        if (fstat(next, &read->ids[index]) != 0 || !S_ISDIR(read->ids[index].st_mode)) goto done;
        if (!end) break;
        part = end + 1;
    }
    const struct stat *root = &read->ids[read->count - 1];
    if (root->st_uid != gate->uid || (root->st_mode & 07022) != 0 || migration_entry_chain_held(read) != 0) goto done;
    int parent = read->fds[read->count - 1];
    struct stat named, after;
    if (fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) kind = "rendezvous_absent";
        goto done;
    }
    if (!S_ISREG(named.st_mode) || named.st_uid != gate->uid || named.st_dev != root->st_dev ||
        (named.st_mode & 07777) != 0600 || named.st_nlink != 1 || named.st_size < 1 || named.st_size > 1048576) goto done;
    read->file = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (read->file < 0 || fstat(read->file, &read->entry) != 0 || !source_metadata_same(&named, &read->entry)) goto done;
    read->size = (size_t)read->entry.st_size; read->bytes = malloc(read->size);
    if (!read->bytes) goto done;
    size_t offset = 0;
    while (offset < read->size) {
        size_t wanted = read->size - offset; if (wanted > 65536) wanted = 65536;
        ssize_t size; do { size = pread(read->file, read->bytes + offset, wanted, (off_t)offset); } while (size < 0 && errno == EINTR);
        if (size <= 0 || (size_t)size > wanted) goto done;
        offset += (size_t)size;
    }
    unsigned char extra;
    ssize_t end; do { end = pread(read->file, &extra, 1, (off_t)read->size); } while (end < 0 && errno == EINTR);
    if (end != 0 || fstat(read->file, &after) != 0 || !source_metadata_same(&after, &read->entry) ||
        fstatat(parent, leaf, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !source_metadata_same(&after, &read->entry)) goto done;
    kind = "rendezvous_present";
done:
    if (kind && (migration_entry_chain_held(read) != 0 || kernel_global_check(gate, env) != 0)) kind = NULL;
    char digest[65] = {0};
    if (kind && !strcmp(kind, "rendezvous_present")) {
        struct sha256_context hash; sha256_init(&hash); sha256_update(&hash, read->bytes, read->size); publication_hash_hex(&hash, digest);
    }
    if (auth_marker) {
        if (!kind || strcmp(kind, "rendezvous_present") || read->size != expected_count || strcmp(digest, expected_digest)) kind = NULL;
        else kind = "matched_auth_bytes";
    }
    napi_value result = NULL;
    if (kind) {
        napi_value label;
        if (napi_create_object(env, &result) != napi_ok || napi_create_string_utf8(env, kind, NAPI_AUTO_LENGTH, &label) != napi_ok ||
            napi_set_named_property(env, result, "kind", label) != napi_ok) result = NULL;
        if (result && (auth_marker || !strcmp(kind, "rendezvous_present"))) {
            const struct stat *original_root = &read->ids[read->count - 1];
            char device[32], inode[32]; napi_value identity, uid;
            snprintf(device, sizeof(device), "%ju", (uintmax_t)original_root->st_dev);
            snprintf(inode, sizeof(inode), "%ju", (uintmax_t)original_root->st_ino);
            if (napi_create_object(env, &identity) != napi_ok ||
                !publication_set_string(env, identity, "deviceId", device) || !publication_set_string(env, identity, "fileId", inode) ||
                napi_create_uint32(env, original_root->st_uid, &uid) != napi_ok ||
                napi_set_named_property(env, identity, "ownerUid", uid) != napi_ok || napi_object_freeze(env, identity) != napi_ok ||
                napi_set_named_property(env, result, "rootIdentity", identity) != napi_ok) result = NULL;
        }
        if (result && auth_marker) {
            napi_value size, content;
            if (napi_create_double(env, (double)read->size, &size) != napi_ok ||
                napi_create_string_utf8(env, digest, 64, &content) != napi_ok ||
                napi_set_named_property(env, result, "byteCount", size) != napi_ok ||
                napi_set_named_property(env, result, "contentDigest", content) != napi_ok) result = NULL;
        } else if (result && !strcmp(kind, "rendezvous_present")) {
            napi_value bytes, digest_value;
            if (napi_create_buffer_copy(env, read->size, read->bytes, NULL, &bytes) != napi_ok ||
                napi_create_string_utf8(env, digest, 64, &digest_value) != napi_ok ||
                napi_set_named_property(env, result, "bytes", bytes) != napi_ok ||
                napi_set_named_property(env, result, "contentDigest", digest_value) != napi_ok) result = NULL;
        }
    }
    if (auth_marker && read->bytes) {
        volatile unsigned char *secret = read->bytes;
        for (size_t index = 0; index < read->size; ++index) secret[index] = 0;
    }
    free(read->bytes); read->bytes = NULL;
    if (migration_entry_join(read, gate) != 0) {
        /* Keep the original failed reader allocation and poisoned SH through
         * process death. No finalizer retries consumed descriptor numbers. */
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "Legacy rendezvous original descriptors did not retire");
    }
    free(read);
    if (!result) return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", error);
    return result;
}
static napi_value inspect_legacy_entry(napi_env env, napi_callback_info info) { return migration_entry_inspect(env, info, 0); }
/* The only auth entry exports a digest equality observation, never raw bytes,
 * even when the actual source is corrupt or still contains a private key. */
static napi_value verify_legacy_migrated_auth(napi_env env, napi_callback_info info) { return migration_entry_inspect(env, info, 1); }
