/* Fixed readonly startup data under the original StateOwner root FD. This
 * observes current complete bytes; it grants no creator, recovery or execution
 * authority. Store separately retains genuine account SH throughout use. */
typedef struct kernel_migration_document {
    int fd, present;
    struct stat identity;
    unsigned char *bytes;
    size_t count;
} kernel_migration_document;
static int kernel_migration_read_document(int parent, const char *leaf, uid_t uid, dev_t device,
                                         kernel_migration_document *document) {
    struct stat named, after;
    if (fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(named.st_mode) || named.st_uid != uid || named.st_dev != device ||
        (named.st_mode & 07777) != 0600 || named.st_nlink != 1 || named.st_size < 1 || named.st_size > 1048576) return -1;
    document->fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (document->fd < 0 || fstat(document->fd, &document->identity) != 0 || !source_metadata_same(&named, &document->identity)) return -1;
    document->present = 1; document->count = (size_t)named.st_size; document->bytes = malloc(document->count);
    if (!document->bytes) return -1;
    size_t offset = 0;
    while (offset < document->count) {
        size_t wanted = document->count - offset; if (wanted > 65536) wanted = 65536;
        ssize_t count; do { count = pread(document->fd, document->bytes + offset, wanted, (off_t)offset); } while (count < 0 && errno == EINTR);
        if (count <= 0 || (size_t)count > wanted) return -1;
        offset += (size_t)count;
    }
    unsigned char byte; ssize_t end;
    do { end = pread(document->fd, &byte, 1, (off_t)document->count); } while (end < 0 && errno == EINTR);
    return end == 0 && fstat(document->fd, &after) == 0 && source_metadata_same(&after, &document->identity) &&
        fstatat(parent, leaf, &after, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&after, &document->identity) ? 0 : -1;
}
static int kernel_migration_document_same(int parent, const char *leaf, const kernel_migration_document *document) {
    struct stat named, held;
    if (!document->present) return fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT ? 0 : -1;
    return document->fd >= 0 && fstat(document->fd, &held) == 0 && source_metadata_same(&held, &document->identity) &&
        fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&named, &document->identity) ? 0 : -1;
}
static napi_value inspect_kernel_migration_entry(napi_env env, napi_callback_info info) {
    size_t count = 2; napi_value arguments[2]; bool tagged = false; state_lock *lock = NULL;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 1 ||
        napi_check_object_type_tag(env, arguments[0], &lock_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&lock) != napi_ok || !lock || lock->owner_env != env ||
        lock->owner_pid != getpid() || lock->owner_uid != geteuid() || lock->owner_gid != getegid() ||
        !pthread_equal(lock->owner_thread, pthread_self()) || lock->migration_retirement_error)
        return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "Kernel migration startup requires its original StateOwner holder");
    int retirement = 0, valid = lock_is_held_with_retirement(lock, &retirement), parent = -1, absent = 0;
    struct stat directory, named;
    kernel_migration_document documents[2]; memset(documents, 0, sizeof(documents)); documents[0].fd = documents[1].fd = -1;
    if (!valid || retirement) goto done;
    if (fstatat(lock->root_fd, "migration", &named, AT_SYMLINK_NOFOLLOW) != 0) {
        absent = errno == ENOENT; valid = absent; goto done;
    }
    if (!private_directory(&named) || named.st_dev != lock->root.st_dev) { valid = 0; goto done; }
    parent = openat(lock->root_fd, "migration", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || fstat(parent, &directory) != 0 || !source_metadata_same(&named, &directory)) { valid = 0; goto done; }
    valid = kernel_migration_read_document(parent, "control-v1.json", lock->owner_uid, directory.st_dev, &documents[0]) == 0 &&
        kernel_migration_read_document(parent, "authority-v1.json", lock->owner_uid, directory.st_dev, &documents[1]) == 0;
    if (valid) valid = (!documents[1].present || documents[0].present) &&
        kernel_migration_document_same(parent, "control-v1.json", &documents[0]) == 0 &&
        kernel_migration_document_same(parent, "authority-v1.json", &documents[1]) == 0 &&
        fstat(parent, &named) == 0 && source_metadata_same(&named, &directory) &&
        fstatat(lock->root_fd, "migration", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&named, &directory);
done:
    if (valid && !retirement) valid = lock_is_held_with_retirement(lock, &retirement);
    napi_value result = NULL;
    if (valid && !retirement && napi_create_object(env, &result) == napi_ok) {
        napi_value kind;
        const char *label = absent || !documents[0].present ? "unmigrated" : "controlled";
        if (napi_create_string_utf8(env, label, NAPI_AUTO_LENGTH, &kind) != napi_ok ||
            napi_set_named_property(env, result, "kind", kind) != napi_ok) result = NULL;
        for (size_t index = 0; result && index < 2; ++index) if (documents[index].present) {
            napi_value bytes;
            if (napi_create_buffer_copy(env, documents[index].count, documents[index].bytes, NULL, &bytes) != napi_ok ||
                napi_set_named_property(env, result, index ? "authorityBytes" : "controlBytes", bytes) != napi_ok) result = NULL;
        }
        if (result && napi_object_freeze(env, result) != napi_ok) result = NULL;
    }
    for (size_t index = 0; index < 2; ++index) {
        int fd = documents[index].fd; documents[index].fd = -1;
        if (fd >= 0 && close(fd) != 0) retirement = 1;
        free(documents[index].bytes);
    }
    if (parent >= 0 && close(parent) != 0) retirement = 1;
    if (retirement) {
        lock->migration_retirement_error = 1; atomic_store(&kernel_global_poisoned, 1);
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "Kernel migration startup descriptors did not actually retire");
    }
    return result ? result : kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "Kernel migration startup data is unavailable");
}

/* Before the first SQL/StateOwner action, inspect only the original selected
 * RootFD under this actual account SH. A completed Legacy marker must refuse
 * Kernel entry before it could create a successor Owner. No path/leaf/create
 * option or temporary Owner is accepted. */
static int kernel_migration_selected_root(int fd, const uint64_t tuple[5], struct stat *identity) {
    return fd >= 0 && fstat(fd, identity) == 0 && private_directory(identity) &&
        (uint64_t)identity->st_dev == tuple[0] && (uint64_t)identity->st_ino == tuple[1] &&
        (uint64_t)identity->st_uid == tuple[2] && (uint64_t)identity->st_gid == tuple[3] &&
        (uint64_t)identity->st_mode == tuple[4] ? 0 : -1;
}
static napi_value inspect_kernel_migration_before_owner(napi_env env, napi_callback_info info) {
    size_t count = 4; napi_value arguments[4]; bool tagged = false; kernel_global_gate *gate = NULL;
    int32_t root_fd = -1; uint32_t length = 0; uint64_t tuple[5]; struct stat root, current, named, directory;
    if (!kernel_global_main_thread() || napi_get_cb_info(env, info, &count, arguments, NULL, NULL) != napi_ok || count != 3 ||
        napi_check_object_type_tag(env, arguments[0], &kernel_global_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arguments[0], (void **)&gate) != napi_ok || !gate || gate->exclusive || kernel_global_check(gate, env) != 0 ||
        napi_get_value_int32(env, arguments[1], &root_fd) != napi_ok ||
        napi_get_array_length(env, arguments[2], &length) != napi_ok || length != 5)
        return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "pre-Owner startup requires its original account SH and selected root");
    for (uint32_t index = 0; index < 5; ++index) {
        napi_value item; bool lossless = false;
        if (napi_get_element(env, arguments[2], index, &item) != napi_ok ||
            napi_get_value_bigint_uint64(env, item, &tuple[index], &lossless) != napi_ok || !lossless)
            return kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "pre-Owner selected root identity is not exact");
    }
    int valid = kernel_migration_selected_root(root_fd, tuple, &root) == 0 && root.st_uid == gate->uid;
    int parent = -1, absent = 0, retirement = 0;
    kernel_migration_document documents[2]; memset(documents, 0, sizeof(documents)); documents[0].fd = documents[1].fd = -1;
    if (!valid) goto done;
    if (fstatat(root_fd, "migration", &named, AT_SYMLINK_NOFOLLOW) != 0) {
        absent = errno == ENOENT; valid = absent; goto done;
    }
    if (!private_directory(&named) || named.st_dev != root.st_dev) { valid = 0; goto done; }
    parent = openat(root_fd, "migration", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || fstat(parent, &directory) != 0 || !source_metadata_same(&named, &directory)) { valid = 0; goto done; }
    valid = kernel_migration_read_document(parent, "control-v1.json", root.st_uid, root.st_dev, &documents[0]) == 0 &&
        kernel_migration_read_document(parent, "authority-v1.json", root.st_uid, root.st_dev, &documents[1]) == 0;
    if (valid) valid = (!documents[1].present || documents[0].present) &&
        kernel_migration_document_same(parent, "control-v1.json", &documents[0]) == 0 &&
        kernel_migration_document_same(parent, "authority-v1.json", &documents[1]) == 0 &&
        fstat(parent, &named) == 0 && source_metadata_same(&named, &directory) &&
        fstatat(root_fd, "migration", &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&named, &directory);
done:
    if (valid) valid = kernel_global_check(gate, env) == 0 &&
        kernel_migration_selected_root(root_fd, tuple, &current) == 0 && source_metadata_same(&root, &current);
    napi_value result = NULL;
    if (valid && napi_create_object(env, &result) == napi_ok) {
        const char *label = absent || !documents[0].present ? "unmigrated" : "controlled";
        if (!publication_set_string(env, result, "kind", label)) result = NULL;
        for (size_t index = 0; result && index < 2; ++index) if (documents[index].present) {
            napi_value bytes;
            if (napi_create_buffer_copy(env, documents[index].count, documents[index].bytes, NULL, &bytes) != napi_ok ||
                napi_set_named_property(env, result, index ? "authorityBytes" : "controlBytes", bytes) != napi_ok) result = NULL;
        }
        if (result && napi_object_freeze(env, result) != napi_ok) result = NULL;
    }
    for (size_t index = 0; index < 2; ++index) {
        int fd = documents[index].fd; documents[index].fd = -1;
        if (fd >= 0 && close(fd) != 0) retirement = 1;
        free(documents[index].bytes);
    }
    if (parent >= 0 && close(parent) != 0) retirement = 1;
    if (retirement) {
        gate->uncertain = 1; atomic_store(&kernel_global_poisoned, 1);
        return kernel_global_error(env, "ERR_CLIQ_RESOURCE_RETIREMENT", "pre-Owner migration data descriptors did not actually retire");
    }
    return result ? result : kernel_global_error(env, "ERR_CLIQ_MIGRATION_ENTRY", "pre-Owner migration data is unavailable");
}
