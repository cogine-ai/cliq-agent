#ifndef CLIQ_SOURCE_GIT_OUTPUT_H
#define CLIQ_SOURCE_GIT_OUTPUT_H

/* Private, fixed four-role collector. The producer alone supplies its held
 * /scratch/output directory after the real helper joins; no NAPI path/FD or
 * authority is created here. Diagnosis is only a finite failed-operation
 * number; it never supplies output, identity, permission or death evidence. */
static void source_output_stage(uint32_t *failure, uint32_t value) {
    if (failure) *failure = value;
}
static const char *const source_output_names[CLIQ_SOURCE_OUTPUTS] = {
    "inspection.json", "canonical.index", "reachable.pack", "reachable.idx"
};
static bool source_output_inventory(int directory, const struct cliq_worker_packet *request,
    uint64_t *copy_capacity, uint32_t *failure) {
    source_output_stage(failure, CLIQ_SOURCE_OUTPUT_SCAN);
    int scan = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan < 0) return false;
    source_output_stage(failure, CLIQ_SOURCE_OUTPUT_SCAN_STREAM);
    DIR *stream = fdopendir(scan);
    if (!stream) { if (!source_close_fd(&scan)) source_output_stage(failure, CLIQ_SOURCE_OUTPUT_SCAN_CLOSE); return false; }
    bool valid = true; unsigned int seen = 0;
    for (;;) {
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_READ_DIRECTORY);
        errno = 0; struct dirent *entry = readdir(stream);
        if (!entry) { if (errno) valid = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        unsigned int at = 0; while (at < CLIQ_SOURCE_OUTPUTS && strcmp(entry->d_name, source_output_names[at]) != 0) at++;
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_NAME);
        if (at == CLIQ_SOURCE_OUTPUTS || (seen & (1U << at))) { valid = false; break; }
        seen |= 1U << at;
    }
    if (closedir(stream) != 0) { source_output_stage(failure, CLIQ_SOURCE_OUTPUT_SCAN_CLOSE); valid = false; }
    if (valid) { source_output_stage(failure, CLIQ_SOURCE_OUTPUT_COMPLETE_NAMES); valid = seen == 15; }
    *copy_capacity = 0;
    for (unsigned int i = 0; valid && i < CLIQ_SOURCE_OUTPUTS; i++) {
        struct stat file;
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_CAPACITY_FILE);
        valid = fstatat(directory, source_output_names[i], &file, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(file.st_mode) &&
            file.st_size >= 0 && (uint64_t)file.st_size <= request->max_file_bytes;
        if (valid) {
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_CAPACITY);
            valid = cliq_source_page_add(copy_capacity, (uint64_t)file.st_size, request->max_generation_bytes);
        }
    }
    return valid;
}
static bool source_output_copy(int directory, const struct cliq_worker_packet *request,
    int outputs[CLIQ_SOURCE_OUTPUTS], struct cliq_worker_packet *result, uint32_t *failure) {
    bool valid = true; uint64_t total = 0;
#define SOURCE_OUTPUT_CHECK(stage, expression) do { \
    if (valid) { source_output_stage(failure, (stage)); valid = (expression); } \
} while (0)
    for (unsigned int i = 0; valid && i < CLIQ_SOURCE_OUTPUTS; i++) {
        source_output_stage(failure, CLIQ_SOURCE_OUTPUT_OPEN);
        int file = openat(directory, source_output_names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        valid = file >= 0;
        struct stat before, after, named;
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_STAT, fstat(file, &before) == 0);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_TYPE, S_ISREG(before.st_mode));
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_LINKS, before.st_nlink == 1);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_UID, before.st_uid == geteuid());
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_SIZE, before.st_size >= 0 && (uint64_t)before.st_size <= request->max_file_bytes);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_METADATA_SIZE, i != 0 || (uint64_t)before.st_size <= request->max_output_bytes);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_TOTAL_SIZE, source_add_u64(&total, (uint64_t)before.st_size, request->max_generation_bytes));
        int writer = -1;
        if (valid) {
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_WRITER);
            writer = memfd_create("cliq-source-output", MFD_CLOEXEC | MFD_ALLOW_SEALING); valid = writer >= 0;
        }
        uint64_t offset = 0; unsigned char buffer[65536]; struct sha256_context hash; sha256_init(&hash);
        while (valid && offset < (uint64_t)before.st_size) {
            size_t wanted = (uint64_t)before.st_size - offset < sizeof(buffer) ? (size_t)((uint64_t)before.st_size - offset) : sizeof(buffer);
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_READ);
            ssize_t count = read(file, buffer, wanted);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { valid = false; break; }
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_WRITE);
            if (!source_write_all(writer, buffer, (size_t)count)) { valid = false; break; }
            sha256_update(&hash, buffer, (size_t)count); offset += (uint64_t)count;
        }
        unsigned char extra; ssize_t count = -1;
        if (valid) {
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_EOF);
            do { count = read(file, &extra, 1); } while (count < 0 && errno == EINTR);
            valid = count == 0;
        }
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_AFTER_STAT, fstat(file, &after) == 0);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_AFTER_IDENTITY, source_stat_same(&before, &after));
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_NAMED_STAT, fstatat(directory, source_output_names[i], &named, AT_SYMLINK_NOFOLLOW) == 0);
        SOURCE_OUTPUT_CHECK(CLIQ_SOURCE_OUTPUT_NAMED_IDENTITY, source_stat_same(&before, &named));
        if (!source_close_fd(&file)) { source_output_stage(failure, CLIQ_SOURCE_OUTPUT_FILE_CLOSE); valid = false; }
        if (valid) {
            source_output_stage(failure, CLIQ_SOURCE_OUTPUT_SEAL);
            outputs[i] = source_sealed_readonly(writer); valid = outputs[i] >= 0;
        }
        if (!source_close_fd(&writer)) { source_output_stage(failure, CLIQ_SOURCE_OUTPUT_WRITER_CLOSE); valid = false; }
        if (valid) {
            unsigned char digest[32]; sha256_final(&hash, digest);
            result->source_output_bytes[i] = offset; source_hex(digest, result->source_output_digests[i]);
        }
    }
#undef SOURCE_OUTPUT_CHECK
    return valid;
}
#endif
