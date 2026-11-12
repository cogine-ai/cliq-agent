/* Fixed private runtime-witness archive pack. The original retirement reader
 * supplies each closed original launch witness before capture. The packer
 * independently pins the fixed source, verifies every byte and exact census,
 * and creates only one fixed archive file. No paths, FDs or new authority
 * escape this helper. Included once in the signed StateOwner translation unit. */
#ifndef CLIQ_KERNEL_ARCHIVE_RUNTIME_WITNESS_H
#define CLIQ_KERNEL_ARCHIVE_RUNTIME_WITNESS_H
#define RW_PACK_NAME "local-inference-witnesses.bin"
#define RW_HEADER 64U
#define RW_RECORD 224U
#define RW_FRAME 4144U
#define RW_MAX_WITNESS_BYTES (RW_FRAME * 128U)
#define RW_MAX_COUNT 1048576U
#define RW_MAX_BYTES UINT64_C(53687091200)
enum rw_phase { RW_SOURCE, RW_CAPTURE, RW_HASH_WRITABLE, RW_HASH_READONLY, RW_COMPLETE };
typedef struct rw_retirement_observation rw_retirement_observation;
typedef struct rw_archive {
    napi_env env;
    migration_credential_gate *binding;
    int archive_fd, source_fd, pack_fd, pack_reader_fd, witness_fd, failed, uncertain;
    struct stat archive, source, pack, witness;
    DIR *scan;
    uint64_t count, witnessed, total, limit, pack_size, offset, witness_offset, checked, scanned;
    unsigned char record[RW_RECORD];
    char prior_launch[44], name[65], pack_digest[65], payload_digest[65];
    struct sha256_context payload_hash, pack_hash, witness_hash;
    enum rw_phase phase;
    int verify_stage, capture_writer;
    rw_retirement_observation *retirement;
    uint64_t physically_observed;
    char observed_launch[44], observed_nonce[65], observed_digest[65];
    char observed_namespace_start[192];
    struct stat observed_file;
    uint64_t observed_cgroup_inode, observed_namespace_inode;
    unsigned int observed_kind;
    int observation_ready;
} rw_archive;
static int rw_retire_observer(rw_archive *held);
static void rw_put32(unsigned char *bytes, uint32_t value) {
    for (unsigned int index = 0; index < 4; ++index) bytes[index] = (unsigned char)(value >> (8 * index));
}
static void rw_put64(unsigned char *bytes, uint64_t value) {
    for (unsigned int index = 0; index < 8; ++index) bytes[index] = (unsigned char)(value >> (8 * index));
}
static int rw_close_fd(rw_archive *held, int *fd) {
    int original = *fd; *fd = -1;
    if (original < 0 || close(original) == 0) return 0;
    held->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return -1;
}
static int rw_close_scan(rw_archive *held) {
    DIR *original = held->scan; held->scan = NULL;
    if (!original || closedir(original) == 0) return 0;
    held->uncertain = 1; atomic_store(&kernel_global_poisoned, 1); return -1;
}
static inline int rw_retire(rw_archive *held) {
    if (!held) return 0;
    int failed = rw_close_scan(held) != 0;
    if (rw_retire_observer(held) != 0) failed = 1;
    int *const descriptors[] = {&held->witness_fd, &held->pack_reader_fd, &held->pack_fd, &held->source_fd};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (rw_close_fd(held, descriptors[index]) != 0) failed = 1;
    if (held->uncertain || failed) return -1;
    free(held); return 0;
}
static int rw_source_custody(const rw_archive *held) {
    state_lock *owner = held->binding->owner;
    struct stat runtime, named;
    return fstat(owner->runtime_fd, &runtime) == 0 && private_directory(&runtime) && same_inode(&runtime, &owner->runtime) &&
        fstatat(owner->root_fd, "runtime", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &runtime) &&
        ma_named_directory(owner->runtime_fd, "local-inference", held->source_fd, &held->source, 1);
}
static int rw_pack_current(const rw_archive *held, mode_t mode, int sealed) {
    struct stat actual, named;
    return held->pack_fd >= 0 && fstat(held->pack_fd, &actual) == 0 && S_ISREG(actual.st_mode) &&
        actual.st_uid == geteuid() && actual.st_gid == getegid() && actual.st_dev == held->archive.st_dev &&
        (actual.st_mode & 07777) == mode && actual.st_nlink == 1 && actual.st_size >= 0 &&
        same_inode(&actual, &held->pack) && (!sealed || source_metadata_same(&actual, &held->pack)) &&
        fstatat(held->archive_fd, RW_PACK_NAME, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&actual, &named);
}
static inline int rw_custody(const rw_archive *held) {
    if (!held) return 0;
    struct stat archive;
    if (held->uncertain || !rw_source_custody(held) ||
        (held->archive_fd >= 0 && (fstat(held->archive_fd, &archive) != 0 || !private_directory(&archive) ||
            !same_inode(&archive, &held->archive)))) return -1;
    if (held->pack_fd >= 0 && !rw_pack_current(held, held->phase >= RW_HASH_READONLY ? 0400 : 0600,
        held->phase >= RW_HASH_WRITABLE)) return -1;
    if (held->pack_reader_fd >= 0 && (fstat(held->pack_reader_fd, &archive) != 0 || !source_metadata_same(&archive, &held->pack)))
        return -1;
    return 0;
}
/* 0 is one actual original source directory; 1 is proven no-follow ENOENT.
 * The parent has already checked this same genuine migration binding. */
static inline int rw_open_source(napi_env env, migration_credential_gate *binding, rw_archive **output) {
    *output = NULL;
    if (!kernel_global_main_thread() || migration_credential_check(binding, env) != 0) return -1;
    int parent = binding->owner->runtime_fd; struct stat named;
    if (fstatat(parent, "local-inference", &named, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT ? 1 : -1;
    if (!private_directory(&named) || named.st_gid != getegid() || named.st_dev != binding->owner->root.st_dev) return -1;
    rw_archive *held = calloc(1, sizeof(*held)); if (!held) return -1;
    *output = held; held->env = env; held->binding = binding;
    held->archive_fd = held->source_fd = held->pack_fd = held->pack_reader_fd = held->witness_fd = -1; held->phase = RW_SOURCE;
    held->source_fd = openat(parent, "local-inference", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (held->source_fd < 0 || fstat(held->source_fd, &held->source) != 0 || !source_metadata_same(&named, &held->source) ||
        rw_custody(held) != 0) return -1;
    return 0;
}
static inline int rw_bind_archive(rw_archive *held, int fd, const struct stat *archive) {
    struct stat actual;
    if (!held || held->phase != RW_SOURCE || held->archive_fd >= 0 || !archive || fd < 0 ||
        fstat(fd, &actual) != 0 || !private_directory(&actual) || !same_inode(&actual, archive) ||
        actual.st_dev != held->source.st_dev || rw_custody(held) != 0) return -1;
    held->archive_fd = fd; held->archive = *archive; return 0;
}
static int rw_write(int fd, const unsigned char *bytes, size_t amount, uint64_t offset) {
    size_t done = 0;
    while (done < amount) {
        ssize_t count = pwrite(fd, bytes + done, amount - done, (off_t)(offset + done));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > amount - done) return -1;
        done += (size_t)count;
    }
    return 0;
}
static void rw_header(const rw_archive *held, unsigned char bytes[RW_HEADER]) {
    memset(bytes, 0, RW_HEADER); memcpy(bytes, "CLQIW001", 8);
    rw_put64(bytes + 8, held->count); rw_put64(bytes + 16, held->total);
    rw_put64(bytes + 24, ma_device(&held->source)); rw_put64(bytes + 32, (uint64_t)held->source.st_ino);
    rw_put32(bytes + 40, (uint32_t)held->source.st_uid); rw_put32(bytes + 44, 0700); rw_put32(bytes + 48, RW_RECORD);
}
static inline int rw_begin_capture(rw_archive *held, uint64_t count, uint64_t limit) {
    if (!held || held->phase != RW_SOURCE || held->failed || held->archive_fd < 0 || rw_custody(held) != 0 || count > RW_MAX_COUNT ||
        limit > RW_MAX_BYTES || RW_HEADER + count * (RW_RECORD + RW_FRAME) > limit) return -1;
    held->count = count; held->limit = limit; held->capture_writer = 1;
    held->pack_fd = openat(held->archive_fd, RW_PACK_NAME, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (held->pack_fd < 0 || fstat(held->pack_fd, &held->pack) != 0 || !rw_pack_current(held, 0600, 0)) return -1;
    unsigned char bytes[RW_HEADER]; rw_header(held, bytes);
    if (rw_write(held->pack_fd, bytes, sizeof(bytes), 0) != 0 || fsync(held->pack_fd) != 0 || fsync(held->archive_fd) != 0)
        return -1;
    held->phase = RW_CAPTURE; held->offset = RW_HEADER; sha256_init(&held->payload_hash); return 0;
}
static int rw_witness_file(const rw_archive *held, const struct stat *file) {
    return S_ISREG(file->st_mode) && file->st_dev == held->source.st_dev && file->st_uid == held->source.st_uid &&
        file->st_gid == held->source.st_gid && (file->st_mode & 07777) == 0600 && file->st_nlink == 1 &&
        file->st_size >= RW_FRAME && (uint64_t)file->st_size <= RW_MAX_WITNESS_BYTES && file->st_size % RW_FRAME == 0;
}
static int rw_current_witness(const rw_archive *held) {
    struct stat actual, named;
    return held->witness_fd >= 0 && fstat(held->witness_fd, &actual) == 0 && rw_witness_file(held, &actual) &&
        source_metadata_same(&actual, &held->witness) &&
        fstatat(held->source_fd, held->name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_metadata_same(&actual, &named);
}
static int rw_launch_id(const unsigned char *bytes) {
    const char allowed[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    for (size_t index = 0; index < 43; ++index) if (!bytes[index] || !strchr(allowed, bytes[index])) return 0;
    return 1;
}
static int rw_entry(rw_archive *held, const unsigned char *packet, size_t size) {
    if (size != RW_RECORD || held->witness_fd >= 0 || !rw_launch_id(packet + 32) ||
        (packet[204] != 1 && packet[204] != 2) || ma_u32(packet + 200) >= 1000000000U) return -1;
    for (size_t index = 75; index < 80; ++index) if (packet[index]) return -1;
    for (size_t index = 205; index < RW_RECORD; ++index) if (packet[index]) return -1;
    char launch[44] = {0}; memcpy(launch, packet + 32, 43);
    uint64_t bytes = ma_u64(packet + 88);
    if (strcmp(held->prior_launch, launch) >= 0 || bytes < RW_FRAME || bytes > RW_MAX_WITNESS_BYTES || bytes % RW_FRAME ||
        !ma_u64(packet + 80)) return -1;
    for (size_t index = 0; index < 32; ++index) snprintf(held->name + index * 2, 3, "%02x", packet[index]);
    held->witness_fd = openat(held->source_fd, held->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (held->witness_fd < 0 || fstat(held->witness_fd, &held->witness) != 0 || !rw_current_witness(held) ||
        (uint64_t)held->witness.st_ino != ma_u64(packet + 80) || (uint64_t)held->witness.st_size != bytes) return -1;
    int64_t seconds; uint32_t nanos; ma_times(&held->witness, &seconds, &nanos);
    if ((uint64_t)seconds != ma_u64(packet + 192) || nanos != ma_u32(packet + 200)) return -1;
    /* Each fixed original birth packet repeats launchId and nonce. Combined
     * with strictly increasing launch IDs this proves unique named files,
     * without a second large metadata index alongside the original CAS. */
    unsigned char birth[RW_FRAME];
    if (ma_pread(held->witness_fd, birth, sizeof(birth), 0) != 0 || ma_u32(birth) != 0x434c4231U ||
        ma_u32(birth + 4) != 1 || ma_u32(birth + 8) != 1 || ma_u32(birth + 12) != 1 ||
        memcmp(birth + 618, launch, sizeof(launch)) || memcmp(birth + 2429, held->name, sizeof(held->name)) ||
        !rw_current_witness(held)) return -1;
    memcpy(held->prior_launch, launch, sizeof(launch)); memcpy(held->record, packet, RW_RECORD);
    held->witness_offset = 0; sha256_init(&held->witness_hash); return 0;
}
static inline int rw_begin_entry(rw_archive *held, const unsigned char *packet, size_t size) {
    if (!held || held->phase != RW_CAPTURE || held->failed || rw_custody(held) != 0 ||
        held->witnessed >= held->count || size != RW_RECORD || held->offset > held->limit ||
        RW_RECORD > held->limit - held->offset || ma_u64(packet + 88) > held->limit - held->offset - RW_RECORD ||
        !held->observation_ready || held->observed_kind != packet[204] || memcmp(packet + 32, held->observed_launch, 44) ||
        ma_u64(packet + 80) != (uint64_t)held->observed_file.st_ino || ma_u64(packet + 88) != (uint64_t)held->observed_file.st_size ||
        rw_entry(held, packet, size) != 0) return -1;
    char digest[65];
    for (size_t index = 0; index < 32; ++index) snprintf(digest + index * 2, 3, "%02x", packet[index + 96]);
    if (strcmp(digest, held->observed_digest) || strcmp(held->name, held->observed_nonce) ||
        !source_metadata_same(&held->witness, &held->observed_file) ||
        rw_write(held->pack_fd, held->record, RW_RECORD, held->offset) != 0) return -1;
    held->observation_ready = 0;
    sha256_update(&held->payload_hash, held->record, RW_RECORD); held->offset += RW_RECORD; return 0;
}
static int rw_witness_end(rw_archive *held) {
    unsigned char expected[32], end; ssize_t count;
    do { count = pread(held->witness_fd, &end, 1, (off_t)held->witness_offset); } while (count < 0 && errno == EINTR);
    sha256_final(&held->witness_hash, expected);
    if (count || memcmp(expected, held->record + 96, sizeof(expected)) || !rw_current_witness(held) ||
        fsync(held->witness_fd) != 0 || rw_close_fd(held, &held->witness_fd) != 0) return -1;
    return 0;
}
static inline int rw_capture_entry_next(rw_archive *held) {
    if (!held || held->phase != RW_CAPTURE || held->failed || rw_custody(held) != 0 || !rw_current_witness(held)) return -1;
    uint64_t total = ma_u64(held->record + 88);
    if (held->witness_offset == total) {
        if (rw_witness_end(held) != 0) return -1;
        held->total += total; held->witnessed++; return 1;
    }
    unsigned char bytes[65536]; size_t amount = total - held->witness_offset < sizeof(bytes) ? (size_t)(total - held->witness_offset) : sizeof(bytes);
    if (ma_pread(held->witness_fd, bytes, amount, held->witness_offset) != 0 || !rw_current_witness(held) ||
        rw_write(held->pack_fd, bytes, amount, held->offset) != 0) return -1;
    sha256_update(&held->witness_hash, bytes, amount); sha256_update(&held->payload_hash, bytes, amount);
    held->witness_offset += amount; held->offset += amount; return 0;
}
static void rw_prepare_read(rw_archive *held) {
    held->offset = held->checked = held->scanned = held->witness_offset = 0;
    held->prior_launch[0] = '\0'; held->verify_stage = 0;
    sha256_init(&held->payload_hash); sha256_init(&held->pack_hash);
}
static inline int rw_begin_seal(rw_archive *held) {
    if (!held || held->phase != RW_CAPTURE || held->failed || rw_custody(held) != 0 ||
        held->witness_fd >= 0 || held->retirement || held->observation_ready || held->physically_observed != held->count ||
        held->witnessed != held->count || held->offset != RW_HEADER + RW_RECORD * held->count + held->total ||
        held->offset > held->limit) return -1;
    held->pack_size = held->offset; publication_hash_hex(&held->payload_hash, held->payload_digest);
    unsigned char bytes[RW_HEADER]; rw_header(held, bytes);
    if (rw_write(held->pack_fd, bytes, sizeof(bytes), 0) != 0 || fsync(held->pack_fd) != 0 || fsync(held->archive_fd) != 0 ||
        fstat(held->pack_fd, &held->pack) != 0 || (uint64_t)held->pack.st_size != held->pack_size ||
        !rw_pack_current(held, 0600, 1)) return -1;
    held->phase = RW_HASH_WRITABLE; rw_prepare_read(held); return 0;
}
static int rw_scan_source(rw_archive *held) {
    if (!held->scan) {
        int fd = openat(held->source_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return -1;
        held->scan = fdopendir(fd);
        if (!held->scan) { (void)rw_close_fd(held, &fd); return -1; }
    }
    for (unsigned int step = 0; step < 64; ++step) {
        errno = 0; struct dirent *entry = readdir(held->scan);
        if (!entry) {
            if (errno || held->scanned != held->count || !rw_source_custody(held) ||
                fsync(held->source_fd) != 0 || rw_close_scan(held) != 0) return -1;
            return 1;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat file;
        if (strlen(entry->d_name) != 64 || !ma_hex(entry->d_name, 64) || held->scanned >= held->count ||
            fstatat(held->source_fd, entry->d_name, &file, AT_SYMLINK_NOFOLLOW) != 0 || !rw_witness_file(held, &file)) return -1;
        held->scanned++;
    }
    return 0;
}
static int rw_read_step(rw_archive *held) {
    int reader = held->phase == RW_HASH_READONLY ? held->pack_reader_fd : held->pack_fd;
    if (reader < 0) return -1;
    if (held->verify_stage == 0) {
        unsigned char actual[RW_HEADER], expected[RW_HEADER]; rw_header(held, expected);
        if (ma_pread(reader, actual, sizeof(actual), 0) != 0 || memcmp(actual, expected, sizeof(actual))) return -1;
        sha256_update(&held->pack_hash, actual, sizeof(actual)); held->offset = sizeof(actual); held->verify_stage = 1; return 0;
    }
    if (held->witness_fd >= 0) {
        uint64_t size = ma_u64(held->record + 88);
        if (held->witness_offset == size) {
            if (rw_witness_end(held) != 0) return -1;
            held->checked++; return 0;
        }
        unsigned char source[65536], archived[65536];
        size_t amount = size - held->witness_offset < sizeof(source) ? (size_t)(size - held->witness_offset) : sizeof(source);
        if (held->offset > held->pack_size || amount > held->pack_size - held->offset || !rw_current_witness(held) ||
            ma_pread(held->witness_fd, source, amount, held->witness_offset) != 0 || !rw_current_witness(held) ||
            ma_pread(reader, archived, amount, held->offset) != 0 || memcmp(source, archived, amount)) return -1;
        sha256_update(&held->pack_hash, archived, amount); sha256_update(&held->payload_hash, archived, amount);
        sha256_update(&held->witness_hash, source, amount);
        held->offset += amount; held->witness_offset += amount; return 0;
    }
    if (held->checked < held->count) {
        unsigned char packet[RW_RECORD];
        if (held->offset > held->pack_size || sizeof(packet) > held->pack_size - held->offset ||
            ma_pread(reader, packet, sizeof(packet), held->offset) != 0 || rw_entry(held, packet, sizeof(packet)) != 0) return -1;
        sha256_update(&held->pack_hash, packet, sizeof(packet)); sha256_update(&held->payload_hash, packet, sizeof(packet));
        held->offset += sizeof(packet); return 0;
    }
    if (held->verify_stage == 1) {
        unsigned char end; ssize_t count;
        do { count = pread(reader, &end, 1, (off_t)held->offset); } while (count < 0 && errno == EINTR);
        if (held->offset != held->pack_size || count) return -1;
        held->verify_stage = 2;
    }
    return rw_scan_source(held);
}
static int rw_begin_readonly(rw_archive *held) {
    if (held->pack_reader_fd >= 0 || held->witness_fd >= 0 || held->scan || !rw_pack_current(held, 0400, 1)) return -1;
    held->pack_reader_fd = openat(held->archive_fd, RW_PACK_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    held->phase = RW_HASH_READONLY;
    if (held->pack_reader_fd < 0 || rw_custody(held) != 0) return -1;
    rw_prepare_read(held); return 0;
}
static inline int rw_verify_next(rw_archive *held) {
    if (!held || held->failed || (held->phase != RW_HASH_WRITABLE && held->phase != RW_HASH_READONLY) || rw_custody(held) != 0) return -1;
    int done = rw_read_step(held);
    if (done < 0 || rw_custody(held) != 0) return -1;
    if (!done) return 0;
    char payload[65], digest[65];
    publication_hash_hex(&held->payload_hash, payload); publication_hash_hex(&held->pack_hash, digest);
    if ((held->capture_writer && strcmp(payload, held->payload_digest)) ||
        (held->phase == RW_HASH_READONLY && strcmp(digest, held->pack_digest)) ||
        fsync(held->pack_fd) != 0 || fsync(held->archive_fd) != 0) return -1;
    if (held->phase == RW_HASH_WRITABLE) {
        if (fchmod(held->pack_fd, 0400) != 0 || fsync(held->pack_fd) != 0 || fsync(held->archive_fd) != 0 ||
            fstat(held->pack_fd, &held->pack) != 0 || !rw_pack_current(held, 0400, 1) || rw_close_fd(held, &held->pack_fd) != 0) return -1;
        held->pack_fd = openat(held->archive_fd, RW_PACK_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        memcpy(held->pack_digest, digest, sizeof(held->pack_digest));
        return rw_begin_readonly(held);
    }
    if (fsync(held->pack_reader_fd) != 0 || rw_close_fd(held, &held->pack_reader_fd) != 0) return -1;
    held->phase = RW_COMPLETE; return 1;
}
static inline int rw_restart_complete(rw_archive *held) {
    if (!held || held->phase != RW_COMPLETE || held->failed || rw_custody(held) != 0) return -1;
    return rw_begin_readonly(held);
}
static inline int rw_open_verified_pack(rw_archive *held, uint64_t device, uint64_t inode, uint64_t bytes,
                                       uint64_t count, uint64_t total, const unsigned char digest[32]) {
    if (!held || held->phase != RW_SOURCE || held->archive_fd < 0 || count > RW_MAX_COUNT || total > RW_MAX_BYTES || bytes > RW_MAX_BYTES ||
        total < count * RW_FRAME || total > count * RW_MAX_WITNESS_BYTES || total % RW_FRAME ||
        bytes != RW_HEADER + RW_RECORD * count + total || rw_custody(held) != 0) return -1;
    held->pack_fd = openat(held->archive_fd, RW_PACK_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (held->pack_fd < 0 || fstat(held->pack_fd, &held->pack) != 0 || ma_device(&held->pack) != device ||
        (uint64_t)held->pack.st_ino != inode || (uint64_t)held->pack.st_size != bytes || !rw_pack_current(held, 0400, 1)) return -1;
    held->count = count; held->total = total; held->pack_size = bytes;
    for (size_t index = 0; index < 32; ++index) snprintf(held->pack_digest + index * 2, 3, "%02x", digest[index]);
    return rw_begin_readonly(held);
}
#include "kernel-archive-runtime-witness-proof.h"
#endif
