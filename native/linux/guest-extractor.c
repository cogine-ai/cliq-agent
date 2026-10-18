/* Signed, fixed Linux extraction recipe. No mount, process, host loader search,
 * caller FD list or JavaScript-supplied execution proof exists in this module. */
#define _GNU_SOURCE
#include <node_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include "guest-toolchain.h"
#include "worker-sha256.h"
#include <elf.h>
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define IMAGE_SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)
#define NODE_PATH "/usr/bin/node"
#define LOADER_PATH "/lib64/ld-linux-x86-64.so.2"
#define CHUNK_BYTES 65536
#define MAX_PHDRS 128
#define MAX_DYNAMIC 4096
#define MAX_STRING_TABLE (1024 * 1024)

static atomic_bool retirement_failed;
struct pinned_file { char path[CLIQ_GUEST_PATH_BYTES], digest[65]; ext2_ino_t inode; };
struct extraction {
    struct cliq_guest_toolchain held; /* Exact shared ABI prefix, offset zero. */
    napi_env env; napi_async_work work; napi_async_cleanup_hook_handle cleanup_hook;
    napi_deferred close_deferred; napi_ref close_promise;
    unsigned int references;
    bool work_complete, env_closing, retired;
    atomic_bool cancelled, finished;
    bool unsafe; const char *error;
    int image_fd, source_fd; struct stat source_identity;
    uint64_t image_bytes, mapped_bytes;
    uint32_t pinned_count; struct pinned_file pinned[CLIQ_GUEST_MAX_PINNED];
    ext2_ino_t mapped_inodes[CLIQ_GUEST_MAX_FILES];
};
_Static_assert(offsetof(struct extraction, held) == 0, "native guest prefix must be the unwrap pointer");

static bool active(struct extraction *job) { return !atomic_load_explicit(&job->cancelled, memory_order_acquire); }
static bool fail(struct extraction *job, const char *code) { if (!job->error) job->error = code; return false; }
static bool retire_fd(struct extraction *job, int *fd) {
    int original = *fd; *fd = -1;
    if (original < 0 || close(original) == 0) return true;
    job->unsafe = true; atomic_store(&retirement_failed, true); return false;
}
static bool hex_digest(const char *text) {
    if (strnlen(text, 65) != 64) return false;
    for (size_t i = 0; i < 64; i++) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
/* The first recipe deliberately accepts canonical ASCII image paths only. */
static bool image_path(const char *path) {
    size_t length = strnlen(path, CLIQ_GUEST_PATH_BYTES);
    if (length < 2 || length >= CLIQ_GUEST_PATH_BYTES || path[0] != '/' || path[length - 1] == '/') return false;
    size_t start = 1;
    for (size_t i = 1; i <= length; i++) {
        if (path[i] == '/' || i == length) {
            size_t count = i - start;
            if (!count || count > 255 || (count == 1 && path[start] == '.') || (count == 2 && !memcmp(path + start, "..", 2))) return false;
            start = i + 1;
        } else if (!((path[i] >= 'A' && path[i] <= 'Z') || (path[i] >= 'a' && path[i] <= 'z') ||
                     (path[i] >= '0' && path[i] <= '9') || strchr("._+-", path[i]))) return false;
    }
    return true;
}
static bool mapped_path(const char *path) {
    if (!image_path(path)) return false;
    if (!strcmp(path, NODE_PATH) || !strcmp(path, LOADER_PATH)) return true;
    const char *roots[] = { "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/" };
    for (size_t i = 0; i < 2; i++) {
        size_t length = strlen(roots[i]);
        if (!strncmp(path, roots[i], length) && path[length] && !strchr(path + length, '/')) return true;
    }
    return false;
}
static void finish_hash(struct sha256_context *hash, char output[65]) {
    static const char digits[] = "0123456789abcdef"; uint8_t bytes[32]; sha256_final(hash, bytes);
    for (size_t i = 0; i < 32; i++) { output[2 * i] = digits[bytes[i] >> 4]; output[2 * i + 1] = digits[bytes[i] & 15]; }
    output[64] = '\0';
}
static bool read_at(struct extraction *job, int fd, uint64_t size, uint64_t offset, void *buffer, size_t bytes) {
    if (offset > size || bytes > size - offset) return fail(job, "guest_elf_bounds");
    size_t received = 0;
    while (received < bytes && active(job)) {
        ssize_t count = pread(fd, (char *)buffer + received, bytes - received, (off_t)(offset + received));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return fail(job, "guest_image_read");
        received += (size_t)count;
    }
    return received == bytes;
}
static bool hash_image(struct extraction *job) {
    struct sha256_context hash; sha256_init(&hash); unsigned char bytes[CHUNK_BYTES]; uint64_t offset = 0;
    while (offset < job->image_bytes && active(job)) {
        size_t count = job->image_bytes - offset < sizeof(bytes) ? (size_t)(job->image_bytes - offset) : sizeof(bytes);
        if (!read_at(job, job->image_fd, job->image_bytes, offset, bytes, count)) return false;
        sha256_update(&hash, bytes, count); offset += count;
    }
    if (!active(job)) return false;
    char digest[65]; finish_hash(&hash, digest);
    return !strcmp(digest, job->held.image_digest) || fail(job, "guest_image_digest");
}
static bool same_source(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino && left->st_size == right->st_size &&
        left->st_mode == right->st_mode && left->st_uid == right->st_uid && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
        left->st_mtim.tv_sec == right->st_mtim.tv_sec && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}
static int readonly_image(struct extraction *job, int descriptor, const struct stat *identity, bool sealed) {
    char path[64]; int length = snprintf(path, sizeof(path), "/proc/self/fd/%d", descriptor);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -1;
    int result = open(path, O_RDONLY | O_CLOEXEC); struct stat reopened;
    if (result < 0) return -1;
    if (fstat(result, &reopened) || !same_source(identity, &reopened) ||
        (fcntl(result, F_GETFL) & O_ACCMODE) != O_RDONLY || (sealed && fcntl(result, F_GET_SEALS) != IMAGE_SEALS)) {
        retire_fd(job, &result); return -1;
    }
    return result;
}
/* The installed CAS descriptor is retained synchronously, but no mutable image
 * is ever parsed. Copy, complete hashing, source re-observation and sealing all
 * belong to this same cancellable task; an already sealed image needs no copy. */
static bool materialize_image(struct extraction *job) {
    if (job->source_fd < 0) return hash_image(job);
    struct stat before, after;
    if (!active(job) || fstat(job->source_fd, &before) || !same_source(&before, &job->source_identity))
        return fail(job, "guest_source_identity");
    job->image_fd = memfd_create("cliq-guest-image", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (job->image_fd < 0) return fail(job, "guest_image_create");
    struct sha256_context hash; sha256_init(&hash); unsigned char bytes[CHUNK_BYTES]; uint64_t offset = 0;
    while (offset < job->image_bytes && active(job)) {
        size_t count = job->image_bytes - offset < sizeof(bytes) ? (size_t)(job->image_bytes - offset) : sizeof(bytes);
        if (!read_at(job, job->source_fd, job->image_bytes, offset, bytes, count)) return false;
        sha256_update(&hash, bytes, count); size_t written = 0;
        while (written < count && active(job)) {
            ssize_t output = write(job->image_fd, bytes + written, count - written);
            if (output < 0 && errno == EINTR) continue;
            if (output <= 0) return fail(job, "guest_image_write");
            written += (size_t)output;
        }
        if (written != count) return false;
        offset += count;
    }
    if (!active(job) || offset != job->image_bytes || fstat(job->source_fd, &after) || !same_source(&after, &job->source_identity))
        return fail(job, "guest_source_changed");
    char digest[65]; finish_hash(&hash, digest);
    if (strcmp(digest, job->held.image_digest)) return fail(job, "guest_image_digest");
    if (fchmod(job->image_fd, 0400) || fcntl(job->image_fd, F_ADD_SEALS, IMAGE_SEALS) || fstat(job->image_fd, &after))
        return fail(job, "guest_image_seal");
    int frozen = readonly_image(job, job->image_fd, &after, true);
    if (frozen < 0) return fail(job, "guest_image_readonly");
    bool closed = retire_fd(job, &job->image_fd); job->image_fd = frozen;
    if (!retire_fd(job, &job->source_fd)) closed = false;
    return closed && active(job);
}

struct directory_search { struct extraction *job; const char *name; size_t length; ext2_ino_t found; bool duplicate; };
static int directory_entry(ext2_ino_t directory, int kind, struct ext2_dir_entry *entry,
                           int offset, int blocksize, char *buffer, void *data) {
    (void)directory; (void)kind; (void)offset; (void)blocksize; (void)buffer;
    struct directory_search *search = data;
    if (!active(search->job)) return DIRENT_ABORT;
    if (!entry->inode || ext2fs_dirent_name_len(entry) != (int)search->length || memcmp(entry->name, search->name, search->length)) return 0;
    if (search->found) { search->duplicate = true; return DIRENT_ABORT; }
    search->found = entry->inode; return 0;
}
/* No namei/follow-link helper is used. Cancellable directory iteration checks
 * exact names and duplicates, then each inode before traversing a component. */
static int lookup(struct extraction *job, ext2_filsys fs, const char *path, ext2_ino_t *result, struct ext2_inode *inode) {
    if (!image_path(path) || !active(job)) return -1;
    ext2_ino_t current = EXT2_ROOT_INO;
    if (ext2fs_read_inode(fs, current, inode) || !LINUX_S_ISDIR(inode->i_mode)) return fail(job, "guest_root_inode"), -1;
    const char *part = path + 1;
    for (;;) {
        if (!active(job)) return -1;
        const char *end = strchr(part, '/'); size_t length = end ? (size_t)(end - part) : strlen(part);
        if (EXT2_I_SIZE(inode) > job->image_bytes) return fail(job, "guest_directory_bounds"), -1;
        struct directory_search search = { .job = job, .name = part, .length = length };
        errcode_t error = ext2fs_dir_iterate2(fs, current, DIRENT_FLAG_INCLUDE_EMPTY, NULL, directory_entry, &search);
        ext2_ino_t next = search.found;
        if (!active(job)) return -1;
        if (!error && !next) return 0;
        if (error || search.duplicate || next < EXT2_ROOT_INO || next > fs->super->s_inodes_count ||
            !ext2fs_test_inode_bitmap2(fs->inode_map, next) || ext2fs_read_inode(fs, next, inode) || !inode->i_links_count ||
            (inode->i_mode & (LINUX_S_ISUID | LINUX_S_ISGID))) return fail(job, "guest_inode_identity"), -1;
        if (end ? !LINUX_S_ISDIR(inode->i_mode) : !LINUX_S_ISREG(inode->i_mode) || inode->i_links_count != 1)
            return fail(job, "guest_inode_kind"), -1;
        current = next;
        if (!end) { *result = next; return 1; }
        part = end + 1;
    }
}
static bool file_bytes(struct extraction *job, ext2_filsys fs, ext2_ino_t inode, const struct ext2_inode *identity,
                       int output, char digest[65]) {
    uint64_t size = EXT2_I_SIZE(identity);
    if (!size || size > CLIQ_GUEST_IMAGE_BYTES || !active(job)) return fail(job, "guest_file_bounds");
    ext2_file_t file = NULL;
    if (ext2fs_file_open(fs, inode, 0, &file)) return fail(job, "guest_file_open");
    struct sha256_context hash; sha256_init(&hash); unsigned char bytes[CHUNK_BYTES]; uint64_t read = 0; bool valid = true;
    while (read < size && active(job)) {
        unsigned int received = 0, wanted = size - read < sizeof(bytes) ? (unsigned int)(size - read) : sizeof(bytes);
        if (ext2fs_file_read(file, bytes, wanted, &received) || received != wanted) { valid = fail(job, "guest_file_read"); break; }
        sha256_update(&hash, bytes, received);
        size_t written = 0;
        while (output >= 0 && written < received && active(job)) {
            ssize_t count = write(output, bytes + written, received - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { valid = fail(job, "guest_file_write"); break; }
            written += (size_t)count;
        }
        if (!valid) break;
        read += received;
    }
    if (ext2fs_file_close(file)) { job->unsafe = true; atomic_store(&retirement_failed, true); valid = false; }
    if (!valid || !active(job) || read != size) return false;
    finish_hash(&hash, digest); return true;
}
static int extract_file(struct extraction *job, ext2_filsys fs, const char *path, const char *expected) {
    if (!mapped_path(path)) return fail(job, "guest_mapping_path"), -1;
    for (uint32_t i = 0; i < job->held.file_count; i++) if (!strcmp(job->held.files[i].path, path)) {
        if (expected && strcmp(expected, job->held.files[i].digest)) return fail(job, "guest_mapping_digest"), -1;
        return (int)i;
    }
    if (job->held.file_count == CLIQ_GUEST_MAX_FILES) return fail(job, "guest_mapping_count"), -1;
    struct ext2_inode identity; ext2_ino_t inode;
    if (lookup(job, fs, path, &inode, &identity) != 1) return fail(job, "guest_mapping_missing"), -1;
    uint64_t size = EXT2_I_SIZE(&identity);
    if (!size || size > CLIQ_GUEST_IMAGE_BYTES - job->mapped_bytes) return fail(job, "guest_mapping_bytes"), -1;
    for (uint32_t i = 0; i < job->held.file_count; i++) {
        const char *prior = job->held.files[i].path; size_t a = strlen(prior), b = strlen(path);
        if (job->mapped_inodes[i] == inode || (a < b && !strncmp(path, prior, a) && path[a] == '/') ||
            (b < a && !strncmp(prior, path, b) && prior[b] == '/')) return fail(job, "guest_mapping_alias"), -1;
    }
    uint32_t index = job->held.file_count++; struct cliq_guest_file *file = &job->held.files[index];
    memcpy(file->path, path, strlen(path) + 1); file->byte_count = size; job->mapped_inodes[index] = inode; job->mapped_bytes += size;
    file->fd = memfd_create("cliq-guest-file", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (file->fd < 0 || !file_bytes(job, fs, inode, &identity, file->fd, file->digest) ||
        (expected && strcmp(expected, file->digest)) || fchmod(file->fd, 0500) ||
        fcntl(file->fd, F_ADD_SEALS, IMAGE_SEALS) || lseek(file->fd, 0, SEEK_SET) < 0)
        return fail(job, "guest_mapping_seal"), -1;
    return (int)index;
}

static bool library_name(const char *value) {
    size_t length = strnlen(value, 256);
    if (!length || length >= 256 || !strcmp(value, ".") || !strcmp(value, "..")) return false;
    for (size_t i = 0; i < length; i++) if (!((value[i] >= 'A' && value[i] <= 'Z') || (value[i] >= 'a' && value[i] <= 'z') ||
        (value[i] >= '0' && value[i] <= '9') || strchr("._+-", value[i]))) return false;
    return true;
}
static bool dependency(struct extraction *job, ext2_filsys fs, const char *name) {
    if (!library_name(name)) return fail(job, "guest_needed_name");
    const char *roots[] = { "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/" };
    for (size_t i = 0; i < 2; i++) {
        char path[CLIQ_GUEST_PATH_BYTES]; int length = snprintf(path, sizeof(path), "%s%s", roots[i], name);
        if (length <= 0 || (size_t)length >= sizeof(path)) return fail(job, "guest_needed_path");
        ext2_ino_t inode; struct ext2_inode identity; int found = lookup(job, fs, path, &inode, &identity);
        if (found < 0) return false;
        if (found == 1) return extract_file(job, fs, path, NULL) >= 0;
    }
    /* The interpreter's own SONAME commonly occurs in libc's NEEDED list. */
    if (!strcmp(name, "ld-linux-x86-64.so.2")) return extract_file(job, fs, LOADER_PATH, NULL) >= 0;
    return fail(job, "guest_needed_missing");
}
static bool elf_dependencies(struct extraction *job, ext2_filsys fs, uint32_t index) {
    struct cliq_guest_file *file = &job->held.files[index]; Elf64_Ehdr header; Elf64_Phdr phdrs[MAX_PHDRS];
    if (!read_at(job, file->fd, file->byte_count, 0, &header, sizeof(header)) || memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_version != EV_CURRENT || header.e_machine != EM_X86_64 || (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum || header.e_phnum > MAX_PHDRS ||
        !read_at(job, file->fd, file->byte_count, header.e_phoff, phdrs, header.e_phnum * sizeof(*phdrs))) return fail(job, "guest_elf_header");
    Elf64_Phdr *dynamic = NULL; bool interpreter = false;
    for (size_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_offset > file->byte_count || ph->p_filesz > file->byte_count - ph->p_offset ||
            (ph->p_type == PT_LOAD && (ph->p_memsz < ph->p_filesz || ph->p_vaddr > UINT64_MAX - ph->p_memsz))) return fail(job, "guest_elf_segment");
        if (ph->p_type == PT_INTERP) {
            char path[CLIQ_GUEST_PATH_BYTES];
            if (interpreter || ph->p_filesz < 2 || ph->p_filesz > sizeof(path) ||
                !read_at(job, file->fd, file->byte_count, ph->p_offset, path, (size_t)ph->p_filesz) ||
                path[ph->p_filesz - 1] || strnlen(path, (size_t)ph->p_filesz) != ph->p_filesz - 1 || strcmp(path, LOADER_PATH))
                return fail(job, "guest_elf_interpreter");
            interpreter = true;
            if (extract_file(job, fs, path, NULL) < 0) return false;
        }
        if (ph->p_type == PT_DYNAMIC) { if (dynamic) return fail(job, "guest_elf_dynamic"); dynamic = ph; }
    }
    if (index == 0 && !interpreter) return fail(job, "guest_node_interpreter");
    if (!dynamic || !dynamic->p_filesz || dynamic->p_filesz % sizeof(Elf64_Dyn) || dynamic->p_filesz / sizeof(Elf64_Dyn) > MAX_DYNAMIC)
        return fail(job, "guest_elf_dynamic");
    Elf64_Dyn entries[MAX_DYNAMIC]; size_t count = (size_t)(dynamic->p_filesz / sizeof(*entries));
    if (!read_at(job, file->fd, file->byte_count, dynamic->p_offset, entries, count * sizeof(*entries))) return false;
    uint64_t string_address = 0, string_bytes = 0, needed[CLIQ_GUEST_MAX_FILES]; size_t needed_count = 0; bool end = false, address_seen = false, size_seen = false;
    for (size_t i = 0; i < count; i++) {
        Elf64_Dyn *entry = &entries[i];
        if (entry->d_tag == DT_NULL) { end = true; break; }
        if (entry->d_tag == DT_RPATH || entry->d_tag == DT_RUNPATH || entry->d_tag == DT_AUDIT || entry->d_tag == DT_DEPAUDIT ||
            entry->d_tag == DT_FILTER || entry->d_tag == DT_AUXILIARY) return fail(job, "guest_elf_lookup_override");
        if (entry->d_tag == DT_STRTAB) { if (address_seen) return fail(job, "guest_elf_strings"); address_seen = true; string_address = entry->d_un.d_ptr; }
        if (entry->d_tag == DT_STRSZ) { if (size_seen) return fail(job, "guest_elf_strings"); size_seen = true; string_bytes = entry->d_un.d_val; }
        if (entry->d_tag == DT_NEEDED) { if (needed_count == CLIQ_GUEST_MAX_FILES) return fail(job, "guest_needed_count"); needed[needed_count++] = entry->d_un.d_val; }
    }
    if (!end || !address_seen || !size_seen || !string_bytes || string_bytes > MAX_STRING_TABLE) return fail(job, "guest_elf_strings");
    uint64_t string_offset = 0; bool located = false;
    for (size_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || string_address < ph->p_vaddr || string_address - ph->p_vaddr > ph->p_filesz ||
            string_bytes > ph->p_filesz - (string_address - ph->p_vaddr)) continue;
        if (located) return fail(job, "guest_elf_string_alias");
        located = true; string_offset = ph->p_offset + (string_address - ph->p_vaddr);
    }
    if (!located) return fail(job, "guest_elf_strings");
    for (size_t i = 0; i < needed_count; i++) {
        if (!active(job) || needed[i] >= string_bytes) return fail(job, "guest_needed_bounds");
        size_t available = string_bytes - needed[i] < 256 ? (size_t)(string_bytes - needed[i]) : 256; char name[256];
        if (!read_at(job, file->fd, file->byte_count, string_offset + needed[i], name, available) || !memchr(name, '\0', available) ||
            !dependency(job, fs, name)) return false;
    }
    return true;
}

static bool image_layout(struct extraction *job) {
    struct ext2_super_block super;
    if (!read_at(job, job->image_fd, job->image_bytes, 1024, &super, sizeof(super)) || super.s_magic != EXT2_SUPER_MAGIC ||
        super.s_log_block_size > 2 || !super.s_blocks_per_group || !super.s_inodes_per_group || !super.s_inodes_count ||
        super.s_inodes_count > job->image_bytes / 128 || super.s_inode_size < 128 || super.s_inode_size > 1024 ||
        (super.s_inode_size & (super.s_inode_size - 1)) || (super.s_feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) ||
        (super.s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER)) return fail(job, "guest_ext4_layout");
    uint64_t blocksize = UINT64_C(1024) << super.s_log_block_size, blocks = ext2fs_blocks_count(&super);
    if (!blocks || blocks > job->image_bytes / blocksize || blocks * blocksize != job->image_bytes ||
        super.s_blocks_per_group > blocksize * 8 || super.s_inodes_per_group > blocksize * 8) return fail(job, "guest_ext4_bounds");
    return true;
}
static void execute(napi_env env, void *data) {
    (void)env; struct extraction *job = data; ext2_filsys fs = NULL; bool valid = active(job) && materialize_image(job) && image_layout(job);
    /* unixfd_io_manager consumes the supplied descriptor on normal close and
     * some (not all) open failures. Never lend it the task's owned FD. The
     * ordinary Unix manager opens this held sealed inode itself, read-only,
     * and owns only that new OFD on both success and failure. This procfs name
     * is generated from our private live FD, not a guest/installation pathname;
     * the original remains held until the filesystem has really closed. */
    char device[64]; int length = snprintf(device, sizeof(device), "/proc/self/fd/%d", job->image_fd);
    if (valid && (length <= 0 || (size_t)length >= sizeof(device) || ext2fs_open(device, EXT2_FLAG_64BITS, 0, 0, unix_io_manager, &fs) ||
                  ext2fs_read_inode_bitmap(fs))) valid = fail(job, "guest_ext4_open");
    for (uint32_t i = 0; valid && i < job->pinned_count; i++) {
        struct ext2_inode inode; char digest[65];
        valid = lookup(job, fs, job->pinned[i].path, &job->pinned[i].inode, &inode) == 1 && (inode.i_mode & 0111) &&
            file_bytes(job, fs, job->pinned[i].inode, &inode, -1, digest) && !strcmp(digest, job->pinned[i].digest);
        for (uint32_t j = 0; valid && j < i; j++) if (job->pinned[j].inode == job->pinned[i].inode) valid = false;
        if (!valid) fail(job, "guest_pinned_identity");
    }
    if (valid) valid = extract_file(job, fs, job->held.node_path, job->held.node_digest) == 0;
    /* Newly discovered libraries extend this same bounded worklist; paths and
     * inodes are deduplicated, so cyclic ELF dependencies cannot grow it. */
    for (uint32_t i = 0; valid && i < job->held.file_count; i++) valid = active(job) && elf_dependencies(job, fs, i);
    if (fs && ext2fs_close(fs)) { job->unsafe = true; atomic_store(&retirement_failed, true); valid = false; }
    if (!retire_fd(job, &job->image_fd)) valid = false;
    if (!retire_fd(job, &job->source_fd)) valid = false;
    if (valid && active(job) && !job->unsafe) atomic_store_explicit(&job->held.ready, true, memory_order_release);
    atomic_store_explicit(&job->finished, true, memory_order_release);
}

static napi_value failure(napi_env env, const char *message) {
    bool pending = false;
    if (napi_is_exception_pending(env, &pending) != napi_ok || !pending) napi_throw_error(env, "RECOVERY_REQUIRED", message);
    return NULL;
}
static napi_value undefined(napi_env env) { napi_value result; napi_get_undefined(env, &result); return result; }
static void release(struct extraction *job) {
    if (--job->references) return;
    if (job->close_promise) napi_delete_reference(job->env, job->close_promise);
    free(job);
}
static void settle_close(struct extraction *job) {
    if (!job->close_deferred || job->env_closing) return;
    napi_status status;
    if (job->unsafe) {
        napi_value code, text, error;
        if (napi_create_string_utf8(job->env, "RECOVERY_REQUIRED", NAPI_AUTO_LENGTH, &code) != napi_ok ||
            napi_create_string_utf8(job->env, "native guest extraction resource join failed", NAPI_AUTO_LENGTH, &text) != napi_ok ||
            napi_create_error(job->env, code, text, &error) != napi_ok) {
            napi_fatal_error("cliq-guest-extractor", NAPI_AUTO_LENGTH, "join error allocation failed", NAPI_AUTO_LENGTH);
        }
        status = napi_reject_deferred(job->env, job->close_deferred, error);
    } else status = napi_resolve_deferred(job->env, job->close_deferred, undefined(job->env));
    if (status != napi_ok) napi_fatal_error("cliq-guest-extractor", NAPI_AUTO_LENGTH, "join completion failed", NAPI_AUTO_LENGTH);
    job->close_deferred = NULL;
}
/* Main-thread-only after N-API's actual completion callback has joined execute.
 * No work cancellation or JS timer can enter this positive resource gate. */
static void retire(struct extraction *job) {
    if (job->retired || !job->work_complete) return;
    atomic_store_explicit(&job->held.ready, false, memory_order_release);
    for (size_t i = 0; i < CLIQ_GUEST_MAX_FILES; i++) retire_fd(job, &job->held.files[i].fd);
    retire_fd(job, &job->image_fd);
    retire_fd(job, &job->source_fd);
    if (job->work) {
        if (napi_delete_async_work(job->env, job->work) != napi_ok) { job->unsafe = true; atomic_store(&retirement_failed, true); }
        job->work = NULL;
    }
    bool hook_removed = false;
    if (job->cleanup_hook) {
        if (napi_remove_async_cleanup_hook(job->cleanup_hook) == napi_ok) { job->cleanup_hook = NULL; hook_removed = true; }
        else { job->unsafe = true; atomic_store(&retirement_failed, true); }
    }
    job->retired = true;
    settle_close(job);
    if (hook_removed) release(job); /* May free an already-finalized receiver. */
}
static void revoke_extraction(struct extraction *job) {
    atomic_store_explicit(&job->held.revoked, true, memory_order_release);
    atomic_store_explicit(&job->cancelled, true, memory_order_release);
}
static void complete(napi_env env, napi_status status, void *data) {
    (void)env; struct extraction *job = data; job->work_complete = true;
    if (status != napi_ok) { job->unsafe = true; atomic_store(&retirement_failed, true); revoke_extraction(job); }
    if (atomic_load_explicit(&job->held.revoked, memory_order_acquire)) retire(job);
}
static void cleanup(napi_async_cleanup_hook_handle handle, void *data) {
    (void)handle; struct extraction *job = data; job->env_closing = true; revoke_extraction(job); retire(job);
}
static void finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint; struct extraction *job = data; revoke_extraction(job); retire(job); release(job);
}
static bool receiver(napi_env env, napi_callback_info info, struct extraction **job) {
    size_t argc = 1; napi_value args[1], self; bool tagged = false;
    return napi_get_cb_info(env, info, &argc, args, &self, NULL) == napi_ok && argc == 0 &&
        napi_check_object_type_tag(env, self, &CLIQ_GUEST_TOOLCHAIN_TAG, &tagged) == napi_ok && tagged &&
        napi_unwrap(env, self, (void **)job) == napi_ok && *job && (*job)->env == env;
}
static bool usable(struct extraction *job) {
    return !atomic_load(&retirement_failed) && !atomic_load_explicit(&job->held.revoked, memory_order_acquire) &&
        atomic_load_explicit(&job->held.ready, memory_order_acquire);
}
static napi_value poll_ready(napi_env env, napi_callback_info info) {
    struct extraction *job;
    if (!receiver(env, info, &job) || atomic_load(&retirement_failed) || atomic_load_explicit(&job->held.revoked, memory_order_acquire))
        return failure(env, "native guest extraction is revoked or unavailable");
    bool ready = atomic_load_explicit(&job->held.ready, memory_order_acquire);
    if (!ready && atomic_load_explicit(&job->finished, memory_order_acquire)) return failure(env, job->error ? job->error : "native guest extraction failed");
    napi_value result;
    if (napi_get_boolean(env, ready, &result) != napi_ok) return failure(env, "native guest readiness unavailable");
    return result;
}
static bool set_text(napi_env env, napi_value object, const char *key, const char *value) {
    napi_value text;
    return napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &text) == napi_ok && napi_set_named_property(env, object, key, text) == napi_ok;
}
static bool set_number(napi_env env, napi_value object, const char *key, uint64_t value) {
    napi_value number;
    return napi_create_double(env, (double)value, &number) == napi_ok && napi_set_named_property(env, object, key, number) == napi_ok;
}
static napi_value describe(napi_env env, napi_callback_info info) {
    struct extraction *job;
    if (!receiver(env, info, &job) || !usable(job)) return failure(env, "native guest description requires its original ready owner");
    napi_value result, files;
    if (napi_create_object(env, &result) != napi_ok || napi_create_array_with_length(env, job->held.file_count, &files) != napi_ok ||
        !set_text(env, result, "imageDigest", job->held.image_digest) || !set_text(env, result, "nodePath", job->held.node_path) ||
        !set_text(env, result, "nodeDigest", job->held.node_digest)) return failure(env, "native guest description unavailable");
    for (uint32_t i = 0; i < job->held.file_count; i++) {
        napi_value file; struct cliq_guest_file *source = &job->held.files[i];
        if (napi_create_object(env, &file) != napi_ok || !set_text(env, file, "path", source->path) ||
            !set_text(env, file, "digest", source->digest) || !set_number(env, file, "byteCount", source->byte_count) ||
            napi_set_element(env, files, i, file) != napi_ok) return failure(env, "native guest file description unavailable");
    }
    if (napi_set_named_property(env, result, "files", files) != napi_ok) return failure(env, "native guest description unavailable");
    return result;
}
static napi_value close_owner(napi_env env, napi_callback_info info) {
    struct extraction *job;
    if (!receiver(env, info, &job)) return failure(env, "native guest close requires its original owner");
    revoke_extraction(job); /* Irreversible before promise allocation, never after an await. */
    napi_value promise;
    if (job->close_promise) {
        if (napi_get_reference_value(env, job->close_promise, &promise) != napi_ok) return failure(env, "native guest join unavailable");
        return promise;
    }
    if (napi_create_promise(env, &job->close_deferred, &promise) != napi_ok || napi_create_reference(env, promise, 1, &job->close_promise) != napi_ok) {
        retire(job); return failure(env, "native guest join allocation failed");
    }
    if (job->retired) settle_close(job); else retire(job);
    return promise;
}
static bool own_fields(napi_env env, napi_value value, const char *const *keys, uint32_t count) {
    napi_valuetype type; napi_value names; uint32_t length; bool array;
    if (napi_typeof(env, value, &type) != napi_ok || type != napi_object || napi_is_array(env, value, &array) != napi_ok || array ||
        napi_get_all_property_names(env, value, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
        napi_get_array_length(env, names, &length) != napi_ok || length != count) return false;
    for (uint32_t i = 0; i < count; i++) {
        napi_value name; char text[64]; size_t bytes;
        if (napi_get_element(env, names, i, &name) != napi_ok || napi_get_value_string_utf8(env, name, text, sizeof(text), &bytes) != napi_ok ||
            !bytes || bytes >= sizeof(text) || strlen(text) != bytes) return false;
        bool present = false;
        for (uint32_t j = 0; j < count; j++) if (!strcmp(text, keys[j])) present = true;
        if (!present) return false;
    }
    return true;
}
static bool field_text(napi_env env, napi_value object, const char *key, char *output, size_t capacity) {
    napi_value field; size_t bytes;
    return napi_get_named_property(env, object, key, &field) == napi_ok && napi_get_value_string_utf8(env, field, NULL, 0, &bytes) == napi_ok &&
        bytes > 0 && bytes < capacity && napi_get_value_string_utf8(env, field, output, capacity, &bytes) == napi_ok && strlen(output) == bytes;
}
static bool number(napi_env env, napi_value value, uint64_t *output) {
    double observed;
    if (napi_get_value_double(env, value, &observed) != napi_ok || !isfinite(observed) || observed < 0 || observed > 9007199254740991.0 ||
        observed != (double)(uint64_t)observed) return false;
    *output = (uint64_t)observed; return true;
}
static bool input(napi_env env, napi_value value, struct extraction *job) {
    const char *keys[] = { "imageDigest", "imageByteCount", "nodePath", "nodeDigest", "architecture", "pinnedExecutables" };
    napi_value size, pins, names; char architecture[16]; bool array; uint32_t length, properties;
    if (!own_fields(env, value, keys, 6) || !field_text(env, value, "imageDigest", job->held.image_digest, 65) || !hex_digest(job->held.image_digest) ||
        !field_text(env, value, "nodePath", job->held.node_path, sizeof(job->held.node_path)) || strcmp(job->held.node_path, NODE_PATH) ||
        !field_text(env, value, "nodeDigest", job->held.node_digest, 65) || !hex_digest(job->held.node_digest) ||
        !field_text(env, value, "architecture", architecture, sizeof(architecture)) || strcmp(architecture, "x86_64") ||
        napi_get_named_property(env, value, "imageByteCount", &size) != napi_ok || !number(env, size, &job->image_bytes) ||
        !job->image_bytes || job->image_bytes > CLIQ_GUEST_IMAGE_BYTES ||
        napi_get_named_property(env, value, "pinnedExecutables", &pins) != napi_ok || napi_is_array(env, pins, &array) != napi_ok || !array ||
        napi_get_array_length(env, pins, &length) != napi_ok || !length || length > CLIQ_GUEST_MAX_PINNED ||
        napi_get_all_property_names(env, pins, napi_key_own_only, napi_key_all_properties, napi_key_numbers_to_strings, &names) != napi_ok ||
        napi_get_array_length(env, names, &properties) != napi_ok || properties != length + 1) return false;
    bool node = false; const char *pin_keys[] = { "path", "digest" };
    for (uint32_t i = 0; i < length; i++) {
        napi_value pin, index; char index_text[16]; bool own;
        int index_length = snprintf(index_text, sizeof(index_text), "%u", i);
        if (index_length <= 0 || (size_t)index_length >= sizeof(index_text) ||
            napi_create_string_utf8(env, index_text, (size_t)index_length, &index) != napi_ok ||
            napi_has_own_property(env, pins, index, &own) != napi_ok || !own ||
            napi_get_element(env, pins, i, &pin) != napi_ok || !own_fields(env, pin, pin_keys, 2) ||
            !field_text(env, pin, "path", job->pinned[i].path, sizeof(job->pinned[i].path)) || !image_path(job->pinned[i].path) ||
            !field_text(env, pin, "digest", job->pinned[i].digest, 65) || !hex_digest(job->pinned[i].digest)) return false;
        for (uint32_t j = 0; j < i; j++) if (!strcmp(job->pinned[j].path, job->pinned[i].path)) return false;
        if (!strcmp(job->pinned[i].path, job->held.node_path)) { if (strcmp(job->pinned[i].digest, job->held.node_digest)) return false; node = true; }
    }
    job->pinned_count = length; return node;
}
static bool retain_image(struct extraction *job, int source) {
    int duplicate = fcntl(source, F_DUPFD_CLOEXEC, 3); struct stat original; bool valid = false;
    if (duplicate < 0) return false;
    if (fstat(duplicate, &original) || !S_ISREG(original.st_mode) || original.st_size <= 0 ||
        (uint64_t)original.st_size != job->image_bytes) goto done;
    bool sealed = fcntl(duplicate, F_GET_SEALS) == IMAGE_SEALS;
    int access = fcntl(duplicate, F_GETFL);
    if (!sealed && (access < 0 || (access & O_ACCMODE) != O_RDONLY || (original.st_mode & 07777) != 0400 ||
        (original.st_uid != geteuid() && original.st_uid != 0))) goto done;
    int retained = readonly_image(job, duplicate, &original, sealed);
    if (retained < 0) goto done;
    if (sealed) job->image_fd = retained;
    else { job->source_fd = retained; job->source_identity = original; }
    valid = true;
done:
    if (!retire_fd(job, &duplicate)) valid = false;
    return valid;
}
static napi_value begin(napi_env env, napi_callback_info info) {
    if (atomic_load(&retirement_failed)) return failure(env, "native guest retirement remains uncertain");
    size_t argc = 3; napi_value args[3], object, resource; uint64_t descriptor;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 || !number(env, args[0], &descriptor) || descriptor > INT_MAX)
        return failure(env, "native guest extraction requires its held image and fixed metadata");
    struct extraction *job = calloc(1, sizeof(*job));
    if (!job) return failure(env, "native guest extraction allocation failed");
    job->env = env; job->references = 1; job->work_complete = true; job->image_fd = -1; job->source_fd = -1; job->held.abi_version = CLIQ_GUEST_ABI_VERSION;
    atomic_init(&job->held.ready, false); atomic_init(&job->held.revoked, false); atomic_init(&job->cancelled, false); atomic_init(&job->finished, false);
    for (size_t i = 0; i < CLIQ_GUEST_MAX_FILES; i++) job->held.files[i].fd = -1;
    if (!input(env, args[1], job) || !retain_image(job, (int)descriptor)) {
        retire_fd(job, &job->image_fd); retire_fd(job, &job->source_fd); release(job);
        return failure(env, "native guest input is not an exact protected image closure");
    }
    napi_property_descriptor properties[] = {
        { "pollReady", NULL, poll_ready, NULL, NULL, NULL, napi_default, NULL },
        { "describe", NULL, describe, NULL, NULL, NULL, napi_default, NULL },
        { "close", NULL, close_owner, NULL, NULL, NULL, napi_default, NULL }
    };
    if (napi_create_object(env, &object) != napi_ok || napi_type_tag_object(env, object, &CLIQ_GUEST_TOOLCHAIN_TAG) != napi_ok ||
        napi_define_properties(env, object, 3, properties) != napi_ok ||
        napi_create_string_utf8(env, "cliq-guest-extraction", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
        napi_create_async_work(env, NULL, resource, execute, complete, job, &job->work) != napi_ok) {
        retire(job); release(job); return failure(env, "native guest asynchronous owner unavailable");
    }
    if (napi_add_async_cleanup_hook(env, cleanup, job, &job->cleanup_hook) != napi_ok) {
        retire(job); release(job); return failure(env, "native guest cleanup owner unavailable");
    }
    job->references++;
    if (napi_wrap(env, object, &job->held, finalize, NULL, NULL) != napi_ok) {
        retire(job); release(job); return failure(env, "native guest original receiver unavailable");
    }
    job->work_complete = false;
    if (napi_queue_async_work(env, job->work) != napi_ok) {
        job->work_complete = true; job->error = "guest_worker_unavailable"; revoke_extraction(job); retire(job);
    }
    return object;
}

NAPI_MODULE_INIT() {
    napi_value version, function;
    if (napi_create_uint32(env, 1, &version) != napi_ok || napi_set_named_property(env, exports, "interfaceVersion", version) != napi_ok ||
        napi_create_function(env, "begin", NAPI_AUTO_LENGTH, begin, NULL, &function) != napi_ok ||
        napi_set_named_property(env, exports, "begin", function) != napi_ok) return NULL;
    return exports;
}
#else
NAPI_MODULE_INIT() { (void)exports; napi_throw_error(env, "UNSUPPORTED_PLATFORM", "Guest extraction requires the qualified Linux x86_64 backend"); return NULL; }
#endif
