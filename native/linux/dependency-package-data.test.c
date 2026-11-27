/* Real owned sealed descriptors only. No Run, StateOwner, Journal or death
 * authority is constructed; installed GET/rollback qualification is separate. */
#define _GNU_SOURCE
#include "dependency-package-data.h"
#include <dirent.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
static unsigned int checks;
static void check(bool value) { checks++; if (!value) { fprintf(stderr, "dependency data component check %u failed\n", checks); exit(1); } }
static size_t descriptors(void) {
    DIR *directory = opendir("/proc/self/fd"); check(directory != NULL); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    check(closedir(directory) == 0); return count;
}
static int package(uint64_t size, char text[65]) {
    int writable = memfd_create("cliq-owned-dependency-data", MFD_CLOEXEC | MFD_ALLOW_SEALING); check(writable >= 0);
    unsigned char bytes[65536]; for (size_t index = 0; index < sizeof(bytes); index++) bytes[index] = (unsigned char)(index % 251);
    struct sha256_context hash; sha256_init(&hash); uint64_t position = 0;
    while (position < size) {
        size_t count = size - position < sizeof(bytes) ? (size_t)(size - position) : sizeof(bytes);
        check(write(writable, bytes, count) == (ssize_t)count); sha256_update(&hash, bytes, count); position += count;
    }
    unsigned char digest[32]; sha256_final(&hash, digest); static const char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < 32; index++) { text[index * 2] = hex[digest[index] >> 4]; text[index * 2 + 1] = hex[digest[index] & 15]; }
    text[64] = '\0'; check(fchmod(writable, 0400) == 0);
    check(fcntl(writable, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
    char path[64]; check(snprintf(path, sizeof(path), "/proc/self/fd/%d", writable) > 0);
    int readonly = open(path, O_RDONLY | O_CLOEXEC); check(readonly >= 0); check(close(writable) == 0); return readonly;
}
static void read_all(struct cliq_dependency_package_reader *reader) {
    unsigned char bytes[CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES]; size_t size = 1; uint64_t total = 0;
    while (size) { check(cliq_dependency_data_read(reader, bytes, &size) == CLIQ_DEPENDENCY_DATA_OK); total += size; }
    check(total == reader->owner->byte_count && cliq_dependency_data_complete(reader));
}
int main(void) {
    const uint64_t size = UINT64_C(3) * 1048576 + 17; size_t before = descriptors(); char digest[65];
    struct cliq_dependency_package_data owner; struct cliq_dependency_package_reader first, retry;
    int fd = package(size, digest);
    check(cliq_dependency_data_initialize(&owner, fd, size, CLIQ_DEPENDENCY_PACKAGE_MAX_BYTES, digest) == CLIQ_DEPENDENCY_DATA_OK);
    check(cliq_dependency_data_open(&owner, &first) == CLIQ_DEPENDENCY_DATA_OK && !cliq_dependency_data_complete(&first));
    unsigned char chunk[CLIQ_DEPENDENCY_PACKAGE_CHUNK_BYTES]; size_t count;
    check(cliq_dependency_data_read(&first, chunk, &count) == CLIQ_DEPENDENCY_DATA_OK && count == sizeof(chunk));
    check(!cliq_dependency_data_complete(&first));
    /* A consumer failure joins only that cursor. The same original package
     * remains available; no new GET or data FD is manufactured. */
    check(cliq_dependency_data_join(&first) == CLIQ_DEPENDENCY_DATA_OK && owner.fd == fd && !owner.retired);
    check(cliq_dependency_data_open(&owner, &retry) == CLIQ_DEPENDENCY_DATA_OK); read_all(&retry);
    check(cliq_dependency_data_join(&retry) == CLIQ_DEPENDENCY_DATA_OK); check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_OK);
    check(owner.retired && owner.fd == -1 && descriptors() == before);

    fd = package(size, digest);
    check(cliq_dependency_data_initialize(&owner, fd, size - 1, size, digest) == CLIQ_DEPENDENCY_DATA_REFUSED);
    check(cliq_dependency_data_initialize(&owner, fd, size, size - 1, digest) == CLIQ_DEPENDENCY_DATA_REFUSED); check(close(fd) == 0);
    fd = package(size, digest); digest[0] = digest[0] == '0' ? '1' : '0';
    check(cliq_dependency_data_initialize(&owner, fd, size, size, digest) == CLIQ_DEPENDENCY_DATA_OK);
    check(cliq_dependency_data_open(&owner, &first) == CLIQ_DEPENDENCY_DATA_OK); enum cliq_dependency_data_status status;
    do { status = cliq_dependency_data_read(&first, chunk, &count); } while (status == CLIQ_DEPENDENCY_DATA_OK && count);
    check(status == CLIQ_DEPENDENCY_DATA_REFUSED && !cliq_dependency_data_complete(&first));
    check(cliq_dependency_data_read(&first, chunk, &count) == CLIQ_DEPENDENCY_DATA_REFUSED && !cliq_dependency_data_complete(&first));
    check(cliq_dependency_data_join(&first) == CLIQ_DEPENDENCY_DATA_OK); check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_OK);

    fd = package(size, digest); check(cliq_dependency_data_initialize(&owner, fd, size, size, digest) == CLIQ_DEPENDENCY_DATA_OK);
    check(cliq_dependency_data_open(&owner, &first) == CLIQ_DEPENDENCY_DATA_OK);
    check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_BUSY && owner.fd == fd && !owner.retired);
    check(cliq_dependency_data_read(&first, chunk, &count) == CLIQ_DEPENDENCY_DATA_CANCELLED);
    check(cliq_dependency_data_open(&owner, &retry) == CLIQ_DEPENDENCY_DATA_CANCELLED);
    check(cliq_dependency_data_join(&first) == CLIQ_DEPENDENCY_DATA_OK); check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_OK);

    fd = package(17, digest); check(cliq_dependency_data_initialize(&owner, fd, 17, 17, digest) == CLIQ_DEPENDENCY_DATA_OK);
    check(close(fd) == 0); check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_RETIREMENT);
    check(owner.fd == -1 && !owner.retired && owner.unsafe); check(cliq_dependency_data_retire(&owner) == CLIQ_DEPENDENCY_DATA_RETIREMENT);
    check(descriptors() == before); printf("dependency-package-data checks=%u fdDelta=0 qualification=false\n", checks); return 0;
}
