/* Actual owned bounded tmpfs geometry only. This cannot qualify a user
 * namespace, signed package, source scope, worker or Run. */
#define _GNU_SOURCE
#include "source-storage.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    assert(source_tmpfs_budget(UINT64_C(16777216)) == UINT64_C(16777216));
    assert(source_tmpfs_budget(UINT64_C(16781311)) == UINT64_C(16777216));
    assert(source_tmpfs_budget(UINT64_C(4095)) == 0);
    char name[] = "/dev/shm/cliq-source-storage-XXXXXX";
    assert(mkdtemp(name) != NULL);
    int directory = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(directory >= 0);
    struct statfs filesystem;
    assert(fstatfs(directory, &filesystem) == 0 && filesystem.f_type == 0x01021994 && filesystem.f_bsize > 0 && filesystem.f_blocks > 0);
    const uint64_t capacity = (uint64_t)filesystem.f_bsize * (uint64_t)filesystem.f_blocks;
    assert(source_tmpfs_within(directory, capacity));
    assert(!source_tmpfs_within(directory, capacity - 1));
    assert(!source_tmpfs_within(directory, 0));
    assert(!source_tmpfs_within(-1, capacity));
    int file = openat(directory, "ordinary", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    assert(file >= 0 && !source_tmpfs_within(file, capacity));
    assert(close(file) == 0 && unlinkat(directory, "ordinary", 0) == 0);
    assert(close(directory) == 0 && rmdir(name) == 0);
    return 0;
}
