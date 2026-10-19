/* Real file/descriptor checks only, not a namespace or Node qualification. */
#define _GNU_SOURCE
#include "verifier-node.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static const char digest[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static void create_node(int directory) {
    int writer = openat(directory, "node", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(writer >= 0 && write(writer, "abc", 3) == 3 && fchown(writer, geteuid(), getegid()) == 0 &&
        fchmod(writer, 0555) == 0 && close(writer) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char location[4096];
    int length = snprintf(location, sizeof(location), "%s/verifier-node-XXXXXX", argv[1]);
    assert(length > 0 && (size_t)length < sizeof(location));
    assert(mkdtemp(location));
    int directory = open(location, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(directory >= 0);
    create_node(directory);
    struct stat held;
    int image = cliq_verifier_node_open(directory, 3, digest, &held);
    assert(image >= 0 && cliq_verifier_node_current(directory, image, &held));
    char bytes[3];
    assert(pread(image, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "abc", 3));
    assert((fcntl(image, F_GETFD) & FD_CLOEXEC) != 0 && (fcntl(image, F_GETFL) & O_ACCMODE) == O_RDONLY);

    /* The original failure pattern: readable correct bytes on a held, now
     * unlinked inode are not an executable with a stable canonical name. */
    assert(unlinkat(directory, "node", 0) == 0);
    assert(pread(image, bytes, sizeof(bytes), 0) == 3 && !memcmp(bytes, "abc", 3));
    assert(!cliq_verifier_node_current(directory, image, &held));
    assert(cliq_verifier_node_open(directory, 3, digest, &held) < 0 && close(image) == 0);

    create_node(directory);
    image = cliq_verifier_node_open(directory, 3, digest, &held);
    assert(image >= 0 && renameat(directory, "node", directory, "retired") == 0);
    create_node(directory);
    /* Equal bytes do not let a replacement directory entry claim the old FD. */
    assert(!cliq_verifier_node_current(directory, image, &held) && close(image) == 0);
    assert(unlinkat(directory, "retired", 0) == 0);

    struct stat replacement;
    image = cliq_verifier_node_open(directory, 3, digest, &replacement);
    assert(image >= 0 && cliq_verifier_node_current(directory, image, &replacement));
    assert(linkat(directory, "node", directory, "alias", 0) == 0);
    assert(!cliq_verifier_node_current(directory, image, &replacement));
    assert(cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(unlinkat(directory, "alias", 0) == 0 && close(image) == 0);

    image = cliq_verifier_node_open(directory, 3, digest, &held);
    assert(image >= 0 && fchmodat(directory, "node", 0755, 0) == 0);
    assert(!cliq_verifier_node_current(directory, image, &held) && close(image) == 0);
    assert(cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(fchmodat(directory, "node", 04755, 0) == 0 && cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(fchmodat(directory, "node", 0644, 0) == 0 && cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(fchmodat(directory, "node", 0555, 0) == 0);

    assert(cliq_verifier_node_open(directory, 2, digest, &held) < 0);
    assert(cliq_verifier_node_open(directory, 0, digest, &held) < 0);
    assert(cliq_verifier_node_open(directory, UINT64_C(268435457), digest, &held) < 0);
    assert(cliq_verifier_node_open(directory, 3,
        "aa7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &held) < 0);
    char empty_digest[65] = "";
    assert(cliq_verifier_node_open(directory, 3, empty_digest, &held) < 0);
    assert(cliq_verifier_node_open(directory, 3,
        "Ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &held) < 0);

    assert(renameat(directory, "node", directory, "target") == 0 && symlinkat("target", directory, "node") == 0);
    assert(cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(unlinkat(directory, "node", 0) == 0 && unlinkat(directory, "target", 0) == 0);
    assert(mkfifoat(directory, "node", 0600) == 0 && cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(unlinkat(directory, "node", 0) == 0);
    assert(mkdirat(directory, "node", 0555) == 0 && cliq_verifier_node_open(directory, 3, digest, &held) < 0);
    assert(unlinkat(directory, "node", AT_REMOVEDIR) == 0);

    /* Independent SHA-256 fixture (65,536 'a' bytes, then 'b'): checking only
     * the first read chunk cannot accept it or detect its changed last byte. */
    unsigned char large[65537]; memset(large, 'a', sizeof(large)); large[sizeof(large) - 1] = 'b';
    int writer = openat(directory, "node", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(writer >= 0 && write(writer, large, sizeof(large)) == (ssize_t)sizeof(large) &&
        fchown(writer, geteuid(), getegid()) == 0 && fchmod(writer, 0555) == 0 && close(writer) == 0);
    const char tail_digest[] = "935bf57d7f52181f095c3a3484b68e542037e287f7cde4ffe8a32896d428a1b1";
    image = cliq_verifier_node_open(directory, sizeof(large), tail_digest, &held);
    assert(image >= 0 && close(image) == 0);
    assert(fchmodat(directory, "node", 0600, 0) == 0);
    writer = openat(directory, "node", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(writer >= 0 && pwrite(writer, "a", 1, sizeof(large) - 1) == 1 && fchmod(writer, 0555) == 0 && close(writer) == 0);
    assert(cliq_verifier_node_open(directory, sizeof(large), tail_digest, &held) < 0);
    assert(unlinkat(directory, "node", 0) == 0);

    assert(close(directory) == 0 && rmdir(location) == 0);
    return 0;
}
