#ifndef CLIQ_BUILTIN_TOOL_GIT_H
#define CLIQ_BUILTIN_TOOL_GIT_H
#include "worker-common.h"
#include "builtin-tool-protocol.h"
/* Native observations of one fixed child of the original held generation.
 * No JS path, existence flag, descriptor or replacement root selects it. */
static inline bool cliq_builtin_git_metadata(const struct stat *root, const struct stat *git) {
    return S_ISDIR(root->st_mode) && S_ISDIR(git->st_mode) && root->st_dev == git->st_dev &&
        root->st_uid == geteuid() && git->st_uid == root->st_uid && git->st_gid == root->st_gid && (git->st_mode & 07777) == 0700;
}
static inline bool cliq_builtin_capture_git_identity(int generation, struct cliq_builtin_config *config) {
    struct stat root, git;
    if (fstat(generation, &root) != 0 || !S_ISDIR(root.st_mode)) return false;
    if (fstatat(generation, ".git", &git, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT;
    if (!cliq_builtin_git_metadata(&root, &git)) return false;
    config->git_kind = 1; config->git_device = (uint64_t)git.st_dev; config->git_inode = (uint64_t)git.st_ino;
    return true;
}
/* The caller owns *held from the instant openat succeeds, including failure;
 * its original controller close joins that descriptor with the other scopes. */
static inline bool cliq_builtin_open_git_identity(int generation, const struct cliq_builtin_config *config, int *held) {
    *held = -1; struct stat root, named, actual, after;
    if (fstat(generation, &root) != 0 || !S_ISDIR(root.st_mode)) return false;
    if (fstatat(generation, ".git", &named, AT_SYMLINK_NOFOLLOW) != 0) return config->git_kind == 0 && errno == ENOENT;
    if (config->git_kind != 1 || !cliq_builtin_git_metadata(&root, &named) ||
        (uint64_t)named.st_dev != config->git_device || (uint64_t)named.st_ino != config->git_inode) return false;
    *held = openat(generation, ".git", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return *held >= 0 && fstat(*held, &actual) == 0 && cliq_builtin_git_metadata(&root, &actual) &&
        actual.st_dev == named.st_dev && actual.st_ino == named.st_ino && actual.st_mode == named.st_mode &&
        actual.st_uid == named.st_uid && actual.st_gid == named.st_gid &&
        fstatat(generation, ".git", &after, AT_SYMLINK_NOFOLLOW) == 0 && after.st_dev == actual.st_dev && after.st_ino == actual.st_ino &&
        after.st_mode == actual.st_mode && after.st_uid == actual.st_uid && after.st_gid == actual.st_gid;
}
#endif
