#ifndef CLIQ_GUEST_SHELL_TOOLS_H
#define CLIQ_GUEST_SHELL_TOOLS_H
#include <stdbool.h>
#include <string.h>

/* Only these additional discovery roots may enter the signed Bash recipe.
 * Each still needs its own pinned bytes, inode and complete ELF closure. */
static inline bool cliq_guest_shell_utility_path(const char *path) {
    const char *paths[] = { "/usr/bin/cat", "/usr/bin/find", "/usr/bin/grep", "/usr/bin/head", "/usr/bin/ls",
        "/usr/bin/sed", "/usr/bin/sort", "/usr/bin/tail", "/usr/bin/uniq", "/usr/bin/wc", "/usr/bin/xargs" };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) if (!strcmp(path, paths[i])) return true;
    return false;
}
static inline bool cliq_builtin_shell_path(const char *path) {
    return !strcmp(path, "/usr/bin/git") || !strcmp(path, "/bin/bash") || cliq_guest_shell_utility_path(path);
}
#endif
