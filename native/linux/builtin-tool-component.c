/* Real native parser/sealed-FD component only. Never a Run, namespace,
 * StateOwner, grant, dispatch or physical containment qualification. */
#define main cliq_owned_controller_entry
#include "cliq-linux-worker-controller.c"
#undef main
#include <assert.h>
static void literal(struct cliq_verifier_config *config, const char *text, uint32_t *at) {
    *at = config->string_bytes; size_t size = strlen(text) + 1;
    assert(size <= sizeof(config->strings) - config->string_bytes);
    memcpy(config->strings + config->string_bytes, text, size); config->string_bytes += (uint32_t)size;
}
static void fixed_config(struct cliq_builtin_config *fixed, bool bash) {
    memset(fixed, 0, sizeof(*fixed)); struct cliq_verifier_config *config = &fixed->capture;
    config->magic = CLIQ_VERIFIER_CONFIG_MAGIC; config->version = 1; config->argument_count = 3; config->environment_count = bash ? 6 : 5;
    config->file_count = bash ? 3 : 1; config->timeout_ms = 60000; config->output_limit = 67108864;
    strcpy(config->executable, "/usr/bin/node"); strcpy(config->cwd, "/work");
    const char *arguments[] = { "/usr/bin/node", "--no-addons", CLIQ_BUILTIN_SCRIPT_PATH };
    const char *environment[] = { "LANG=C", "LC_ALL=C", "HOME=/home/cliq", "TMPDIR=/tmp", bash ? "PATH=/usr/bin:/bin" : "PATH=/usr/bin", "GIT_OPTIONAL_LOCKS=0" };
    for (size_t i = 0; i < 3; i++) literal(config, arguments[i], &config->arguments[i]);
    for (size_t i = 0; i < config->environment_count; i++) literal(config, environment[i], &config->environment[i]);
    const char *paths[] = { "/usr/bin/node", "/usr/bin/git", "/bin/bash" };
    for (uint32_t i = 0; i < config->file_count; i++) {
        strcpy(config->files[i].path, paths[i]); config->files[i].byte_count = 1; memset(config->files[i].digest, 'a', 64);
    }
    fixed->builtin_magic = CLIQ_BUILTIN_CONFIG_MAGIC; fixed->builtin_version = 1; fixed->tool = bash ? CLIQ_BUILTIN_BASH : CLIQ_BUILTIN_READ;
    fixed->script_bytes = fixed->input_bytes = 1; memset(fixed->script_digest, 'a', 64); memset(fixed->input_digest, 'a', 64);
    if (bash) { fixed->command_bytes = 1; memset(fixed->command_digest, 'a', 64); }
}
int main(void) {
    struct cliq_builtin_config fixed, changed; unsigned int checks = 0;
    assert(cliq_capture_generation_readonly(false, false, 0)); checks++; /* resident */
    assert(!cliq_capture_generation_readonly(true, false, 0)); checks++; /* original static edit */
    assert(cliq_capture_generation_readonly(true, true, 0)); checks++; /* original Node verifier */
    for (uint32_t tool = CLIQ_BUILTIN_READ; tool <= CLIQ_BUILTIN_BASH; tool++) {
        assert(cliq_capture_generation_readonly(true, true, tool) == (tool != CLIQ_BUILTIN_BASH)); checks++;
    }
    for (unsigned int bash = 0; bash < 2; bash++) {
        fixed_config(&fixed, bash != 0); assert(cliq_builtin_config_valid(&fixed)); checks++;
        if (bash) { assert(!cliq_verifier_config_valid(&fixed.capture)); checks++; } /* Bash mapping never widens the Node verifier validator. */
#define REFUSE(change) do { changed = fixed; change; assert(!cliq_builtin_config_valid(&changed)); checks++; } while (0)
        REFUSE(changed.builtin_version = 2); REFUSE(changed.git_kind = 2); REFUSE(changed.tool = 0); REFUSE(changed.tool = 6);
        REFUSE(changed.input_bytes = CLIQ_BUILTIN_INPUT_BYTES + 1); REFUSE(changed.script_bytes = 1048577);
        REFUSE(changed.script_digest[0] = 'A'); REFUSE(changed.capture.timeout_ms = 60001);
        REFUSE(changed.capture.output_limit = UINT64_C(67108865)); REFUSE(changed.capture.output_limit = 65535);
        REFUSE(changed.capture.argument_count = 4); REFUSE(changed.capture.environment_count++);
        REFUSE(changed.capture.strings[changed.capture.arguments[2]] = 'x');
        REFUSE(changed.capture.arguments[2]++); REFUSE(changed.capture.string_bytes++);
        REFUSE(strcpy(changed.capture.cwd, "/work/sub")); REFUSE(strcpy(changed.capture.files[0].path, "/usr/bin/other"));
        REFUSE(changed.capture.files[0].digest[0] = 'g'); REFUSE(changed.capture.files[0].byte_count = UINT64_C(268435457));
        if (bash) {
            REFUSE(changed.capture.file_count = 2); REFUSE(changed.command_bytes = 0); REFUSE(changed.command_digest[0] = '\0');
            REFUSE(changed.capture.strings[changed.capture.environment[5] + strlen("GIT_OPTIONAL_LOCKS=")] = '1');
        } else {
            REFUSE(changed.command_bytes = 1); REFUSE(changed.command_digest[0] = 'a');
            REFUSE(changed.git_kind = 1; changed.git_device = 1; changed.git_inode = 1);
        }
#undef REFUSE
        int fd = memfd_create("cliq-owned-fixed-config", MFD_CLOEXEC | MFD_ALLOW_SEALING); assert(fd >= 0);
        assert(write(fd, &fixed, sizeof(fixed)) == (ssize_t)sizeof(fixed));
        assert(!builtin_read_config(fd, &changed)); checks++;
        assert(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
        assert(builtin_read_config(fd, &changed)); checks++; assert(close(fd) == 0);
    }
    /* Actual descriptor-relative identity, absence, symlink and replacement
     * refusal. No mount/namespace/Run proof is manufactured here. */
    char directory[] = "/tmp/cliq-owned-git-identity.XXXXXX"; assert(mkdtemp(directory));
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); assert(root >= 0);
    fixed_config(&fixed, true); assert(cliq_builtin_capture_git_identity(root, &fixed)); assert(fixed.git_kind == 0); checks++;
    int held = -1; assert(cliq_builtin_open_git_identity(root, &fixed, &held) && held == -1); checks++;
    assert(symlinkat("/tmp", root, ".git") == 0); assert(!cliq_builtin_capture_git_identity(root, &fixed)); checks++;
    assert(!cliq_builtin_open_git_identity(root, &fixed, &held) && held == -1); checks++; assert(unlinkat(root, ".git", 0) == 0);
    assert(mkdirat(root, ".git", 0700) == 0); assert(cliq_builtin_capture_git_identity(root, &fixed) && fixed.git_kind == 1); checks++;
    assert(cliq_builtin_open_git_identity(root, &fixed, &held) && held >= 0); checks++; assert(close(held) == 0);
    assert(renameat(root, ".git", root, "original-git") == 0 && mkdirat(root, ".git", 0700) == 0);
    assert(!cliq_builtin_open_git_identity(root, &fixed, &held) && held == -1); checks++;
    assert(unlinkat(root, ".git", AT_REMOVEDIR) == 0 && unlinkat(root, "original-git", AT_REMOVEDIR) == 0 && close(root) == 0 && rmdir(directory) == 0);
    const char *digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    int fd = memfd_create("cliq-owned-script-data", MFD_CLOEXEC | MFD_ALLOW_SEALING); assert(fd >= 0);
    assert(write(fd, "abc", 3) == 3); assert(!builtin_sealed_data(fd, 3, digest)); checks++;
    assert(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
    assert(builtin_sealed_data(fd, 3, digest)); checks++; assert(!builtin_sealed_data(fd, 2, digest)); checks++;
    char wrong[65]; memset(wrong, 'a', 64); wrong[64] = '\0'; assert(!builtin_sealed_data(fd, 3, wrong)); checks++;
    assert(close(fd) == 0);
    printf("{\"format\":\"cliq-fixed-builtin-native-data-component-v1\",\"checks\":%u,\"runAuthority\":false,\"physicalContainmentQualified\":false}\n", checks);
    return 0;
}
