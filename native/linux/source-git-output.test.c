/* Real private tmpfs/nlink/read/EOF/memfd/close component, using the exact
 * compiled signed controller collector. No namespace, Run, owner, source
 * grant, successful result or physical death qualification is minted. */
#define main cliq_original_controller_main
#include "cliq-linux-worker-controller.c"
#undef main

static unsigned int output_checks;
static void output_check(bool valid, const char *message) {
    output_checks++;
    if (!valid) { fprintf(stderr, "source output component failed: %s\n", message); exit(1); }
}
static size_t output_fds(void) {
    DIR *directory = opendir("/proc/self/fd"); output_check(directory != NULL, "actual FD inventory");
    size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    output_check(closedir(directory) == 0, "inventory actual close"); return count;
}
static const size_t output_lengths[] = { 2, 31, 70001, 1072 };
static unsigned char output_byte(size_t role, size_t offset) { return (unsigned char)((offset * 31 + role) % 251); }
static void output_fixture(int directory) {
    for (size_t role = 0; role < CLIQ_SOURCE_OUTPUTS; role++) {
        int file = openat(directory, source_output_names[role], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        output_check(file >= 0, "owned regular output birth");
        unsigned char bytes[65536]; size_t offset = 0;
        while (offset < output_lengths[role]) {
            size_t length = output_lengths[role] - offset < sizeof(bytes) ? output_lengths[role] - offset : sizeof(bytes);
            for (size_t i = 0; i < length; i++) bytes[i] = output_byte(role, offset + i);
            output_check(source_write_all(file, bytes, length), "actual complete output fixture bytes"); offset += length;
        }
        output_check(source_close_fd(&file), "fixture writer close");
    }
}
static void output_close_results(int outputs[CLIQ_SOURCE_OUTPUTS]) {
    for (size_t role = 0; role < CLIQ_SOURCE_OUTPUTS; role++) output_check(source_close_fd(&outputs[role]), "original sealed output close");
}
static bool output_collect(int directory, struct cliq_worker_packet *request, uint32_t *failure) {
    const size_t baseline = output_fds();
    int outputs[CLIQ_SOURCE_OUTPUTS] = { -1, -1, -1, -1 }; struct cliq_worker_packet result = {0};
    bool accepted = source_output_copy(directory, request, outputs, &result, failure);
    if (accepted) for (size_t role = 0; role < CLIQ_SOURCE_OUTPUTS; role++) {
        struct stat object;
        output_check(fstat(outputs[role], &object) == 0 && S_ISREG(object.st_mode) && object.st_nlink == 0 &&
            object.st_size == (off_t)output_lengths[role] && (fcntl(outputs[role], F_GETFL) & O_ACCMODE) == O_RDONLY &&
            fcntl(outputs[role], F_GET_SEALS) == (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL), "actual immutable RO output shape");
        struct sha256_context hash; sha256_init(&hash); size_t offset = 0; unsigned char bytes[65536];
        for (;;) {
            ssize_t got = read(outputs[role], bytes, sizeof(bytes));
            output_check(got >= 0, "actual readonly output read"); if (got == 0) break;
            output_check(offset + (size_t)got <= output_lengths[role], "actual full output length ceiling");
            for (size_t i = 0; i < (size_t)got; i++) output_check(bytes[i] == output_byte(role, offset + i), "actual full byte equality");
            sha256_update(&hash, bytes, (size_t)got); offset += (size_t)got;
        }
        unsigned char digest[32]; char expected[65]; sha256_final(&hash, digest); source_hex(digest, expected);
        output_check(offset == output_lengths[role] && result.source_output_bytes[role] == offset &&
            strcmp(result.source_output_digests[role], expected) == 0, "original digest/count complete EOF equality");
        output_check(pwrite(outputs[role], "x", 1, 0) < 0 && ftruncate(outputs[role], 0) < 0, "actual sealed output cannot mutate");
    }
    output_close_results(outputs); output_check(output_fds() == baseline, "all actual collector FDs joined"); return accepted;
}
int main(void) {
    const size_t original = output_fds();
    char root[] = "/dev/shm/cliq-output-XXXXXX"; output_check(mkdtemp(root) != NULL, "owned tmpfs fixture root");
    int parent = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); output_check(parent >= 0, "held fixture root");
    output_check(mkdirat(parent, "output", 0700) == 0, "owned output directory birth");
    int directory = openat(parent, "output", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); output_check(directory >= 0, "held output directory");
    struct cliq_worker_packet request = cliq_packet(CLIQ_SOURCE_RESERVE);
    request.max_file_bytes = 1048576; request.max_generation_bytes = 268435456; request.max_output_bytes = 65536;
    output_fixture(directory); uint64_t pages = 0; uint32_t failure = 0;
    output_check(source_output_inventory(directory, &request, &pages, &failure) && pages == 86016, "same fixed four namespace and exact original page accounting");
    output_check(source_output_inventory(directory, &request, &pages, &failure) && pages == 86016, "independent directory cursor supports fresh full re-observation");
    output_check(output_collect(directory, &request, &failure), "real complete four output immutable copies");
    pid_t limited = fork(); output_check(limited >= 0, "actual owned descriptor-bound child");
    if (limited == 0) {
        struct rlimit original_limit; if (getrlimit(RLIMIT_NOFILE, &original_limit) != 0) _exit(1);
        int highest = directory > parent ? directory : parent;
        struct rlimit limited_fd = original_limit; limited_fd.rlim_cur = (rlim_t)highest + 2;
        if (setrlimit(RLIMIT_NOFILE, &limited_fd) != 0) _exit(1);
        int outputs[4] = {-1, -1, -1, -1}; struct cliq_worker_packet result = {0}; uint32_t reason = 0;
        bool accepted = source_output_copy(directory, &request, outputs, &result, &reason);
        bool valid = !accepted && reason == CLIQ_SOURCE_OUTPUT_WRITER;
        for (size_t i = 0; i < 4; i++) if (!source_close_fd(&outputs[i])) valid = false;
        if (setrlimit(RLIMIT_NOFILE, &original_limit) != 0) valid = false;
        if (!source_close_fd(&directory) || !source_close_fd(&parent)) valid = false;
        _exit(valid ? 0 : 1);
    }
    int limited_status = 0; pid_t joined;
    do { joined = waitpid(limited, &limited_status, 0); } while (joined < 0 && errno == EINTR);
    output_check(joined == limited && WIFEXITED(limited_status) && WEXITSTATUS(limited_status) == 0,
        "actual memfd allocation failure retains diagnosis and joins all reader/writer FDs");
    output_check(linkat(directory, "canonical.index", parent, "alias", 0) == 0, "real extra hard link fixture");
    output_check(!output_collect(directory, &request, &failure) && failure == CLIQ_SOURCE_OUTPUT_LINKS, "nlink-one guard remains exact");
    output_check(unlinkat(parent, "alias", 0) == 0, "extra hard link actual cleanup");
    request.max_output_bytes = 1;
    output_check(!output_collect(directory, &request, &failure) && failure == CLIQ_SOURCE_OUTPUT_METADATA_SIZE, "metadata original output ceiling retained");
    request.max_output_bytes = 65536; request.max_file_bytes = 70000;
    output_check(!source_output_inventory(directory, &request, &pages, &failure) && failure == CLIQ_SOURCE_OUTPUT_CAPACITY_FILE, "actual oversize regular file refused before copy");
    request.max_file_bytes = 1048576; request.max_generation_bytes = 86015;
    output_check(!source_output_inventory(directory, &request, &pages, &failure) && failure == CLIQ_SOURCE_OUTPUT_CAPACITY, "rounded simultaneous copy capacity retains original bound");
    request.max_generation_bytes = 268435456;
    const char *unexpected_names[] = { "extra", "reachable.rev", "input.verified.rev", "canonical.index.lock", "tmp_pack_owned" };
    for (size_t i = 0; i < sizeof(unexpected_names) / sizeof(unexpected_names[0]); i++) {
        int unexpected = openat(directory, unexpected_names[i], O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
        output_check(unexpected >= 0 && source_close_fd(&unexpected), "actual unexpected object fixture");
        output_check(!source_output_inventory(directory, &request, &pages, &failure) && failure == CLIQ_SOURCE_OUTPUT_NAME, "every extra namespace entry remains rejected");
        output_check(unlinkat(directory, unexpected_names[i], 0) == 0, "actual rejected extra fixture cleanup");
    }
    output_check(unlinkat(directory, "reachable.idx", 0) == 0, "actual entry removal");
    output_check(!source_output_inventory(directory, &request, &pages, &failure) && failure == CLIQ_SOURCE_OUTPUT_COMPLETE_NAMES, "missing role remains rejected");
    output_check(symlinkat("canonical.index", directory, "reachable.idx") == 0, "actual symlink fixture");
    output_check(!source_output_inventory(directory, &request, &pages, &failure) && failure == CLIQ_SOURCE_OUTPUT_CAPACITY_FILE, "fixed named no-follow regular-file guard retained");
    output_check(!output_collect(directory, &request, &failure) && failure == CLIQ_SOURCE_OUTPUT_OPEN, "actual symlink is never opened for output");
    output_check(unlinkat(directory, "reachable.idx", 0) == 0, "actual symlink removal");
    for (size_t i = 0; i < CLIQ_SOURCE_OUTPUTS - 1; i++) output_check(unlinkat(directory, source_output_names[i], 0) == 0, "owned original output cleanup");
    output_check(source_close_fd(&directory) && unlinkat(parent, "output", AT_REMOVEDIR) == 0 && source_close_fd(&parent) && rmdir(root) == 0, "all fixture directories and FDs joined");
    output_check(output_fds() == original, "original complete descriptor inventory restored");
    printf("{\"format\":\"cliq-source-output-component-v1\",\"checks\":%u,\"actualRunQualified\":false,\"scratchRemountQualified\":false}\n", output_checks);
    return 0;
}
