#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PATH_BYTES 4096
#define MAX_OUTPUT_BYTES 16384

struct sha256_context {
    uint8_t data[64];
    uint32_t state[8];
    uint64_t bit_length;
    size_t data_length;
};

static const uint32_t sha256_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
};

static uint32_t rotate_right(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

static void sha256_transform(struct sha256_context *context, const uint8_t block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; index++) {
        words[index] = ((uint32_t)block[index * 4] << 24) |
                       ((uint32_t)block[index * 4 + 1] << 16) |
                       ((uint32_t)block[index * 4 + 2] << 8) |
                       (uint32_t)block[index * 4 + 3];
    }
    for (size_t index = 16; index < 64; index++) {
        uint32_t s0 = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    uint32_t a = context->state[0], b = context->state[1], c = context->state[2],
             d = context->state[3], e = context->state[4], f = context->state[5],
             g = context->state[6], h = context->state[7];
    for (size_t index = 0; index < 64; index++) {
        uint32_t sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sigma1 + choice + sha256_constants[index] + words[index];
        uint32_t sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sigma0 + majority;
        h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

static void sha256_init(struct sha256_context *context) {
    context->data_length = 0;
    context->bit_length = 0;
    uint32_t initial[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(context->state, initial, sizeof(initial));
}

static void sha256_update(struct sha256_context *context, const uint8_t *data, size_t length) {
    for (size_t index = 0; index < length; index++) {
        context->data[context->data_length++] = data[index];
        if (context->data_length == 64) {
            sha256_transform(context, context->data);
            context->bit_length += 512;
            context->data_length = 0;
        }
    }
}

static void sha256_final(struct sha256_context *context, uint8_t digest[32]) {
    size_t index = context->data_length;
    context->data[index++] = 0x80;
    if (index > 56) {
        while (index < 64) context->data[index++] = 0;
        sha256_transform(context, context->data);
        index = 0;
    }
    while (index < 56) context->data[index++] = 0;
    context->bit_length += context->data_length * 8;
    for (size_t offset = 0; offset < 8; offset++) {
        context->data[63 - offset] = (uint8_t)(context->bit_length >> (offset * 8));
    }
    sha256_transform(context, context->data);
    for (size_t word = 0; word < 8; word++) {
        digest[word * 4] = (uint8_t)(context->state[word] >> 24);
        digest[word * 4 + 1] = (uint8_t)(context->state[word] >> 16);
        digest[word * 4 + 2] = (uint8_t)(context->state[word] >> 8);
        digest[word * 4 + 3] = (uint8_t)context->state[word];
    }
}

static bool sha256_fd(int fd, char output[65]) {
    struct sha256_context context;
    sha256_init(&context);
    uint8_t buffer[64 * 1024];
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    for (;;) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (length == 0) break;
        sha256_update(&context, buffer, (size_t)length);
    }
    uint8_t digest[32];
    sha256_final(&context, digest);
    for (size_t index = 0; index < 32; index++) sprintf(output + index * 2, "%02x", digest[index]);
    output[64] = '\0';
    return true;
}

static bool sha256_self_test(void) {
    static const char expected[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    struct sha256_context context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)"abc", 3);
    uint8_t digest[32];
    char encoded[65];
    sha256_final(&context, digest);
    for (size_t index = 0; index < 32; index++) sprintf(encoded + index * 2, "%02x", digest[index]);
    encoded[64] = '\0';
    return strcmp(encoded, expected) == 0;
}

static void fail(const char *message) {
    fprintf(stderr, "cliq-linux-probe: %s: %s\n", message, strerror(errno));
    exit(1);
}

static void fail_message(const char *message) {
    fprintf(stderr, "cliq-linux-probe: %s\n", message);
    exit(1);
}

static bool is_sha256(const char *value) {
    if (value == NULL || strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static const char *argument_value(int argc, char **argv, const char *name) {
    for (int index = 2; index + 1 < argc; index += 2) {
        if (strcmp(argv[index], name) == 0) return argv[index + 1];
    }
    return NULL;
}

static void require_absolute_path(const char *value, const char *label) {
    if (value == NULL || value[0] != '/' || strlen(value) >= MAX_PATH_BYTES || strstr(value, "//") != NULL ||
        strstr(value, "/../") != NULL || strstr(value, "/./") != NULL) {
        fprintf(stderr, "cliq-linux-probe: %s must be a normalized absolute path\n", label);
        exit(1);
    }
}

static void write_all(int fd, const void *buffer, size_t length) {
    const uint8_t *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            fail("write failed");
        }
        cursor += written;
        length -= (size_t)written;
    }
}

static void write_text_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) fail(path);
    const uint8_t *cursor = (const uint8_t *)value;
    size_t remaining = strlen(value);
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            int saved_errno = errno;
            close(fd);
            fprintf(stderr, "cliq-linux-probe: write %s failed: %s\n", path, strerror(saved_errno));
            exit(1);
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    if (close(fd) != 0) {
        fprintf(stderr, "cliq-linux-probe: close %s failed: %s\n", path, strerror(errno));
        exit(1);
    }
}

static void join_path(char *output, size_t capacity, const char *base, const char *suffix) {
    size_t base_length = strlen(base);
    size_t suffix_length = strlen(suffix);
    if (base_length + suffix_length + 1 > capacity) fail_message("path overflow");
    memcpy(output, base, base_length);
    memcpy(output + base_length, suffix, suffix_length + 1);
}

static ssize_t read_text_file(const char *path, char *buffer, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length = read(fd, buffer, capacity - 1);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (length >= 0) buffer[length] = '\0';
    return length;
}

static bool file_contains(const char *path, const char *needle) {
    char buffer[4096];
    if (read_text_file(path, buffer, sizeof(buffer)) < 0) return false;
    return strstr(buffer, needle) != NULL;
}

static bool wait_for_file_text(const char *path, const char *needle, int timeout_ms) {
    const int interval_ms = 20;
    for (int elapsed = 0; elapsed <= timeout_ms; elapsed += interval_ms) {
        if (file_contains(path, needle)) return true;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = interval_ms * 1000 * 1000 };
        nanosleep(&delay, NULL);
    }
    return false;
}

static int count_lines(const char *path) {
    char buffer[16384];
    ssize_t length = read_text_file(path, buffer, sizeof(buffer));
    if (length < 0) return -1;
    int count = 0;
    for (ssize_t index = 0; index < length; index++) {
        if (buffer[index] == '\n') count++;
    }
    return count;
}

static void namespace_token(const char *name, char *output, size_t capacity) {
    char path[128];
    if (snprintf(path, sizeof(path), "/proc/self/ns/%s", name) >= (int)sizeof(path)) {
        fail_message("namespace path overflow");
    }
    ssize_t length = readlink(path, output, capacity - 1);
    if (length < 0 || (size_t)length >= capacity - 1) fail("readlink namespace failed");
    output[length] = '\0';
}

static bool path_is_denied(const char *path, bool write_access) {
    int flags = write_access ? O_WRONLY | O_CREAT | O_CLOEXEC : O_RDONLY | O_CLOEXEC;
    int fd = open(path, flags, 0600);
    if (fd >= 0) {
        close(fd);
        return false;
    }
    return errno == ENOENT || errno == EACCES || errno == EPERM || errno == EROFS;
}

static bool direct_network_denied(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return errno == EAFNOSUPPORT || errno == EPERM;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(53);
    if (inet_pton(AF_INET, "1.1.1.1", &address.sin_addr) != 1) {
        close(fd);
        return false;
    }
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(fd);
    return result < 0 && (saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH ||
                          saved_errno == ECONNREFUSED || saved_errno == EPERM);
}

static bool write_generation_marker(const char *challenge) {
    char marker[128];
    int marker_length = snprintf(marker, sizeof(marker), "cliq-linux-generation-%s", challenge);
    if (marker_length <= 0 || marker_length >= (int)sizeof(marker)) return false;
    int fd = open("/generation/probe-marker", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = write(fd, marker, (size_t)marker_length) == marker_length && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    int directory = open("/generation", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return false;
    if (fsync(directory) != 0) ok = false;
    close(directory);
    return ok;
}

static bool read_process_parent(pid_t pid, pid_t *parent_out) {
    char path[64];
    char buffer[512];
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >= (int)sizeof(path)) return false;
    if (read_text_file(path, buffer, sizeof(buffer)) < 0) return false;
    char *right_paren = strrchr(buffer, ')');
    if (right_paren == NULL) return false;
    long parent = 0;
    if (sscanf(right_paren + 1, " %*c %ld", &parent) != 1 || parent <= 0) return false;
    *parent_out = (pid_t)parent;
    return true;
}

static bool process_is_visible(pid_t pid) {
    char path[64];
    if (snprintf(path, sizeof(path), "/proc/%ld", (long)pid) >= (int)sizeof(path)) return false;
    struct stat metadata;
    return stat(path, &metadata) == 0 && S_ISDIR(metadata.st_mode);
}

static int run_guest(int argc, char **argv) {
    const char *challenge = argument_value(argc, argv, "--challenge");
    const char *helper_digest = argument_value(argc, argv, "--helper-sha256");
    const char *workspace = argument_value(argc, argv, "--workspace-path");
    const char *state_root = argument_value(argc, argv, "--state-root-path");
    const char *home = argument_value(argc, argv, "--home-path");
    const char *host_userns = argument_value(argc, argv, "--host-userns");
    const char *host_mntns = argument_value(argc, argv, "--host-mntns");
    const char *host_netns = argument_value(argc, argv, "--host-netns");
    const char *host_pidns = argument_value(argc, argv, "--host-pidns");
    const char *host_cgroupns = argument_value(argc, argv, "--host-cgroupns");
    if (!is_sha256(challenge) || !is_sha256(helper_digest)) return 1;
    require_absolute_path(workspace, "workspace path");
    require_absolute_path(state_root, "state root path");
    require_absolute_path(home, "home path");

    int self_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    char observed_helper_digest[65];
    if (self_fd < 0 || !sha256_fd(self_fd, observed_helper_digest) ||
        strcmp(observed_helper_digest, helper_digest) != 0) return 1;
    close(self_fd);

    if (getpid() != 2 || getppid() != 1) return 1;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) return 1;
    int subreaper = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, &subreaper, 0, 0, 0) != 0 || subreaper != 1) return 1;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 1;

    char userns[64], mntns[64], netns[64], pidns[64], cgroupns[64];
    namespace_token("user", userns, sizeof(userns));
    namespace_token("mnt", mntns, sizeof(mntns));
    namespace_token("net", netns, sizeof(netns));
    namespace_token("pid", pidns, sizeof(pidns));
    namespace_token("cgroup", cgroupns, sizeof(cgroupns));
    if (strcmp(userns, host_userns) == 0 || strcmp(mntns, host_mntns) == 0 ||
        strcmp(netns, host_netns) == 0 || strcmp(pidns, host_pidns) == 0 ||
        strcmp(cgroupns, host_cgroupns) == 0) return 1;

    if (!write_generation_marker(challenge)) return 1;
    if (!path_is_denied(workspace, false) || !path_is_denied(workspace, true) ||
        !path_is_denied(state_root, false) || !path_is_denied(state_root, true) ||
        !path_is_denied(home, false) || !direct_network_denied()) return 1;

    int grandchild_pipe[2];
    if (pipe2(grandchild_pipe, O_CLOEXEC) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(grandchild_pipe[0]);
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(1);
        if (grandchild == 0) {
            close(grandchild_pipe[1]);
            if (setsid() < 0) _exit(1);
            for (;;) pause();
        }
        write_all(grandchild_pipe[1], &grandchild, sizeof(grandchild));
        close(grandchild_pipe[1]);
        _exit(0);
    }
    close(grandchild_pipe[1]);
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        return 1;
    }
    pid_t grandchild = 0;
    if (read(grandchild_pipe[0], &grandchild, sizeof(grandchild)) != (ssize_t)sizeof(grandchild)) return 1;
    close(grandchild_pipe[0]);
    struct timespec settle = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&settle, NULL);
    pid_t observed_parent = 0;
    if (!process_is_visible(grandchild) || !read_process_parent(grandchild, &observed_parent) ||
        observed_parent != getpid()) return 1;

    printf("CLIQ_LINUX_GUEST_READY %s %s\n", challenge, helper_digest);
    fflush(stdout);
    for (;;) pause();
}

static bool wait_for_guest_ready(int fd, const char *challenge, const char *helper_digest, int timeout_ms) {
    char expected[160];
    if (snprintf(expected, sizeof(expected), "CLIQ_LINUX_GUEST_READY %s %s", challenge, helper_digest) >=
        (int)sizeof(expected)) return false;
    char output[MAX_OUTPUT_BYTES];
    size_t used = 0;
    int remaining = timeout_ms;
    while (remaining > 0 && used + 1 < sizeof(output)) {
        struct pollfd descriptor = { .fd = fd, .events = POLLIN | POLLHUP };
        int interval = remaining > 100 ? 100 : remaining;
        int poll_result = poll(&descriptor, 1, interval);
        remaining -= interval;
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (poll_result == 0) continue;
        ssize_t length = read(fd, output + used, sizeof(output) - used - 1);
        if (length < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (length == 0) break;
        used += (size_t)length;
        output[used] = '\0';
        if (strstr(output, expected) != NULL) return true;
    }
    if (used > 0) fprintf(stderr, "%.*s", (int)used, output);
    return false;
}

static int run_host(int argc, char **argv) {
    const char *bwrap = argument_value(argc, argv, "--bwrap");
    const char *cgroup_parent = argument_value(argc, argv, "--cgroup-parent");
    const char *generation = argument_value(argc, argv, "--generation");
    const char *challenge = argument_value(argc, argv, "--challenge");
    const char *helper_digest = argument_value(argc, argv, "--helper-sha256");
    const char *bwrap_digest = argument_value(argc, argv, "--bwrap-sha256");
    const char *workspace = argument_value(argc, argv, "--workspace-path");
    const char *state_root = argument_value(argc, argv, "--state-root-path");
    const char *home = argument_value(argc, argv, "--home-path");
    require_absolute_path(bwrap, "bubblewrap path");
    require_absolute_path(cgroup_parent, "cgroup parent");
    require_absolute_path(generation, "generation path");
    require_absolute_path(workspace, "workspace path");
    require_absolute_path(state_root, "state root path");
    require_absolute_path(home, "home path");
    if (!is_sha256(challenge) || !is_sha256(helper_digest) || !is_sha256(bwrap_digest)) {
        fail_message("challenge and executable identities must be raw SHA-256 digests");
    }

    int self_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int bwrap_fd = open(bwrap, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char observed_helper_digest[65], observed_bwrap_digest[65];
    if (self_fd < 0 || bwrap_fd < 0 || !sha256_fd(self_fd, observed_helper_digest) ||
        !sha256_fd(bwrap_fd, observed_bwrap_digest) || strcmp(observed_helper_digest, helper_digest) != 0 ||
        strcmp(observed_bwrap_digest, bwrap_digest) != 0) {
        fail_message("executable digest verification failed");
    }

    struct stat parent_metadata;
    if (lstat(cgroup_parent, &parent_metadata) != 0 || !S_ISDIR(parent_metadata.st_mode) ||
        parent_metadata.st_uid != geteuid()) fail_message("cgroup parent is not delegated to this uid");

    char cgroup_path[MAX_PATH_BYTES];
    if (snprintf(cgroup_path, sizeof(cgroup_path), "%s/cliq-probe-%ld-%.12s", cgroup_parent,
                 (long)getpid(), challenge) >= (int)sizeof(cgroup_path)) fail_message("cgroup path overflow");
    if (mkdir(cgroup_path, 0700) != 0) fail("create probe cgroup failed");
    chmod(cgroup_path, 0700);
    struct stat cgroup_metadata;
    if (lstat(cgroup_path, &cgroup_metadata) != 0 || cgroup_metadata.st_uid != geteuid()) {
        fail_message("probe cgroup ownership mismatch");
    }

    char cgroup_procs[MAX_PATH_BYTES], cgroup_events[MAX_PATH_BYTES], cgroup_freeze[MAX_PATH_BYTES],
        cgroup_kill[MAX_PATH_BYTES];
    join_path(cgroup_procs, sizeof(cgroup_procs), cgroup_path, "/cgroup.procs");
    join_path(cgroup_events, sizeof(cgroup_events), cgroup_path, "/cgroup.events");
    join_path(cgroup_freeze, sizeof(cgroup_freeze), cgroup_path, "/cgroup.freeze");
    join_path(cgroup_kill, sizeof(cgroup_kill), cgroup_path, "/cgroup.kill");
    char pids_max[MAX_PATH_BYTES], memory_max[MAX_PATH_BYTES], cpu_max[MAX_PATH_BYTES];
    join_path(pids_max, sizeof(pids_max), cgroup_path, "/pids.max");
    join_path(memory_max, sizeof(memory_max), cgroup_path, "/memory.max");
    join_path(cpu_max, sizeof(cpu_max), cgroup_path, "/cpu.max");
    write_text_file(pids_max, "64\n");
    write_text_file(memory_max, "268435456\n");
    write_text_file(cpu_max, "40000 100000\n");
    if (!file_contains(pids_max, "64") || !file_contains(memory_max, "268435456") ||
        !file_contains(cpu_max, "40000 100000")) fail_message("cgroup resource limits did not persist");

    char userns[64], mntns[64], netns[64], pidns[64], cgroupns[64];
    namespace_token("user", userns, sizeof(userns));
    namespace_token("mnt", mntns, sizeof(mntns));
    namespace_token("net", netns, sizeof(netns));
    namespace_token("pid", pidns, sizeof(pidns));
    namespace_token("cgroup", cgroupns, sizeof(cgroupns));
    int barrier[2], output[2];
    if (pipe2(barrier, O_CLOEXEC) != 0 || pipe2(output, O_CLOEXEC) != 0) fail("pipe failed");
    pid_t child = fork();
    if (child < 0) fail("fork failed");
    if (child == 0) {
        close(barrier[1]);
        close(output[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0 || dup2(output[1], STDERR_FILENO) < 0) _exit(126);
        close(output[1]);
        char release = 0;
        if (read(barrier[0], &release, 1) != 1) _exit(126);
        close(barrier[0]);
        /* Give bubblewrap the already-verified inode, not a path it would reopen. */
        int helper_fd_flags = fcntl(self_fd, F_GETFD);
        if (helper_fd_flags < 0 || fcntl(self_fd, F_SETFD, helper_fd_flags & ~FD_CLOEXEC) != 0 ||
            lseek(self_fd, 0, SEEK_SET) < 0) _exit(126);
        char helper_fd_text[32];
        if (snprintf(helper_fd_text, sizeof(helper_fd_text), "%d", self_fd) >=
            (int)sizeof(helper_fd_text)) _exit(126);
        char *const bwrap_argv[] = {
            (char *)bwrap, "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid",
            "--unshare-net", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--hostname",
            "cliq-probe", "--new-session", "--die-with-parent", "--clearenv", "--setenv", "PATH", "/",
            "--cap-drop", "ALL", "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--dir",
            "/generation", "--bind", (char *)generation, "/generation", "--perms", "0555",
            "--ro-bind-data", helper_fd_text, "/cliq-probe", "--chdir", "/generation", "--",
            "/cliq-probe", "--guest", "--challenge",
            (char *)challenge, "--helper-sha256", (char *)helper_digest, "--workspace-path", (char *)workspace,
            "--state-root-path", (char *)state_root, "--home-path", (char *)home, "--host-userns", userns,
            "--host-mntns", mntns, "--host-netns", netns, "--host-pidns", pidns, "--host-cgroupns",
            cgroupns, NULL
        };
        char *const clean_environment[] = { "PATH=/usr/bin:/bin", NULL };
        fexecve(bwrap_fd, bwrap_argv, clean_environment);
        _exit(127);
    }
    close(barrier[0]);
    close(output[1]);

    char child_text[64];
    snprintf(child_text, sizeof(child_text), "%ld\n", (long)child);
    write_text_file(cgroup_procs, child_text);
    write_all(barrier[1], "1", 1);
    close(barrier[1]);

    if (!wait_for_guest_ready(output[0], challenge, helper_digest, 20000)) {
        write_text_file(cgroup_kill, "1\n");
        waitpid(child, NULL, 0);
        close(output[0]);
        rmdir(cgroup_path);
        fail_message("sandboxed guest did not produce a complete receipt");
    }
    close(output[0]);
    int descendants = count_lines(cgroup_procs);
    if (descendants < 3) {
        write_text_file(cgroup_kill, "1\n");
        waitpid(child, NULL, 0);
        rmdir(cgroup_path);
        fail_message("cgroup did not enumerate the complete descendant set");
    }

    write_text_file(cgroup_freeze, "1\n");
    if (!wait_for_file_text(cgroup_events, "frozen 1", 5000)) fail_message("cgroup.freeze did not freeze");
    write_text_file(cgroup_freeze, "0\n");
    if (!wait_for_file_text(cgroup_events, "frozen 0", 5000)) fail_message("cgroup.freeze did not thaw");
    write_text_file(cgroup_kill, "1\n");
    if (!wait_for_file_text(cgroup_events, "populated 0", 5000)) fail_message("cgroup.kill did not empty");
    waitpid(child, NULL, 0);
    if (count_lines(cgroup_procs) != 0) fail_message("cgroup remained populated after kill");
    if (rmdir(cgroup_path) != 0) fail("remove empty probe cgroup failed");
    close(self_fd);
    close(bwrap_fd);

    printf("{\"backend\":\"linux_namespace\",\"bubblewrapDigest\":\"%s\",\"challenge\":\"%s\","
           "\"helperDigest\":\"%s\",\"observations\":{"
           "\"cgroupEmpty\":true,\"cgroupFreeze\":true,\"cgroupKill\":true,\"cgroupOwned\":true,"
           "\"cgroupV2\":true,\"daemonContained\":true,\"descendantsEnumerated\":true,"
           "\"directNetworkDenied\":true,\"forcedTerminationEmpty\":true,\"generationWrite\":true,"
           "\"helperIdentityObserved\":true,\"homeReadDenied\":true,\"mountNamespace\":true,"
           "\"networkNamespace\":true,\"noNewPrivileges\":true,\"pidNamespace\":true,"
           "\"resourceLimits\":true,\"stateReadDenied\":true,\"stateWriteDenied\":true,\"subreaper\":true,"
           "\"userNamespace\":true,\"workerIdentityVerified\":true,\"workspaceReadDenied\":true,"
           "\"workspaceWriteDenied\":true},\"protocolVersion\":\"cliq-execution-backend-probe-v1\","
           "\"schemaVersion\":1}\n", bwrap_digest, challenge, helper_digest);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) fail_message("expected --host or --guest");
    if (strcmp(argv[1], "--self-test") == 0) return sha256_self_test() ? 0 : 1;
    if (strcmp(argv[1], "--guest") == 0) return run_guest(argc, argv);
    if (strcmp(argv[1], "--host") == 0) return run_host(argc, argv);
    fail_message("expected --host or --guest");
    return 1;
}
