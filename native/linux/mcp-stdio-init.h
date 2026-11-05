#ifndef CLIQ_MCP_STDIO_INIT_H
#define CLIQ_MCP_STDIO_INIT_H
/* Fixed signed controller's contained C client. The selected static server
 * has only stdin/stdout/stderr after exec; it never receives operation IPC,
 * a recipe/state FD, a host mount, an interpreter or network permission. */
#include "mcp-stdio-protocol.h"
#include <sys/mman.h>
static volatile sig_atomic_t mcp_stdio_cancelled;
static void mcp_stdio_cancel_signal(int number) {
    (void)number;
    mcp_stdio_cancelled = 1;
}
struct mcp_stdio_client {
    int operation, input, output[2];
    unsigned char *recipe, *ping;
    size_t recipe_size, write_at, write_size;
    const unsigned char *write_bytes;
    struct cliq_mcp_stdio_recipe_header header;
    uint64_t deadline, stop_deadline, output_bytes;
    unsigned next_phase, write_phase, ping_count, pending_stream;
    bool stopping, killed, write_ping, write_pending, written_pending, output_eof[2], protocol_done, server_reaped;
    pid_t server;
};
static uint32_t mcp_stdio_le32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}
static void mcp_stdio_put32(unsigned char *bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) bytes[i] = (unsigned char)(value >> (i * 8));
}
static uint64_t mcp_stdio_monotonic_ms(void) {
    struct timespec time;
    return clock_gettime(CLOCK_MONOTONIC, &time) ? 0 : (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}
static bool mcp_stdio_client_live(struct mcp_stdio_client *client) {
    uint64_t now = mcp_stdio_monotonic_ms();
    if (!now) return false;
    if (mcp_stdio_cancelled || now >= client->deadline) client->stopping = true;
    if (client->stopping && !client->killed) {
        client->killed = true;
        client->stop_deadline = now + 2000;
        /* This function runs only as the namespace's actual PID1. Linux
         * kill(-1) excludes that init, so it can drain and ACK real pipes. */
        if (getpid() != 1 || (kill(-1, SIGKILL) && errno != ESRCH)) return false;
        if (!source_close_fd(&client->input)) return false;
        client->write_pending = false;
        if (client->ping) { free(client->ping); client->ping = NULL; }
    }
    return !client->stop_deadline || now < client->stop_deadline;
}
static bool mcp_stdio_client_io(struct mcp_stdio_client *client, unsigned char *bytes, size_t size, bool sending) {
    size_t at = 0;
    while (at < size) {
        if (!mcp_stdio_client_live(client)) return false;
        struct pollfd descriptor = {.fd = client->operation, .events = sending ? POLLOUT : POLLIN};
        int available = poll(&descriptor, 1, 10);
        if (available < 0 && errno == EINTR) continue;
        if (available < 0 || (descriptor.revents & POLLNVAL)) return false;
        if (!available) continue;
        ssize_t n = sending ? send(client->operation, bytes + at, size - at, MSG_NOSIGNAL | MSG_DONTWAIT) :
            recv(client->operation, bytes + at, size - at, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}
static bool mcp_stdio_client_send(struct mcp_stdio_client *client, unsigned kind, const void *bytes, size_t size) {
    unsigned char header[16];
    if (size > CLIQ_MCP_STDIO_MAX_MESSAGE) return false;
    mcp_stdio_put32(header, CLIQ_MCP_STDIO_CHANNEL_MAGIC); mcp_stdio_put32(header + 4, 1);
    mcp_stdio_put32(header + 8, kind); mcp_stdio_put32(header + 12, (uint32_t)size);
    return mcp_stdio_client_io(client, header, sizeof(header), true) &&
        (!size || mcp_stdio_client_io(client, (unsigned char *)bytes, size, true));
}
static bool mcp_stdio_client_command(struct mcp_stdio_client *client) {
    unsigned char header[16], scalar[4];
    if (!mcp_stdio_client_io(client, header, sizeof(header), false) || mcp_stdio_le32(header) != CLIQ_MCP_STDIO_CHANNEL_MAGIC ||
        mcp_stdio_le32(header + 4) != 1) return false;
    uint32_t kind = mcp_stdio_le32(header + 8), size = mcp_stdio_le32(header + 12);
    if (kind == CLIQ_MCP_STDIO_CANCEL && !size) { client->stopping = true; return mcp_stdio_client_live(client); }
    if (kind == CLIQ_MCP_STDIO_PROTOCOL_DONE && !size && client->next_phase == client->header.phase_count && !client->write_pending) {
        client->protocol_done = true;
        return true;
    }
    if (kind == CLIQ_MCP_STDIO_CHUNK_ACK && size == sizeof(scalar) &&
        mcp_stdio_client_io(client, scalar, sizeof(scalar), false) && client->pending_stream && mcp_stdio_le32(scalar) == client->pending_stream) {
        client->pending_stream = 0;
        return true;
    }
    if (client->stopping) {
        /* An original host frame can already be partially in this stream
         * when SIGTERM revokes server writes. Consume that one bounded frame
         * without releasing it, so its prefix cannot corrupt drain/ACK IPC. */
        if (!((kind == CLIQ_MCP_STDIO_FRAME && size == sizeof(scalar)) ||
            (kind == CLIQ_MCP_STDIO_PING_REPLY && size && size <= client->header.maximum_response_bytes))) return false;
        unsigned char discarded[65536]; size_t left = size;
        while (left) {
            size_t count = left < sizeof(discarded) ? left : sizeof(discarded);
            if (!mcp_stdio_client_io(client, discarded, count, false)) return false;
            left -= count;
        }
        return true;
    }
    if (client->write_pending || client->written_pending || client->input < 0) return false;
    if (kind == CLIQ_MCP_STDIO_FRAME && size == sizeof(scalar) && mcp_stdio_client_io(client, scalar, sizeof(scalar), false)) {
        unsigned phase = mcp_stdio_le32(scalar);
        if (phase != client->next_phase || phase >= client->header.phase_count) return false;
        client->write_phase = phase; client->write_at = 0; client->write_ping = false;
        client->write_bytes = client->recipe + client->header.frames[phase].offset;
        client->write_size = (size_t)client->header.frames[phase].bytes;
        client->write_pending = true;
        return true;
    }
    if (kind != CLIQ_MCP_STDIO_PING_REPLY || !size || size > CLIQ_MCP_STDIO_MAX_MESSAGE || client->ping_count >= 8) return false;
    client->ping = malloc(size);
    if (!client->ping || !mcp_stdio_client_io(client, client->ping, size, false) || memchr(client->ping, '\n', size) || memchr(client->ping, '\r', size)) return false;
    client->ping_count++; client->write_at = 0; client->write_size = size;
    client->write_bytes = client->ping; client->write_ping = true; client->write_pending = true;
    return true;
}
static bool mcp_stdio_client_write(struct mcp_stdio_client *client) {
    unsigned char lf = '\n';
    const unsigned char *bytes = client->write_at < client->write_size ? client->write_bytes + client->write_at : &lf;
    size_t size = client->write_at < client->write_size ? client->write_size - client->write_at : 1;
    ssize_t n = write(client->input, bytes, size);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return true;
    if (n <= 0) { client->stopping = true; return mcp_stdio_client_live(client); }
    client->write_at += (size_t)n;
    if (client->write_at <= client->write_size) return true;
    client->write_pending = false; client->written_pending = true;
    if (!client->write_ping) client->next_phase++;
    if (client->ping) { free(client->ping); client->ping = NULL; }
    return true;
}
static bool mcp_stdio_client_output(struct mcp_stdio_client *client, unsigned stream) {
    unsigned char bytes[CLIQ_MCP_STDIO_CHUNK_BYTES];
    uint64_t left = client->header.maximum_output_bytes - client->output_bytes;
    size_t wanted = left < sizeof(bytes) ? (size_t)left + 1 : sizeof(bytes);
    ssize_t n = read(client->output[stream], bytes, wanted);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return true;
    if (n < 0) return false;
    if (!n) {
        client->output_eof[stream] = true;
        if (!source_close_fd(&client->output[stream])) return false;
        unsigned char scalar[4]; mcp_stdio_put32(scalar, stream + 1);
        if (!mcp_stdio_client_send(client, CLIQ_MCP_STDIO_OUTPUT_EOF, scalar, sizeof(scalar))) return false;
    } else {
        if ((uint64_t)n > left) return false;
        client->output_bytes += (uint64_t)n;
        if (!mcp_stdio_client_send(client, stream ? CLIQ_MCP_STDIO_STDERR : CLIQ_MCP_STDIO_STDOUT, bytes, (size_t)n)) return false;
    }
    client->pending_stream = stream + 1;
    return true;
}
static bool mcp_stdio_client_loop(struct mcp_stdio_client *client) {
    for (;;) {
        if (!mcp_stdio_client_live(client)) return false;
        int status; pid_t reaped;
        do {
            reaped = waitpid(-1, &status, WNOHANG);
            if (reaped == client->server) { client->server_reaped = true; client->stopping = true; }
        } while (reaped > 0 || (reaped < 0 && errno == EINTR));
        if (client->written_pending) {
            unsigned char result[8]; mcp_stdio_put32(result, client->write_ping ? UINT32_MAX : client->write_phase); mcp_stdio_put32(result + 4, 0);
            if (!mcp_stdio_client_send(client, CLIQ_MCP_STDIO_FRAME_WRITTEN, result, sizeof(result))) return false;
            client->written_pending = false;
        }
        if (client->server_reaped && reaped < 0 && errno == ECHILD && client->output_eof[0] && client->output_eof[1] && !client->pending_stream && !client->write_pending) {
            unsigned char result[4]; mcp_stdio_put32(result, client->protocol_done ? 1 : 0);
            return mcp_stdio_client_send(client, CLIQ_MCP_STDIO_CLIENT_JOINED, result, sizeof(result));
        }
        struct pollfd descriptors[4] = {
            {.fd = client->operation, .events = POLLIN},
            {.fd = client->write_pending && !client->stopping ? client->input : -1, .events = POLLOUT},
            {.fd = client->pending_stream ? -1 : client->output[0], .events = POLLIN},
            {.fd = client->pending_stream ? -1 : client->output[1], .events = POLLIN}
        };
        int available = poll(descriptors, 4, 1);
        if (available < 0 && errno == EINTR) continue;
        if (available < 0) return false;
        if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) && !mcp_stdio_client_command(client)) return false;
        if ((descriptors[1].revents & (POLLOUT | POLLHUP | POLLERR)) && !mcp_stdio_client_write(client)) return false;
        for (unsigned stream = 0; stream < 2 && !client->pending_stream; stream++)
            if ((descriptors[stream + 2].revents & (POLLIN | POLLHUP | POLLERR)) && !mcp_stdio_client_output(client, stream)) return false;
    }
}
static bool mcp_stdio_server_mount(const struct cliq_mcp_stdio_recipe_header *recipe) {
    int parent = open("/runtime", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int image = parent >= 0 ? openat(parent, "mcp-server", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) : -1;
    struct stat held, after, named;
    bool valid = image >= 0 && !fstat(image, &held) && S_ISREG(held.st_mode) && held.st_uid == geteuid() && held.st_gid == getegid() &&
        held.st_nlink == 1 && (held.st_mode & 07777) == 0555 && held.st_size > 0 && (uint64_t)held.st_size == recipe->server_bytes;
    struct sha256_context hash; sha256_init(&hash);
    unsigned char bytes[65536]; uint64_t at = 0;
    while (valid && at < recipe->server_bytes) {
        size_t wanted = recipe->server_bytes - at < sizeof(bytes) ? (size_t)(recipe->server_bytes - at) : sizeof(bytes);
        ssize_t n = pread(image, bytes, wanted, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { valid = false; break; }
        sha256_update(&hash, bytes, (size_t)n); at += (uint64_t)n;
    }
    unsigned char digest[32]; char text[65]; sha256_final(&hash, digest); source_hex(digest, text);
    void *mapping = valid ? mmap(NULL, (size_t)held.st_size, PROT_READ, MAP_PRIVATE, image, 0) : MAP_FAILED;
    valid = valid && !strcmp(text, recipe->server_digest) && mapping != MAP_FAILED && cliq_mcp_stdio_static_elf(mapping, (size_t)held.st_size);
    if (mapping != MAP_FAILED && munmap(mapping, (size_t)held.st_size)) valid = false;
    char source[64]; int length = snprintf(source, sizeof(source), "/proc/self/fd/%d", image);
    valid = valid && length > 0 && (size_t)length < sizeof(source) && !fstat(image, &after) && source_stat_same(&held, &after) &&
        !fstatat(parent, "mcp-server", &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&held, &named) &&
        !mount(source, CLIQ_MCP_STDIO_SERVER_PATH, NULL, MS_BIND, NULL) && !fstat(image, &after) && source_stat_same(&held, &after) &&
        !fstatat(parent, "mcp-server", &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&held, &named);
    if (!source_close_fd(&image)) valid = false;
    if (!source_close_fd(&parent)) valid = false;
    return valid;
}
static bool mcp_stdio_confinement(const struct cliq_mcp_stdio_recipe_header *recipe) {
    return mcp_stdio_server_mount(recipe) &&
        verifier_mount_attributes("/", AT_RECURSIVE, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID, 0) &&
        verifier_mount_attributes("/", 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0) &&
        verifier_mount_attributes("/scratch", 0, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0) &&
        verifier_mount_attributes("/proc", AT_RECURSIVE, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0) &&
        verifier_mount_attributes(CLIQ_MCP_STDIO_SERVER_PATH, 0, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC) &&
        verifier_mount_observed("/", true, false, false) && verifier_mount_observed("/scratch", false, false, false) &&
        verifier_mount_observed("/proc", true, false, false) && verifier_mount_observed("/dev", false, false, true) &&
        verifier_mount_observed(CLIQ_MCP_STDIO_SERVER_PATH, true, true, false) && verifier_drop_capabilities() && verifier_filter();
}
static int mcp_stdio_namespace(struct cliq_worker_packet request, int passed[2]) {
    struct mcp_stdio_client client = {.operation = -1, .input = -1, .output = {-1, -1}};
    struct stat recipe;
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    bool valid = getpid() == 1 && request.command == CLIQ_MCP_STDIO_CREATE_BLOCKED &&
        !fstat(passed[0], &recipe) && S_ISREG(recipe.st_mode) && recipe.st_size > 0 && (uint64_t)recipe.st_size <= CLIQ_MCP_STDIO_MAX_RECIPE &&
        (uint64_t)recipe.st_size == request.stdio_recipe_bytes && fcntl(passed[0], F_GET_SEALS) == seals;
    client.recipe_size = valid ? (size_t)recipe.st_size : 0;
    client.recipe = valid ? malloc(client.recipe_size) : NULL;
    valid = valid && client.recipe && cliq_mcp_admin_read_exact(passed[0], client.recipe, client.recipe_size, 0) &&
        cliq_mcp_stdio_recipe_valid(client.recipe, client.recipe_size, &client.header) && client.header.purpose == request.stdio_purpose &&
        !strcmp(client.header.server_digest, request.stdio_server_digest) && client.header.server_bytes == request.stdio_server_bytes;
    unsigned char hash[32]; char digest[65];
    if (valid) { cliq_mcp_admin_hash(client.recipe, client.recipe_size, hash); source_hex(hash, digest); valid = !strcmp(digest, request.stdio_recipe_digest); }
    if (!source_close_fd(&passed[0])) valid = false;
    struct timespec realtime;
    uint64_t monotonic = mcp_stdio_monotonic_ms();
    valid = valid && monotonic && !clock_gettime(CLOCK_REALTIME, &realtime);
    uint64_t now = valid ? (uint64_t)realtime.tv_sec * 1000 + (uint64_t)realtime.tv_nsec / 1000000 : 0;
    valid = valid && request.stdio_call_deadline_ms > now && request.stdio_call_deadline_ms - now <= INT_MAX;
    if (valid) client.deadline = monotonic + request.stdio_call_deadline_ms - now;
    client.operation = passed[1]; passed[1] = -1;
    int input[2] = {-1, -1}, output[2] = {-1, -1}, error[2] = {-1, -1}, barrier[2] = {-1, -1};
    struct sigaction cancel = {.sa_handler = mcp_stdio_cancel_signal}, ignore = {.sa_handler = SIG_IGN};
    valid = valid && !sigemptyset(&cancel.sa_mask) && !sigemptyset(&ignore.sa_mask) && !sigaction(SIGTERM, &cancel, NULL) &&
        !sigaction(SIGINT, &cancel, NULL) && !sigaction(SIGPIPE, &ignore, NULL) && !mkdir("/scratch/home", 0700) && !mkdir("/scratch/tmp", 0700) &&
        mcp_stdio_confinement(&client.header) && !pipe2(input, O_CLOEXEC) && !pipe2(output, O_CLOEXEC) && !pipe2(error, O_CLOEXEC) && !pipe2(barrier, O_CLOEXEC);
    if (valid) client.server = fork();
    if (valid && client.server == 0) {
        struct sigaction normal = {.sa_handler = SIG_DFL};
        if (sigemptyset(&normal.sa_mask) || sigaction(SIGTERM, &normal, NULL) || sigaction(SIGINT, &normal, NULL) || sigaction(SIGPIPE, &normal, NULL)) _exit(70);
        int block = fcntl(barrier[0], F_DUPFD_CLOEXEC, 10);
        if (block < 0 || dup2(input[0], 0) < 0 || dup2(output[1], 1) < 0 || dup2(error[1], 2) < 0 || dup2(block, 3) < 0 || !cliq_close_range(4, UINT_MAX)) _exit(70);
        char go; ssize_t n;
        do { n = read(3, &go, 1); } while (n < 0 && errno == EINTR);
        if (n != 1 || go != '1' || close(3) || chdir("/scratch")) _exit(70);
        char *arguments[CLIQ_MCP_STDIO_MAX_ARGS + 2]; arguments[0] = CLIQ_MCP_STDIO_SERVER_PATH;
        for (unsigned i = 0; i < client.header.argument_count; i++) arguments[i + 1] = (char *)client.recipe + sizeof(client.header) + client.header.arguments[i];
        arguments[client.header.argument_count + 1] = NULL;
        char *const environment[] = {"LANG=C", "LC_ALL=C", "HOME=/scratch/home", "TMPDIR=/scratch/tmp", "PATH=/runtime", NULL};
        execve(CLIQ_MCP_STDIO_SERVER_PATH, arguments, environment);
        _exit(70);
    }
    valid = valid && client.server > 0;
    if (!source_close_fd(&input[0]) || !source_close_fd(&output[1]) || !source_close_fd(&error[1]) || !source_close_fd(&barrier[0])) valid = false;
    client.input = input[1]; input[1] = -1; client.output[0] = output[0]; output[0] = -1; client.output[1] = error[0]; error[0] = -1;
    struct cliq_worker_packet ready = request; ready.command = CLIQ_WORKER_READY;
    struct stat namespace;
    valid = valid && !stat("/proc/self/ns/pid", &namespace) && cliq_process_token(client.server, ready.start_token) && cliq_process_token(1, ready.init_start_token);
    if (valid) { ready.pid = client.server; ready.namespace_init_pid = 1; ready.pid_namespace_inode = namespace.st_ino; valid = cliq_send(3, &ready, NULL, 0); }
    bool can_drain = valid;
    struct cliq_worker_packet release; size_t count = 0;
    while (valid && !mcp_stdio_cancelled) {
        struct timespec actual;
        if (clock_gettime(CLOCK_REALTIME, &actual) || (uint64_t)actual.tv_sec * 1000 + (uint64_t)actual.tv_nsec / 1000000 >= request.stdio_launch_deadline_ms) { valid = false; break; }
        struct pollfd control = {.fd = 3, .events = POLLIN}; int available = poll(&control, 1, 10);
        if (available < 0 && errno == EINTR) continue;
        if (available < 0 || (control.revents & (POLLHUP | POLLERR | POLLNVAL))) { valid = false; break; }
        if (available && (control.revents & POLLIN)) break;
    }
    valid = valid && !mcp_stdio_cancelled && cliq_receive_flags(3, &release, NULL, 0, &count, MSG_DONTWAIT) && !count && release.command == CLIQ_MCP_STDIO_RELEASE_EXEC && cliq_mcp_stdio_packet_same(&request, &release) &&
        write(barrier[1], "1", 1) == 1;
    if (!valid && can_drain) client.stopping = true;
    bool descriptors_retired = source_close_fd(&barrier[1]);
    if (!source_close_fd(&(int){3})) descriptors_retired = false;
    int descriptors[] = {client.operation, client.input, client.output[0], client.output[1]};
    for (size_t i = 0; can_drain && i < sizeof(descriptors) / sizeof(descriptors[0]); i++) {
        int flags = fcntl(descriptors[i], F_GETFL);
        can_drain = flags >= 0 && !fcntl(descriptors[i], F_SETFL, flags | O_NONBLOCK);
    }
    valid = can_drain && mcp_stdio_client_loop(&client) && descriptors_retired;
    if (client.server > 0) (void)kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) { errno = 0; }
    int *slots[] = {&client.operation, &client.input, &client.output[0], &client.output[1], &input[0], &input[1], &output[0], &output[1], &error[0], &error[1], &barrier[0], &barrier[1], &passed[0], &passed[1]};
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) if (!source_close_fd(slots[i])) valid = false;
    free(client.recipe); free(client.ping);
    return valid ? 0 : 70;
}
#endif
