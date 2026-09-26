#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A private, single-threaded UDS acceptor. The trusted Supervisor speaks the
 * fixed binary pipe protocol; no user request can supply a principal or fd.
 * The child owns all socket descriptors and dies when its parent pipe closes. */
#define MAX_CLIENTS 32
#define MAX_FRAME (8u * 1024u * 1024u)
#define HEADER_SIZE 13u
#define ENDPOINT "control-v1.sock"

enum { OUT_READY = 1, OUT_OPEN = 2, OUT_FRAME = 3, OUT_CLOSED = 4, OUT_RECHECKED = 5 };
enum { IN_RESPONSE = 6, IN_SHUTDOWN = 7, IN_CLOSE = 8, IN_RECHECK = 9 };

typedef struct {
    int fd;
    uint64_t id;
    struct stat identity;
    uid_t uid;
    gid_t gid;
    unsigned char *input;
    size_t input_size, input_capacity;
    unsigned char *output;
    size_t output_size, output_offset;
    int awaiting_response;
    int announced;
} client;

static int root_fd = -1, runtime_fd = -1, listener_fd = -1;
static struct stat root_identity, runtime_identity, endpoint_identity, listener_identity;
static char *root_path;
static client clients[MAX_CLIENTS];
static uint64_t next_client_id = 1;
static unsigned char *parent_input;
static size_t parent_input_size, parent_input_capacity;
static int owned_endpoint;

static int same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int private_directory(const struct stat *info) {
    return S_ISDIR(info->st_mode) && info->st_uid == geteuid() && (info->st_mode & 07777) == 0700;
}

static int expected_identity(const struct stat *info, const char *device, const char *file) {
    char observed_device[32], observed_file[32];
#ifdef __APPLE__
    unsigned long long dev = (uint32_t)info->st_dev;
#else
    unsigned long long dev = info->st_dev;
#endif
    snprintf(observed_device, sizeof(observed_device), "%llu", dev);
    snprintf(observed_file, sizeof(observed_file), "%llu", (unsigned long long)info->st_ino);
    return strcmp(device, observed_device) == 0 && strcmp(file, observed_file) == 0;
}

static int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int open_root(const char *path) {
    if (!path || path[0] != '/' || path[1] == '\0') { errno = EINVAL; return -1; }
    int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (!size || size > NAME_MAX || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) {
            close(current); errno = EINVAL; return -1;
        }
        char name[NAME_MAX + 1];
        memcpy(name, part, size); name[size] = '\0';
        int next = openat(current, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved = errno;
        close(current);
        if (next < 0) { errno = saved; return -1; }
        current = next;
        if (!end) break;
        part = end + 1;
        if (!*part) { close(current); errno = EINVAL; return -1; }
    }
    return current;
}

static int write_all(int fd, const unsigned char *bytes, size_t count) {
    size_t done = 0;
    while (done < count) {
        ssize_t written = write(fd, bytes + done, count - done);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        done += (size_t)written;
    }
    return 1;
}

static int send_event(uint8_t kind, uint64_t id, const void *payload, uint32_t count) {
    unsigned char header[HEADER_SIZE];
    header[0] = kind;
    for (unsigned index = 0; index < 8; index++) header[1 + index] = (uint8_t)(id >> (56u - 8u * index));
    for (unsigned index = 0; index < 4; index++) header[9 + index] = (uint8_t)(count >> (24u - 8u * index));
    return write_all(STDOUT_FILENO, header, sizeof(header)) &&
        (!count || write_all(STDOUT_FILENO, payload, count));
}

static int append_bytes(unsigned char **buffer, size_t *size, size_t *capacity,
                        const unsigned char *bytes, size_t count, size_t limit) {
    if (count > limit || *size > limit - count) return 0;
    if (*size + count > *capacity) {
        size_t next = *capacity ? *capacity : 4096;
        while (next < *size + count) {
            if (next > limit / 2) { next = limit; break; }
            next *= 2;
        }
        unsigned char *resized = realloc(*buffer, next);
        if (!resized) return 0;
        *buffer = resized; *capacity = next;
    }
    memcpy(*buffer + *size, bytes, count);
    *size += count;
    return 1;
}

static int socket_kind(int fd) {
    struct sockaddr_un address;
    socklen_t size = sizeof(address);
    int type = 0;
    socklen_t type_size = sizeof(type);
    return getsockname(fd, (struct sockaddr *)&address, &size) == 0 &&
        size >= sizeof(sa_family_t) && address.sun_family == AF_UNIX &&
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0 &&
        type_size == sizeof(type) && type == SOCK_STREAM;
}

static int peer_credentials(int fd, uid_t *uid, gid_t *gid) {
#ifdef __APPLE__
    return getpeereid(fd, uid, gid) == 0;
#else
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 || size != sizeof(peer)) return 0;
    *uid = peer.uid; *gid = peer.gid;
    return 1;
#endif
}

/* A pathname identity and a socket descriptor identity are independent. */
static int check_endpoint(void) {
    struct stat root, runtime, endpoint, listener, named;
    int reopened = open_root(root_path);
    if (reopened < 0) return 0;
    int root_named = fstat(reopened, &named) == 0 && same_inode(&named, &root_identity);
    close(reopened);
    return root_named && fstat(root_fd, &root) == 0 && private_directory(&root) && same_inode(&root, &root_identity) &&
        fstat(runtime_fd, &runtime) == 0 && private_directory(&runtime) && same_inode(&runtime, &runtime_identity) &&
        fstatat(root_fd, "runtime", &named, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&named, &runtime) &&
        fstatat(runtime_fd, ENDPOINT, &endpoint, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_inode(&endpoint, &endpoint_identity) && S_ISSOCK(endpoint.st_mode) &&
        endpoint.st_uid == root.st_uid && (endpoint.st_mode & 07777) == 0600 &&
        fstat(listener_fd, &listener) == 0 && S_ISSOCK(listener.st_mode) &&
        same_inode(&listener, &listener_identity) && socket_kind(listener_fd);
}

static int check_client(client *item) {
    struct stat observed;
    uid_t uid; gid_t gid;
    return item->fd >= 0 && check_endpoint() && fstat(item->fd, &observed) == 0 &&
        S_ISSOCK(observed.st_mode) && same_inode(&observed, &item->identity) &&
        socket_kind(item->fd) && peer_credentials(item->fd, &uid, &gid) &&
        uid == root_identity.st_uid && uid == item->uid && gid == item->gid;
}

static int connection_live(client *item) {
    struct pollfd current = { .fd = item->fd, .events = POLLIN };
    int ready = poll(&current, 1, 0);
    if (ready < 0 || (current.revents & (POLLHUP | POLLERR | POLLNVAL))) return 0;
    if (ready > 0 && (current.revents & POLLIN)) {
        unsigned char next;
        ssize_t size = recv(item->fd, &next, 1, MSG_PEEK | MSG_DONTWAIT);
        if (size == 0 || (size < 0 && errno != EAGAIN && errno != EINTR)) return 0;
    }
    return 1;
}

static void close_client(client *item) {
    if (item->fd >= 0) {
        close(item->fd);
        if (item->announced) (void)send_event(OUT_CLOSED, item->id, NULL, 0);
    }
    free(item->input); free(item->output);
    memset(item, 0, sizeof(*item));
    item->fd = -1;
}

static int send_open(client *item) {
    char json[1024];
#ifdef __APPLE__
    unsigned long long endpoint_dev = (uint32_t)endpoint_identity.st_dev;
    unsigned long long listener_dev = (uint32_t)listener_identity.st_dev;
    unsigned long long client_dev = (uint32_t)item->identity.st_dev;
    const char *api = "macos_getpeereid";
    const char *platform = "macos";
#else
    unsigned long long endpoint_dev = endpoint_identity.st_dev;
    unsigned long long listener_dev = listener_identity.st_dev;
    unsigned long long client_dev = item->identity.st_dev;
    const char *api = "linux_so_peercred";
    const char *platform = "linux";
#endif
    int size = snprintf(json, sizeof(json),
        "{\"platform\":\"%s\",\"endpoint\":{\"deviceId\":\"%llu\",\"fileId\":\"%llu\",\"ownerUid\":%u,\"mode\":%u},"
        "\"listenerSocket\":{\"deviceId\":\"%llu\",\"fileId\":\"%llu\"},"
        "\"acceptedSocket\":{\"deviceId\":\"%llu\",\"fileId\":\"%llu\"},"
        "\"credentialApi\":\"%s\",\"peerUid\":%u,\"peerGid\":%u}",
        platform, endpoint_dev, (unsigned long long)endpoint_identity.st_ino,
        endpoint_identity.st_uid, endpoint_identity.st_mode & 07777,
        listener_dev, (unsigned long long)listener_identity.st_ino,
        client_dev, (unsigned long long)item->identity.st_ino, api, item->uid, item->gid);
    return size > 0 && (size_t)size < sizeof(json) && send_event(OUT_OPEN, item->id, json, (uint32_t)size);
}

static int dispatch_complete_frame(client *item) {
    if (item->awaiting_response) return 1;
    unsigned char *end = memchr(item->input, '\n', item->input_size);
    if (!end) return item->input_size <= MAX_FRAME;
    size_t length = (size_t)(end - item->input);
    if (!length || length > MAX_FRAME || !check_client(item) ||
        !send_event(OUT_FRAME, item->id, item->input, (uint32_t)length)) return 0;
    size_t consumed = length + 1;
    memmove(item->input, item->input + consumed, item->input_size - consumed);
    item->input_size -= consumed;
    item->awaiting_response = 1;
    return 1;
}

static int parse_parent(void) {
    while (parent_input_size >= HEADER_SIZE) {
        uint8_t kind = parent_input[0];
        uint64_t id = 0;
        uint32_t length = 0;
        for (unsigned index = 0; index < 8; index++) id = (id << 8) | parent_input[1 + index];
        for (unsigned index = 0; index < 4; index++) length = (length << 8) | parent_input[9 + index];
        if (length > MAX_FRAME || parent_input_size < HEADER_SIZE + length) {
            if (length > MAX_FRAME) return 0;
            break;
        }
        if (kind == IN_SHUTDOWN && id == 0 && length == 0) return -1;
        client *item = NULL;
        for (size_t index = 0; index < MAX_CLIENTS; index++) {
            if (clients[index].fd >= 0 && clients[index].id == id) { item = &clients[index]; break; }
        }
        if (kind == IN_CLOSE && length == 0) {
            if (item) close_client(item);
        } else if (kind == IN_RECHECK && length == 0 && !item) {
            /* A disconnect may win the race against the Supervisor's recheck. */
        } else if (kind == IN_RECHECK && length == 0 && item && item->awaiting_response) {
            if (!check_client(item) || !connection_live(item)) close_client(item);
            else if (!send_event(OUT_RECHECKED, id, NULL, 0)) return 0;
        } else if (kind == IN_RESPONSE && !item) {
            /* The authenticated request may finish after client disconnect. */
        } else if (kind == IN_RESPONSE && item && item->awaiting_response &&
                 length > 0 && length <= MAX_FRAME && !item->output) {
            item->output = malloc((size_t)length + 1);
            if (!item->output) return 0;
            memcpy(item->output, parent_input + HEADER_SIZE, length);
            item->output[length] = '\n';
            item->output_size = (size_t)length + 1;
            item->output_offset = 0;
        } else {
            return 0;
        }
        size_t consumed = HEADER_SIZE + length;
        memmove(parent_input, parent_input + consumed, parent_input_size - consumed);
        parent_input_size -= consumed;
    }
    return 1;
}

static void cleanup(void) {
    for (size_t index = 0; index < MAX_CLIENTS; index++) if (clients[index].fd >= 0) close_client(&clients[index]);
    if (listener_fd >= 0) close(listener_fd);
    if (runtime_fd >= 0) {
        struct stat named;
        if (owned_endpoint && fstatat(runtime_fd, ENDPOINT, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_inode(&named, &endpoint_identity) && S_ISSOCK(named.st_mode)) {
            if (unlinkat(runtime_fd, ENDPOINT, 0) == 0) (void)fsync(runtime_fd);
        }
        close(runtime_fd);
    }
    if (root_fd >= 0) close(root_fd);
    free(parent_input);
}

int main(int argc, char **argv) {
    for (size_t index = 0; index < MAX_CLIENTS; index++) clients[index].fd = -1;
    (void)signal(SIGPIPE, SIG_IGN);
    if (argc != 6 || !set_cloexec(STDIN_FILENO) || !set_cloexec(STDOUT_FILENO)) goto fail;
    root_path = argv[1];
    root_fd = open_root(root_path);
    if (root_fd < 0 || fstat(root_fd, &root_identity) < 0 || !private_directory(&root_identity) ||
        !expected_identity(&root_identity, argv[2], argv[3])) goto fail;
    runtime_fd = openat(root_fd, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (runtime_fd < 0 || fstat(runtime_fd, &runtime_identity) < 0 || !private_directory(&runtime_identity) ||
        !expected_identity(&runtime_identity, argv[4], argv[5])) goto fail;
    if (fstatat(runtime_fd, ENDPOINT, &endpoint_identity, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto fail;
    if (fchdir(runtime_fd) < 0) goto fail;
    umask(0177); /* process-local; the parent Supervisor's umask is unchanged */
    listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener_fd < 0 || !set_cloexec(listener_fd)) goto fail;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, ENDPOINT, sizeof(ENDPOINT));
    if (strlen(root_path) + sizeof("/runtime/") - 1 + sizeof(ENDPOINT) > sizeof(address.sun_path)) {
        errno = ENAMETOOLONG; goto fail;
    }
    if (bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) < 0) goto fail;
    if (fstatat(runtime_fd, ENDPOINT, &endpoint_identity, AT_SYMLINK_NOFOLLOW) < 0) goto fail;
    owned_endpoint = 1;
    if (
        !S_ISSOCK(endpoint_identity.st_mode) || endpoint_identity.st_uid != geteuid() ||
        (endpoint_identity.st_mode & 07777) != 0600 ||
        fstat(listener_fd, &listener_identity) < 0 || !socket_kind(listener_fd) ||
        listen(listener_fd, MAX_CLIENTS) < 0 || !set_nonblock(listener_fd) ||
        !check_endpoint() || fsync(runtime_fd) < 0 ||
        !send_event(OUT_READY, 0, NULL, 0)) goto fail;

    for (;;) {
        struct pollfd fds[2 + MAX_CLIENTS];
        client *mapped[2 + MAX_CLIENTS];
        uint64_t mapped_id[2 + MAX_CLIENTS];
        nfds_t count = 0;
        fds[count] = (struct pollfd){ .fd = STDIN_FILENO, .events = POLLIN }; mapped[count++] = NULL;
        fds[count] = (struct pollfd){ .fd = listener_fd, .events = POLLIN }; mapped[count++] = NULL;
        for (size_t index = 0; index < MAX_CLIENTS; index++) {
            client *item = &clients[index];
            if (item->fd < 0) continue;
            fds[count] = (struct pollfd){ .fd = item->fd,
                .events = item->output ? POLLOUT : (item->awaiting_response ? 0 : POLLIN) };
            mapped_id[count] = item->id;
            mapped[count++] = item;
        }
        int polled = poll(fds, count, 1000);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0 || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) break;
        if (!check_endpoint()) break;
        if (fds[0].revents & POLLIN) {
            unsigned char chunk[8192];
            ssize_t n = read(STDIN_FILENO, chunk, sizeof(chunk));
            if (n <= 0 || !append_bytes(&parent_input, &parent_input_size, &parent_input_capacity,
                    chunk, (size_t)n, MAX_FRAME + HEADER_SIZE + sizeof(chunk)) || parse_parent() <= 0) break;
        }
        if (fds[1].revents & POLLIN) {
            if (!check_endpoint()) break;
            int accepted = accept(listener_fd, NULL, NULL);
            if (accepted < 0) { if (errno != EAGAIN && errno != EINTR) break; }
            else {
                client *slot = NULL;
                for (size_t index = 0; index < MAX_CLIENTS; index++) if (clients[index].fd < 0) { slot = &clients[index]; break; }
                if (!slot || !set_cloexec(accepted) || !set_nonblock(accepted)) close(accepted);
                else {
                    slot->fd = accepted;
                    slot->id = next_client_id++;
                    if (!next_client_id || fstat(accepted, &slot->identity) < 0 ||
                        !peer_credentials(accepted, &slot->uid, &slot->gid) ||
                        slot->uid != root_identity.st_uid || !check_client(slot) || !send_open(slot)) close_client(slot);
                    else slot->announced = 1;
                }
            }
        }
        for (nfds_t index = 2; index < count; index++) {
            client *item = mapped[index];
            // parse_parent() can close this slot before accept() reuses its fd.
            if (item->fd < 0 || item->fd != fds[index].fd || item->id != mapped_id[index]) continue;
            short ready = fds[index].revents;
            if (ready & (POLLHUP | POLLERR | POLLNVAL)) { close_client(item); continue; }
            if (ready & POLLOUT && item->output) {
                if (!check_client(item)) { close_client(item); continue; }
                ssize_t n = write(item->fd, item->output + item->output_offset,
                                  item->output_size - item->output_offset);
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                if (n <= 0) { close_client(item); continue; }
                item->output_offset += (size_t)n;
                if (item->output_offset == item->output_size) {
                    free(item->output); item->output = NULL;
                    item->output_size = item->output_offset = 0;
                    item->awaiting_response = 0;
                    if (!dispatch_complete_frame(item)) close_client(item);
                }
            }
            if (ready & POLLIN && !item->awaiting_response && !item->output) {
                if (!check_client(item)) { close_client(item); continue; }
                unsigned char chunk[8192];
                ssize_t n = read(item->fd, chunk, sizeof(chunk));
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                if (n <= 0 || !append_bytes(&item->input, &item->input_size, &item->input_capacity,
                        chunk, (size_t)n, MAX_FRAME + 1) || !dispatch_complete_frame(item)) close_client(item);
            }
        }
    }
    cleanup();
    return 0;
fail:
    fprintf(stderr, "Cliq control listener failed closed (errno=%d: %s)\n", errno, strerror(errno));
    cleanup();
    return 1;
}
