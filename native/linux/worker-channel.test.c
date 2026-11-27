/* Real SCM_RIGHTS regression for the shared production receive helper. No
 * synthetic descriptor, kernel response, or weakened ancillary/frame limit. */
#define _GNU_SOURCE
#include "worker-common.h"
#include "verifier-setup.h"
#include <assert.h>
#include <dirent.h>

static size_t open_descriptors(void) {
    DIR *directory = opendir("/proc/self/fd");
    assert(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) count++;
    }
    assert(errno == 0);
    assert(closedir(directory) == 0);
    return count;
}

static void send_rights(int channel, int descriptor, size_t count, bool bad_packet, int length_adjustment) {
    struct cliq_worker_packet packet = cliq_packet(CLIQ_WORKER_READY);
    if (bad_packet) packet.magic = 0;
    unsigned char body[sizeof(packet) + 1];
    memcpy(body, &packet, sizeof(packet)); body[sizeof(packet)] = 0;
    assert(length_adjustment >= -1 && length_adjustment <= 1);
    struct iovec iov = { .iov_base = body, .iov_len = (size_t)((ssize_t)sizeof(packet) + length_adjustment) };
    char ancillary[CMSG_SPACE((CLIQ_WORKER_MAX_FDS + 1) * sizeof(int))];
    memset(ancillary, 0, sizeof(ancillary));
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (count) {
        assert(count <= CLIQ_WORKER_MAX_FDS + 1);
        message.msg_control = ancillary; message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(count * sizeof(int));
        int rights[CLIQ_WORKER_MAX_FDS + 1];
        for (size_t i = 0; i < count; i++) rights[i] = descriptor;
        memcpy(CMSG_DATA(header), rights, count * sizeof(int));
    }
    assert(sendmsg(channel, &message, MSG_NOSIGNAL) == (ssize_t)iov.iov_len);
}

static void receive_case(int channel[2], int descriptor, const char *name, size_t sent,
                         size_t capacity, bool bad_packet, int length_adjustment, bool accepted) {
    const size_t before = open_descriptors();
    send_rights(channel[0], descriptor, sent, bad_packet, length_adjustment);
    int guarded[CLIQ_WORKER_MAX_FDS + 2];
    for (size_t i = 0; i < sizeof(guarded) / sizeof(guarded[0]); i++) guarded[i] = -1234567;
    struct cliq_worker_packet packet; size_t count = SIZE_MAX;
    errno = 0;
    assert(cliq_receive(channel[1], &packet, guarded, capacity, &count) == accepted);
    const int receive_errno = errno;
    for (size_t i = capacity; i < sizeof(guarded) / sizeof(guarded[0]); i++) assert(guarded[i] == -1234567);
    if (accepted) {
        assert(count == sent);
        for (size_t i = 0; i < count; i++) {
            assert(guarded[i] != descriptor && (fcntl(guarded[i], F_GETFD) & FD_CLOEXEC) != 0);
            assert(close(guarded[i]) == 0);
        }
    } else {
        assert(count == 0 && receive_errno == EPROTO);
        for (size_t i = 0; i < capacity; i++) {
            if (guarded[i] == -1234567) continue;
            errno = 0; assert(fcntl(guarded[i], F_GETFD) == -1 && errno == EBADF);
        }
    }
    assert(open_descriptors() == before);
    printf("PASS %s\n", name);
}

int main(void) {
    int channel[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) == 0);
    const int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(descriptor >= 0);
    receive_case(channel, descriptor, "empty packet with zero capacity", 0, 0, false, false, true);
    receive_case(channel, descriptor, "legacy five-FD receiver remains supported", 5, 5, false, false, true);
    receive_case(channel, descriptor, "verifier protocol maximum remains supported", CLIQ_WORKER_MAX_FDS,
        CLIQ_WORKER_MAX_FDS, false, false, true);
    for (size_t i = 0; i < 32; i++) {
        receive_case(channel, descriptor, "excess right cannot overwrite legacy extent or leak", 6, 5, false, false, false);
        receive_case(channel, descriptor, "zero-capacity receiver retires unexpected rights", 1, 0, false, false, false);
        receive_case(channel, descriptor, "kernel-truncated ancillary rejects and retires all received rights",
            CLIQ_WORKER_MAX_FDS + 1, CLIQ_WORKER_MAX_FDS, false, false, false);
    }
    receive_case(channel, descriptor, "invalid packet retires copied rights", 3, 5, true, false, false);
    receive_case(channel, descriptor, "truncated payload retires copied rights", 3, 5, false, true, false);
    receive_case(channel, descriptor, "short payload retires copied rights", 3, 5, false, -1, false);
    struct cliq_worker_packet packet; size_t count = SIZE_MAX;
    int untouched = -1234567;
    const size_t before = open_descriptors();
    assert(!cliq_receive_flags(channel[1], &packet, &untouched, 1, &count, MSG_DONTWAIT));
    assert((errno == EAGAIN || errno == EWOULDBLOCK) && count == 0 && untouched == -1234567);
    receive_case(channel, descriptor, "a valid packet remains receivable after EAGAIN", 1, 1, false, 0, true);
    send_rights(channel[0], descriptor, 0, false, 0);
    assert(cliq_receive(channel[1], &packet, NULL, 0, &count) && count == 0);
    assert(!cliq_receive(channel[1], &packet, NULL, 1, &count) && errno == EINVAL && count == 0);
    assert(!cliq_receive(channel[1], &packet, &untouched, CLIQ_WORKER_MAX_FDS + 1, &count) &&
        errno == EINVAL && count == 0 && untouched == -1234567);
    assert(open_descriptors() == before);
    /* The same production SCM receiver accepts only the fixed, ordered setup
     * data. An unexpected right is still retired and refuses the whole frame. */
    uint32_t stage = 0;
    for (uint32_t next = CLIQ_VERIFIER_SETUP_ENTRY; next <= CLIQ_VERIFIER_SETUP_BEFORE_READY; next++) {
        struct cliq_worker_packet progress = cliq_verifier_setup_packet(2, next);
        assert(cliq_send(channel[0], &progress, NULL, 0));
        assert(cliq_receive(channel[1], &packet, NULL, 0, &count) && count == 0);
        assert(cliq_verifier_setup_accept(&packet, 2, &stage) && stage == next);
    }
    struct cliq_worker_packet progress = cliq_verifier_setup_packet(2, CLIQ_VERIFIER_SETUP_ENTRY);
    assert(cliq_send(channel[0], &progress, &descriptor, 1));
    assert(!cliq_receive(channel[1], &packet, NULL, 0, &count) && count == 0 && errno == EPROTO);
    assert(open_descriptors() == before);
    assert(cliq_send(channel[0], &progress, NULL, 0));
    assert(cliq_receive(channel[1], &packet, NULL, 0, &count) && count == 0);
    assert(!cliq_verifier_setup_accept(&packet, 2, &stage));
    progress = cliq_packet(CLIQ_WORKER_READY); progress.setup.stage = CLIQ_VERIFIER_SETUP_BEFORE_READY;
    assert(cliq_send(channel[0], &progress, NULL, 0));
    assert(!cliq_receive(channel[1], &packet, NULL, 0, &count) && count == 0 && errno == EPROTO);
    puts("PASS setup diagnostics do not accept duplicates or unexpected rights");
    assert(close(descriptor) == 0 && close(channel[0]) == 0 && close(channel[1]) == 0);
    puts("PASS nonblocking and invalid-capacity requests preserve descriptor ownership");
    return 0;
}
