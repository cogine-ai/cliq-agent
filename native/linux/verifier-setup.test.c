/* Real POSIX polling and fixed data only, not Linux namespace qualification. */
#define _GNU_SOURCE
#include "verifier-setup.h"
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t cancelled, cancel_on_alarm;
static void alarm_observed(int number) { (void)number; interrupted++; if (cancel_on_alarm) cancelled = 1; }

static void progress_packets(void) {
    uint32_t stage = 0;
    for (uint32_t next = CLIQ_VERIFIER_SETUP_ENTRY; next <= CLIQ_VERIFIER_SETUP_BEFORE_READY; next++) {
        struct cliq_worker_packet packet = cliq_verifier_setup_packet(2, next);
        assert(cliq_verifier_setup_accept(&packet, 2, &stage) && stage == next);
        assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == next);
    }
    assert(stage == CLIQ_VERIFIER_SETUP_BEFORE_READY);
    struct cliq_worker_packet packet = cliq_verifier_setup_packet(2, CLIQ_VERIFIER_SETUP_ENTRY);
    stage = 0;
    packet.nonce[0] = 'x'; assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == 0);
    packet = cliq_verifier_setup_packet(2, CLIQ_VERIFIER_SETUP_NODE_CHECK);
    assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == 0);
    packet = cliq_verifier_setup_packet(3, CLIQ_VERIFIER_SETUP_ENTRY);
    assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == 0);
    packet = cliq_verifier_setup_packet(2, CLIQ_VERIFIER_SETUP_ENTRY);
    packet.setup.poll_errno = 1; assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == 0);
    packet = cliq_verifier_setup_packet(2, CLIQ_VERIFIER_SETUP_ENTRY);
    packet.command = CLIQ_WORKER_READY; assert(!cliq_verifier_setup_accept(&packet, 2, &stage) && stage == 0);
    assert(cliq_verifier_setup_empty(&packet.setup) == false);
    memset(&packet.setup, 0, sizeof(packet.setup)); assert(cliq_verifier_setup_empty(&packet.setup));
}

int main(void) {
    progress_packets();
    int channel[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
    struct cliq_verifier_setup_observation observation = {0};
    int64_t start = cliq_verifier_setup_now(); assert(start >= 0);
    assert(write(channel[0], "x", 1) == 1);
    assert(cliq_verifier_setup_readable(channel[1], start, start + 1000, &observation, NULL));
    assert(observation.poll_result == 1 && (observation.poll_revents & POLLIN) != 0 && observation.poll_errno == 0);
    char byte; assert(read(channel[1], &byte, 1) == 1 && close(channel[0]) == 0);
    start = cliq_verifier_setup_now();
    /* POSIX EOF can include POLLIN as well as HUP (Darwin/Linux differ).
     * Keep the real kernel flags; do not invent a timeout or hangup cause. */
    struct pollfd baseline = { .fd = channel[1], .events = POLLIN };
    assert(poll(&baseline, 1, 0) == 1);
    const bool available = cliq_verifier_setup_readable(channel[1], start, start + 1000, &observation, NULL);
    assert(available == ((baseline.revents & POLLIN) != 0));
    assert(observation.poll_result == 1 && observation.poll_revents == (uint16_t)baseline.revents && observation.poll_errno == 0);
    assert(close(channel[1]) == 0);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
    struct sigaction action = {0}, original;
    action.sa_handler = alarm_observed; assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGALRM, &action, &original) == 0);
    struct itimerval timer = { .it_interval = {0, 10000}, .it_value = {0, 10000} };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    start = cliq_verifier_setup_now();
    assert(!cliq_verifier_setup_readable(channel[1], start, start + 150, &observation, NULL));
    memset(&timer, 0, sizeof(timer)); assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    assert(sigaction(SIGALRM, &original, NULL) == 0 && interrupted > 0);
    assert((observation.poll_result == 0 && observation.poll_errno == 0) ||
        (observation.poll_result == -1 && observation.poll_errno == EINTR));
    assert(observation.poll_revents == 0);
    assert(observation.elapsed_ms >= 150 && observation.elapsed_ms < 2000);
    assert(sigaction(SIGALRM, &action, NULL) == 0); cancelled = 0; cancel_on_alarm = 1;
    timer.it_value.tv_usec = 10000; assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    start = cliq_verifier_setup_now();
    assert(!cliq_verifier_setup_readable(channel[1], start, start + 5000, &observation, &cancelled));
    memset(&timer, 0, sizeof(timer)); assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    assert(sigaction(SIGALRM, &original, NULL) == 0 && cancelled == 1);
    assert(observation.poll_result == -1 && observation.poll_errno == EINTR && observation.elapsed_ms < 2000);
    assert(cliq_verifier_setup_valid(&observation));
    assert(!cliq_verifier_setup_readable(channel[1], start, start + 5000, &observation, &cancelled));
    assert(observation.poll_result == -2 && observation.poll_revents == 0 && observation.poll_errno == 0);
    assert(close(channel[0]) == 0 && close(channel[1]) == 0);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
    /* Queued progress must use the same absolute budget. Do not require a
     * separately scheduled child to deliver before the test's deadline. */
    assert(write(channel[0], "xx", 2) == 2); start = cliq_verifier_setup_now();
    const int64_t deadline = start + 150;
    for (int index = 0; index < 2; index++) {
        assert(cliq_verifier_setup_readable(channel[1], start, deadline, &observation, NULL));
        assert(read(channel[1], &byte, 1) == 1);
    }
    assert(!cliq_verifier_setup_readable(channel[1], start, deadline, &observation, NULL));
    assert(observation.poll_result == 0 && observation.elapsed_ms >= 150 && observation.elapsed_ms < 2000);
    /* Expired budget wins even over already readable data: do not poll or
     * consume it, and do not restart the clock for another progress packet. */
    assert(write(channel[0], "x", 1) == 1);
    assert(!cliq_verifier_setup_readable(channel[1], start, deadline, &observation, NULL));
    assert(observation.poll_result == -2 && observation.poll_revents == 0 && observation.poll_errno == 0);
    assert(read(channel[1], &byte, 1) == 1 && byte == 'x');
    assert(close(channel[0]) == 0 && close(channel[1]) == 0);
    return 0;
}
