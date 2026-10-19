/* Test-only observer. One actual inotify deletion may trigger exactly one
 * SIGKILL of a preverified original Supervisor pidfd. Events confer no proof
 * or permission. No pause, ptrace, DB/clock write, arbitrary signal or retry. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/inotify.h>
#include <sys/syscall.h>
#include "../../../native/linux/worker-sha256.h"

static int number(const char *text, uint64_t *out) {
    if (!*text || (*text == '0' && text[1])) return 0;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9' || value > (UINT64_MAX - (uint64_t)(*p - '0')) / 10) return 0;
        value = value * 10 + (uint64_t)(*p - '0');
    }
    *out = value; return 1;
}
static int digest(const char *text) {
    if (strlen(text) != 64) return 0;
    for (size_t i = 0; i < 64; i++) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return 0;
    return 1;
}
static int arena_id(const char *text) {
    if (strlen(text) != 43) return 0;
    for (size_t i = 0; i < 43; i++) if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'z') ||
        (text[i] >= 'A' && text[i] <= 'Z') || text[i] == '_' || text[i] == '-')) return 0;
    return 1;
}
static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static int private_directory(const struct stat *s, uid_t uid) { return S_ISDIR(s->st_mode) && s->st_uid == uid && (s->st_mode & 07777) == 0700; }
static int start_token(pid_t pid, uint64_t expected, uid_t uid) {
    char path[64], bytes[4097]; struct stat owner;
    if (snprintf(path, sizeof(path), "/proc/%d", pid) >= (int)sizeof(path) || stat(path, &owner) || owner.st_uid != uid ||
        snprintf(path, sizeof(path), "/proc/%d/stat", pid) >= (int)sizeof(path)) return 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return 0;
    ssize_t n = read(fd, bytes, sizeof(bytes) - 1); char extra; ssize_t end = read(fd, &extra, 1); int closed = close(fd);
    if (n <= 0 || n == (ssize_t)sizeof(bytes) - 1 || end != 0 || closed) return 0;
    bytes[n] = 0; char *p = strrchr(bytes, ')'); if (!p || p[1] != ' ' || p[2] == 'Z' || p[2] == 'X' || p[2] == 'x') return 0;
    p += 2; char *save = NULL;
    for (int field = 0; field <= 19; field++) {
        char *part = strtok_r(field ? NULL : p, " \n", &save); if (!part) return 0;
        if (field == 19) { uint64_t value; return number(part, &value) && value == expected; }
    }
    return 0;
}
static int image(pid_t pid, uid_t uid, const char *expected, uint64_t dev, uint64_t ino, uint64_t size) {
    char path[64], actual[65]; struct stat before, after, named;
    if (snprintf(path, sizeof(path), "/proc/%d/exe", pid) >= (int)sizeof(path)) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    int valid = 0;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != uid || before.st_nlink != 1 ||
        (uint64_t)before.st_dev != dev || (uint64_t)before.st_ino != ino || before.st_size <= 0 || (uint64_t)before.st_size != size ||
        size > UINT64_C(1073741824) || !(before.st_mode & 0111)) goto done;
    struct sha256_context hash; sha256_init(&hash); unsigned char buffer[65536], value[32]; uint64_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer)); if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (n > 0 && (uint64_t)n > size - total)) goto done;
        if (!n) break;
        sha256_update(&hash, buffer, (size_t)n); total += (uint64_t)n;
    }
    sha256_final(&hash, value);
    for (size_t i = 0; i < 32; i++) snprintf(actual + i * 2, 3, "%02x", value[i]);
    valid = total == size && !strcmp(actual, expected) && !fstat(fd, &after) && same(&before, &after) && !stat(path, &named) && same(&before, &named);
done:
    if (close(fd)) valid = 0;
    return valid;
}
static int64_t milliseconds(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1; return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000; }
static int frame(const char *text) { size_t n = strlen(text); return write(STDOUT_FILENO, text, n) == (ssize_t)n; }

int main(int argc, char **argv) {
    uint64_t pid_value, ticks, uid_value, image_dev, image_ino, image_size;
    if (argc != 9 || argv[1][0] != '/' || !number(argv[2], &pid_value) || !pid_value || pid_value > INT_MAX ||
        !number(argv[3], &ticks) || !number(argv[4], &uid_value) || !uid_value || uid_value > UINT32_MAX ||
        getuid() != (uid_t)uid_value || geteuid() != (uid_t)uid_value || !digest(argv[5]) ||
        !number(argv[6], &image_dev) || !number(argv[7], &image_ino) || !number(argv[8], &image_size)) return 98;
    int root = -1, runtime = -1, parent = -1, notify = -1, process = -1, arena = -1, result = 98;
    pid_t pid = (pid_t)pid_value; uid_t uid = (uid_t)uid_value; struct stat r, p, named, captured;
    if (!start_token(pid, ticks, uid)) goto done;
    process = (int)syscall(SYS_pidfd_open, pid, 0); if (process < 0 || !start_token(pid, ticks, uid) ||
        !image(pid, uid, argv[5], image_dev, image_ino, image_size) || !start_token(pid, ticks, uid)) goto done;
    root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || fstat(root, &r) || !private_directory(&r, uid)) goto done;
    runtime = openat(root, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (runtime < 0 || fstat(runtime, &named) || !private_directory(&named, uid) || named.st_dev != r.st_dev) goto done;
    parent = openat(runtime, "publications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || fstat(parent, &p) || !private_directory(&p, uid) || p.st_dev != r.st_dev) goto done;
    notify = inotify_init1(IN_CLOEXEC | IN_NONBLOCK); if (notify < 0) goto done;
    char watched[64]; if (snprintf(watched, sizeof(watched), "/proc/self/fd/%d", parent) >= (int)sizeof(watched)) goto done;
    int watch = inotify_add_watch(notify, watched, IN_CREATE | IN_DELETE | IN_ONLYDIR | IN_MOVE_SELF | IN_DELETE_SELF);
    if (watch < 0 || !frame("publication_parent_watch_ready\n")) goto done;
    int64_t started = milliseconds(); if (started < 0) goto done;
    char candidate[65] = {0}, input[256] = {0}; size_t used = 0; int armed = 0, deleted = 0, input_done = 0;
    for (;;) {
        int64_t now = milliseconds(); if (now < started || now - started >= 90000) goto done;
        struct pollfd fds[] = {{notify, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}, {process, POLLIN, 0}};
        int ready = poll(fds, 3, (int)(90000 - (now - started)));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || fds[2].revents || (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) || (fds[1].revents & (POLLERR | POLLNVAL))) goto done;
        if (fds[1].revents & (POLLIN | POLLHUP)) {
            if (input_done) goto done; /* EOF/extra bytes cancel; never another arm. */
            ssize_t n = read(STDIN_FILENO, input + used, sizeof(input) - 1 - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || used + (size_t)n >= sizeof(input) - 1) goto done;
            used += (size_t)n;
            if (memchr(input, '\n', used)) {
                input_done = 1;
                if (!used || input[used - 1] != '\n') goto done;
                input[used - 1] = 0;
            }
        }
        if (fds[0].revents & POLLIN) {
            _Alignas(struct inotify_event) unsigned char events[4096]; ssize_t n = read(notify, events, sizeof(events));
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (n <= 0) goto done;
            for (size_t at = 0; at < (size_t)n;) {
                if ((size_t)n - at < sizeof(struct inotify_event)) goto done;
                const struct inotify_event *e = (const struct inotify_event *)(events + at);
                size_t length = sizeof(*e) + e->len;
                if (length > (size_t)n - at || e->wd != watch || !e->len || !memchr(e->name, 0, e->len) ||
                    !(e->mask & IN_ISDIR) || (e->mask & ~(IN_CREATE | IN_DELETE | IN_ISDIR)) || !arena_id(e->name)) goto done;
                if (e->mask & IN_CREATE) {
                    if (arena >= 0 || *candidate) goto done;
                    arena = openat(parent, e->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    if (arena < 0 || fstat(arena, &captured) || !private_directory(&captured, uid) || captured.st_dev != p.st_dev ||
                        fstatat(parent, e->name, &named, AT_SYMLINK_NOFOLLOW) || !same(&captured, &named)) goto done;
                    memcpy(candidate, e->name, 44);
                }
                if (e->mask & IN_DELETE) { if (!*candidate || strcmp(candidate, e->name) || deleted) goto done; deleted = 1; }
                at += length;
            }
        }
        // Consume the already-queued real CREATE before matching a concurrent
        // coordinator arm; stdin scheduling must not turn that ordering into a
        // false identity match or a newly opened/deletion-recreated arena.
        if (input_done && !armed) {
            char name[65], a[21], b[21], c[21], d[21], extra, canonical[256]; uint64_t ad, ai, pd, pi;
            if (sscanf(input, "%64s %20s %20s %20s %20s%c", name, a, b, c, d, &extra) != 5 || !arena_id(name) ||
                !number(a, &ad) || !number(b, &ai) || !number(c, &pd) || !number(d, &pi) ||
                pd != (uint64_t)p.st_dev || pi != (uint64_t)p.st_ino || arena < 0 || strcmp(candidate, name) ||
                ad != (uint64_t)captured.st_dev || ai != (uint64_t)captured.st_ino ||
                snprintf(canonical, sizeof(canonical), "%s %s %s %s %s", name, a, b, c, d) != (int)used - 1 || strcmp(canonical, input)) goto done;
            armed = 1; if (!frame("publication_original_birth_armed\n")) goto done;
        }
        if (armed && deleted) {
            if (fstat(parent, &named) || named.st_dev != p.st_dev || named.st_ino != p.st_ino || !private_directory(&named, uid) ||
                fstat(arena, &named) || named.st_dev != captured.st_dev || named.st_ino != captured.st_ino || named.st_nlink != 0 ||
                fstatat(parent, candidate, &named, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT || !start_token(pid, ticks, uid)) goto done;
            // No arena/watch/directory FD survives the actual kill. These are
            // only the external actor's observations, never original native
            // publication resources or proof of their retirement.
            int *observations[] = {&arena, &notify, &parent, &runtime, &root};
            for (size_t i = 0; i < sizeof(observations) / sizeof(observations[0]); i++) {
                int fd = *observations[i]; *observations[i] = -1; if (close(fd)) goto done;
            }
            if (syscall(SYS_pidfd_send_signal, process, SIGKILL, NULL, 0)) goto done;
            for (;;) {
                now = milliseconds(); if (now < started || now - started >= 90000) goto done;
                struct pollfd death = {process, POLLIN, 0};
                int exited = poll(&death, 1, (int)(90000 - (now - started)));
                if (exited < 0 && errno == EINTR) continue;
                if (exited <= 0 || !(death.revents & POLLIN) || (death.revents & (POLLERR | POLLNVAL))) goto done;
                break;
            }
            int original = process; process = -1; if (close(original)) goto done;
            if (!frame("publication_original_supervisor_killed\n")) goto done;
            result = 0; break;
        }
    }
done:
    for (size_t i = 0; i < 6; i++) { int fd = (int[]){arena, process, notify, parent, runtime, root}[i]; if (fd >= 0 && close(fd)) result = 98; }
    return result;
}
#else
/* Host compilation is not a Linux inotify/pidfd qualification. */
int main(void) { return 98; }
#endif
