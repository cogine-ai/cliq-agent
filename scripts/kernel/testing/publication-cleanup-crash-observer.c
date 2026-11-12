/* Test-only observer. One actual inotify deletion may trigger exactly one
 * SIGKILL (default) or fixed retirement-stop SIGTERM of a preverified original
 * Supervisor pidfd. The latter must observe real death/join within two seconds
 * of the original signal start. Events and timestamps confer no proof
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
static int stamp(uint64_t *monotonic, uint64_t *realtime) {
    struct timespec m, r;
    if (clock_gettime(CLOCK_MONOTONIC, &m) || clock_gettime(CLOCK_REALTIME, &r) || m.tv_sec < 0 || r.tv_sec < 0 ||
        m.tv_nsec < 0 || m.tv_nsec >= 1000000000L || r.tv_nsec < 0 || r.tv_nsec >= 1000000000L ||
        (uint64_t)m.tv_sec > (UINT64_MAX - (uint64_t)m.tv_nsec) / UINT64_C(1000000000) ||
        (uint64_t)r.tv_sec > (UINT64_MAX - (uint64_t)r.tv_nsec) / UINT64_C(1000000000)) return 0;
    *monotonic = (uint64_t)m.tv_sec * UINT64_C(1000000000) + (uint64_t)m.tv_nsec;
    *realtime = (uint64_t)r.tv_sec * UINT64_C(1000000000) + (uint64_t)r.tv_nsec; return 1;
}
static int retirement_stop(int *process, int64_t watch_started) {
    uint64_t enter_m, enter_r, return_m, return_r, joined_m, joined_r;
    if (watch_started < 0 || (uint64_t)watch_started > UINT64_MAX / UINT64_C(1000000) - UINT64_C(90000) ||
        !stamp(&enter_m, &enter_r) || enter_m > UINT64_MAX - UINT64_C(2000000000)) return 0;
    uint64_t watch_deadline = ((uint64_t)watch_started + UINT64_C(90000)) * UINT64_C(1000000);
    const uint64_t deadline = enter_m + UINT64_C(2000000000);
    if (enter_m < (uint64_t)watch_started * UINT64_C(1000000) || deadline >= watch_deadline) return 0;
    /* One fixed signal only. Its original pre-syscall sample starts the stop
     * bound; neither a later native return nor an output consumer restarts it. */
    if (syscall(SYS_pidfd_send_signal, *process, SIGTERM, NULL, 0) || !stamp(&return_m, &return_r) ||
        return_m < enter_m || return_r < enter_r || return_m > deadline) return 0;
    for (;;) {
        uint64_t now_m, now_r;
        if (!stamp(&now_m, &now_r) || now_m < return_m || now_r < return_r || now_m > deadline) return 0;
        struct pollfd death = {*process, POLLIN, 0};
        int exited = poll(&death, 1, (int)((deadline - now_m) / UINT64_C(1000000)));
        if (exited < 0 && errno == EINTR) continue;
        if (exited < 0 || (death.revents & (POLLERR | POLLNVAL))) return 0;
        if (!exited) continue;
        if (!(death.revents & POLLIN)) return 0;
        break;
    }
    int original = *process; *process = -1; if (close(original)) return 0;
    if (!stamp(&joined_m, &joined_r) || joined_m < return_m || joined_r < return_r ||
        joined_m > deadline || joined_m >= watch_deadline) return 0;
    char output[512];
    int n = snprintf(output, sizeof(output),
        "publication_retirement_signal_v1 %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n"
        "publication_retirement_joined_v1 %" PRIu64 " %" PRIu64 "\n"
        "publication_retirement_original_supervisor_stopped_joined\n", enter_m, enter_r, return_m, return_r, joined_m, joined_r);
    return n > 0 && n < (int)sizeof(output) && frame(output);
}

/* Only the real disposable NSS fixture may use the root-side migration
 * observer. The actor is outside the same-user census. It opens no SQL,
 * records no credential bytes, and never signals an unobserved phase. */
static int rollback_probe_root(const char *location, uid_t uid, int *legacy, int *root) {
    static const char prefix[] = "/var/tmp/cliq-systemd-probe.", suffix[] = "/home/.cliq/kernel-v1";
    size_t length = strlen(location), head = sizeof(prefix) - 1, tail = sizeof(suffix) - 1;
    if (length <= head + tail || length > head + 64 + tail || memcmp(location, prefix, head) ||
        strcmp(location + length - tail, suffix)) return 0;
    const size_t nonce = length - head - tail;
    if (strspn(location + head, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != nonce) return 0;
    char fixture_name[96];
    const char *base = location + sizeof("/var/tmp/") - 1;
    size_t name_length = length - tail - (size_t)(base - location);
    if (name_length >= sizeof(fixture_name)) return 0;
    memcpy(fixture_name, base, name_length); fixture_name[name_length] = 0;
    int parent = open("/var/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), fixture = -1, home = -1;
    struct stat metadata, source, kernel;
    int valid = parent >= 0 &&
        (fixture = openat(parent, fixture_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) >= 0 &&
        !fstat(fixture, &metadata) && S_ISDIR(metadata.st_mode) && metadata.st_uid == 0 && metadata.st_gid == 0 &&
        (metadata.st_mode & 07777) == 0755 &&
        (home = openat(fixture, "home", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) >= 0 &&
        !fstat(home, &metadata) && private_directory(&metadata, uid) &&
        (*legacy = openat(home, ".cliq", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) >= 0 &&
        !fstat(*legacy, &source) && private_directory(&source, uid) &&
        (*root = openat(*legacy, "kernel-v1", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) >= 0 &&
        !fstat(*root, &kernel) && private_directory(&kernel, uid) && kernel.st_dev == source.st_dev;
    int descriptors[] = {home, fixture, parent};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (descriptors[index] >= 0 && close(descriptors[index])) valid = 0;
    return valid;
}
static int rollback_document(int parent, const char *leaf, uid_t uid, unsigned char *bytes, size_t capacity,
                             const char *required_phase, struct stat *observed, char digest_text[65]) {
    int fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat before, after, named;
    int valid = !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_uid == uid &&
        before.st_nlink == 1 && (before.st_mode & 07777) == 0600 && before.st_size > 0 && (uint64_t)before.st_size < capacity;
    size_t size = 0;
    while (valid && size < (size_t)before.st_size) {
        ssize_t received = read(fd, bytes + size, (size_t)before.st_size - size);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) { valid = 0; break; }
        size += (size_t)received;
    }
    if (valid) {
        unsigned char extra; ssize_t end;
        do { end = read(fd, &extra, 1); } while (end < 0 && errno == EINTR);
        valid = end == 0 && !fstat(fd, &after) && same(&before, &after) &&
            !fstatat(parent, leaf, &named, AT_SYMLINK_NOFOLLOW) && same(&before, &named);
    }
    if (close(fd) || !valid) return -1;
    static const char format[] = "\"format\":\"cliq-kernel-rollback-control-v1\"";
    if (required_phase && (!memmem(bytes, size, format, sizeof(format) - 1) ||
        !memmem(bytes, size, required_phase, strlen(required_phase)))) return 0;
    struct sha256_context hash; unsigned char value[32];
    sha256_init(&hash); sha256_update(&hash, bytes, size); sha256_final(&hash, value);
    for (size_t index = 0; index < sizeof(value); ++index) snprintf(digest_text + index * 2, 3, "%02x", value[index]);
    *observed = before;
    return 1;
}
static int rollback_displaced_name(const unsigned char *bytes, size_t size, const char *phase, const char *actual) {
    static const char field[] = "{\"archiveId\":\"";
    const size_t offset = sizeof(field) - 1;
    if (size < offset + 45 || memcmp(bytes, field, offset) || bytes[offset + 43] != '"' || bytes[offset + 44] != ',') return 0;
    char archive[44], expected[NAME_MAX + 1]; memcpy(archive, bytes + offset, 43); archive[43] = 0;
    if (!arena_id(archive)) return 0;
    const char *suffix = !strcmp(phase, "rollback_archive_ready") ? "archive-ready" : "restoring";
    int length = snprintf(expected, sizeof(expected), ".cliq-%s-rollback-%s.tmp", archive, suffix);
    return length > 0 && (size_t)length < sizeof(expected) && !strcmp(expected, actual);
}
static int rollback_cut(const char *location, pid_t pid, uint64_t ticks, uid_t uid,
                        const char *image_digest, uint64_t image_dev, uint64_t image_ino, uint64_t image_size,
                        const char *phase, const char *kernel_marker) {
    if ((strcmp(phase, "rollback_archive_ready") && strcmp(phase, "rollback_restoring")) || !digest(kernel_marker)) return 98;
    int legacy = -1, root = -1, migration = -1, notify = -1, process = -1, result = 98, armed = 0;
    unsigned char *bytes = malloc(1048577); char output[256] = {0};
    struct stat parent, marker_before, marker_after, control_before, control_after, legacy_marker, auth;
    char marker_hash[65], before_hash[65], after_hash[65], legacy_hash[65], watched[64], required[80], executable[64];
    int required_count = snprintf(required, sizeof(required), ",\"phase\":\"%s\",", phase);
    int executable_count = snprintf(executable, sizeof(executable), "/proc/%d/exe", pid);
    if (!bytes || required_count <= 0 || (size_t)required_count >= sizeof(required) ||
        executable_count <= 0 || (size_t)executable_count >= sizeof(executable) ||
        !start_token(pid, ticks, uid) || (process = (int)syscall(SYS_pidfd_open, pid, 0)) < 0 ||
        !image(pid, uid, image_digest, image_dev, image_ino, image_size) || !start_token(pid, ticks, uid) ||
        !rollback_probe_root(location, uid, &legacy, &root)) goto done;
    migration = openat(root, "migration", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (migration < 0 || fstat(migration, &parent) || !private_directory(&parent, uid) ||
        rollback_document(migration, "authority-v1.json", uid, bytes, 1048577, NULL, &marker_before, marker_hash) != 1 ||
        strcmp(marker_hash, kernel_marker)) goto done;
    notify = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (notify < 0 || snprintf(watched, sizeof(watched), "/proc/self/fd/%d", migration) >= (int)sizeof(watched)) goto done;
    int watch = inotify_add_watch(notify, watched, IN_DELETE | IN_MOVE_SELF | IN_DELETE_SELF | IN_ONLYDIR);
    int64_t started = milliseconds();
    if (watch < 0 || started < 0 || !frame("migration_rollback_cut_ready\n")) goto done;
    for (;;) {
        int64_t now = milliseconds();
        if (now < started || now - started >= 90000) goto done;
        struct pollfd fds[] = {{notify, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}, {process, POLLIN, 0}};
        int available = poll(fds, 3, (int)(90000 - (now - started)));
        if (available < 0 && errno == EINTR) continue;
        if (available <= 0 || fds[2].revents || (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) goto done;
        if (fds[1].revents & POLLIN) {
            char input[32]; ssize_t size = read(STDIN_FILENO, input, sizeof(input));
            if (armed || size != 9 || memcmp(input, "rollback\n", 9)) goto done;
            armed = 1;
        }
        if (!(fds[0].revents & POLLIN)) continue;
        _Alignas(struct inotify_event) unsigned char events[4096]; ssize_t count = read(notify, events, sizeof(events));
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) goto done;
        for (size_t offset = 0; offset < (size_t)count;) {
            if ((size_t)count - offset < sizeof(struct inotify_event)) goto done;
            const struct inotify_event *event = (const void *)(events + offset);
            if (event->len > (size_t)count - offset - sizeof(*event) ||
                (event->mask & (IN_Q_OVERFLOW | IN_MOVE_SELF | IN_DELETE_SELF | IN_IGNORED))) goto done;
            offset += sizeof(*event) + event->len;
            if (!armed || event->wd != watch || !(event->mask & IN_DELETE) ||
                !event->len || !memchr(event->name, 0, event->len)) continue;
            /* cr_replace_control unlinks the displaced old control only
             * after the new control's exact exchange and directory fsync. */
            if (rollback_document(migration, "control-v1.json", uid, bytes, 1048577, required, &control_before, before_hash) != 1 ||
                !rollback_displaced_name(bytes, (size_t)control_before.st_size, phase, event->name)) continue;
            struct stat original_image;
            if (rollback_document(migration, "authority-v1.json", uid, bytes, 1048577, NULL, &marker_after, marker_hash) != 1 ||
                !same(&marker_before, &marker_after) || strcmp(marker_hash, kernel_marker) || !start_token(pid, ticks, uid) ||
                stat(executable, &original_image) || !S_ISREG(original_image.st_mode) || original_image.st_uid != uid ||
                (uint64_t)original_image.st_dev != image_dev || (uint64_t)original_image.st_ino != image_ino ||
                (uint64_t)original_image.st_size != image_size) goto done;
            if (syscall(SYS_pidfd_send_signal, process, SIGKILL, NULL, 0)) goto done;
            const int64_t death_start = milliseconds();
            if (death_start < started || death_start - started >= 90000) goto done;
            for (;;) {
                int64_t sampled = milliseconds();
                if (sampled < death_start || sampled - death_start >= 2000 || sampled - started >= 90000) goto done;
                struct pollfd death = {process, POLLIN, 0};
                int exited = poll(&death, 1, (int)(2000 - (sampled - death_start)));
                if (exited < 0 && errno == EINTR) continue;
                if (exited <= 0 || !(death.revents & POLLIN) || (death.revents & (POLLERR | POLLNVAL))) goto done;
                break;
            }
            uint64_t death_monotonic, death_realtime;
            if (!stamp(&death_monotonic, &death_realtime) || death_monotonic / UINT64_C(1000000) < (uint64_t)death_start ||
                death_monotonic / UINT64_C(1000000) - (uint64_t)death_start > 2000) goto done;
            struct stat named;
            if (fstatat(root, "migration", &named, AT_SYMLINK_NOFOLLOW) || named.st_dev != parent.st_dev || named.st_ino != parent.st_ino ||
                rollback_document(migration, "control-v1.json", uid, bytes, 1048577, required, &control_after, after_hash) != 1 ||
                !same(&control_before, &control_after) || strcmp(before_hash, after_hash) ||
                rollback_document(migration, "authority-v1.json", uid, bytes, 1048577, NULL, &marker_after, marker_hash) != 1 ||
                !same(&marker_before, &marker_after) || strcmp(marker_hash, kernel_marker) ||
                rollback_document(legacy, ".cliq-generation-v1.json", uid, bytes, 1048577, NULL, &legacy_marker, legacy_hash) != 1) goto done;
            int auth_present = fstatat(legacy, "auth.json", &auth, AT_SYMLINK_NOFOLLOW) == 0;
            if (auth_present ? !S_ISREG(auth.st_mode) || auth.st_uid != uid || auth.st_nlink != 1 ||
                (auth.st_mode & 07777) != 0600 : errno != ENOENT) goto done;
            int length = snprintf(output, sizeof(output), "migration_rollback_cut_v1 %s %s %d %" PRIu64 " %" PRIu64 " %d %" PRIu64 "\n",
                phase, after_hash, auth_present, auth_present ? (uint64_t)auth.st_dev : 0,
                auth_present ? (uint64_t)auth.st_ino : 0, !strcmp(legacy_hash, kernel_marker), death_realtime / UINT64_C(1000000));
            if (length <= 0 || (size_t)length >= sizeof(output)) goto done;
            result = 0; goto done;
        }
    }
done:
    free(bytes);
    int descriptors[] = {process, notify, migration, root, legacy};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index)
        if (descriptors[index] >= 0 && close(descriptors[index])) result = 98;
    return result == 0 && frame(output) ? 0 : 98;
}

int main(int argc, char **argv) {
    uint64_t pid_value, ticks, uid_value, image_dev, image_ino, image_size;
    int stopping = argc == 10 && !strcmp(argv[9], "--retirement-stop");
    int rollback = argc == 12 && !strcmp(argv[9], "--rollback-cut");
    if ((argc != 9 && !stopping && !rollback) || argv[1][0] != '/' || !number(argv[2], &pid_value) || !pid_value || pid_value > INT_MAX ||
        !number(argv[3], &ticks) || !number(argv[4], &uid_value) || !uid_value || uid_value > UINT32_MAX ||
        getuid() != (rollback ? 0 : (uid_t)uid_value) || geteuid() != (rollback ? 0 : (uid_t)uid_value) || !digest(argv[5]) ||
        !number(argv[6], &image_dev) || !number(argv[7], &image_ino) || !number(argv[8], &image_size)) return 98;
    if (rollback) return rollback_cut(argv[1], (pid_t)pid_value, ticks, (uid_t)uid_value,
        argv[5], image_dev, image_ino, image_size, argv[10], argv[11]);
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
    if (watch < 0 || !frame(stopping ? "publication_retirement_watch_ready\n" : "publication_parent_watch_ready\n")) goto done;
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
            armed = 1; if (!frame(stopping ? "publication_retirement_original_birth_armed\n" : "publication_original_birth_armed\n")) goto done;
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
            if (stopping) {
                if (!retirement_stop(&process, started)) goto done;
                result = 0; break;
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
