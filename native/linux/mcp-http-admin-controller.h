#ifndef CLIQ_MCP_HTTP_ADMIN_CONTROLLER_H
#define CLIQ_MCP_HTTP_ADMIN_CONTROLLER_H
#include "mcp-http-admin-protocol.h"
struct mcp_admin_controller_scope {
    bool            attempted, created, blocked, released, complete, failed, dead, acked, monitor_joined, monitor_success, stage_waiting;
    int             anchor, birth, config_fd, recipe_fd, helper, bwrap, script, files[CLIQ_VERIFIER_MAX_FILES], channel, operation,
                    stdout_fd, stderr_fd, cgroup;
    struct stat     anchor_identity, cgroup_identity;
    struct cliq_mcp_admin_config config;
    struct cliq_worker_packet identity;
    struct cliq_mcp_admin_progress origin;
    struct scope    process;
    int             construction[6];
    unsigned        next_phase;
    unsigned char   header[16], *incoming;
    size_t          header_size, incoming_size, incoming_at;
    uint32_t        incoming_kind;
};
static struct mcp_admin_controller_scope mcp_admin_scope;
static void
mcp_admin_note_reaped(pid_t pid, int status)
{
    if (mcp_admin_scope.attempted && !mcp_admin_scope.acked && !mcp_admin_scope.monitor_joined && pid == mcp_admin_scope.process.monitor) {
        mcp_admin_scope.monitor_joined = true;
        mcp_admin_scope.monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
}
static bool
sealed_file_matches(int fd, uint64_t size, const char *expected)
{
    struct stat     file;
    if (fstat(fd, &file) || !S_ISREG(file.st_mode) || file.st_size < 1 || (uint64_t) file.st_size != size || fcntl(fd, F_GET_SEALS) != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
        return false;
    struct sha256_context hash;
    sha256_init(&hash);
    unsigned char   bytes[65536];
    uint64_t        at = 0;
    while (at < size) {
        size_t          wanted = size - at < sizeof(bytes) ? (size_t) (size - at) : sizeof(bytes);
        ssize_t         n = pread(fd, bytes, wanted, (off_t) at);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        sha256_update(&hash, bytes, (size_t) n);
        at += (uint64_t) n;
    } unsigned char digest[32];
    char            text[65];
    sha256_final(&hash, digest);
    source_hex(digest, text);
    return !strcmp(text, expected);
}
static void
mcp_admin_controller_init(void)
{
    memset(&mcp_admin_scope, 0, sizeof(mcp_admin_scope));
    int            *fds[] = {&mcp_admin_scope.anchor, &mcp_admin_scope.birth, &mcp_admin_scope.config_fd, &mcp_admin_scope.recipe_fd, &mcp_admin_scope.helper, &mcp_admin_scope.bwrap, &mcp_admin_scope.script, &mcp_admin_scope.channel, &mcp_admin_scope.operation, &mcp_admin_scope.stdout_fd, &mcp_admin_scope.stderr_fd, &mcp_admin_scope.cgroup};
    for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++)
        *fds[i] = -1;
    for (size_t i = 0; i < CLIQ_VERIFIER_MAX_FILES; i++)
        mcp_admin_scope.files[i] = -1;
    for (size_t i = 0; i < 6; i++)
        mcp_admin_scope.construction[i] = -1;
}
static bool
mcp_admin_root_current(void)
{
    struct stat     root, named;
    return mcp_admin_scope.anchor >= 0 && fstat(mcp_admin_scope.anchor, &root) == 0 && source_stat_same(&root, &mcp_admin_scope.anchor_identity) && native_cgroup(mcp_admin_scope.anchor) &&
        (!mcp_admin_scope.created || (fstatat(mcp_admin_scope.anchor, mcp_admin_scope.identity.cgroup_name, &named, AT_SYMLINK_NOFOLLOW) == 0 && source_stat_same(&named, &mcp_admin_scope.cgroup_identity)));
}
static bool
mcp_admin_step(unsigned kind)
{
    struct cliq_mcp_admin_progress frame = mcp_admin_scope.origin;
    frame.packet = mcp_admin_scope.identity;
    return mcp_admin_root_current() && cliq_mcp_admin_append(mcp_admin_scope.birth, kind, &frame);
}
static bool
mcp_admin_reserve(struct cliq_worker_packet *request, int passed[CLIQ_WORKER_MAX_FDS], size_t count, struct cliq_worker_packet *response)
{
    if (mcp_admin_scope.attempted || count < 8 || request->command != CLIQ_MCP_ADMIN_RESERVE || request->scope != 0 || request->parent || request->generation_ref[0] || request->source_inspection_id[0] || request->preparation_input_intent_ref[0] ||
        !cliq_mcp_admin_digest(request->nonce) || !cliq_mcp_admin_digest(request->admin_target_ref) || !cliq_mcp_admin_digest(request->admin_target_digest) || !cliq_mcp_admin_digest(request->admin_core_ref) || !cliq_mcp_admin_digest(request->admin_core_digest) ||
        !cliq_mcp_admin_digest(request->plan_ref) || !cliq_mcp_admin_digest(request->admin_plan_digest) || !cliq_mcp_admin_digest(request->sandbox_launch_ref) || !cliq_mcp_admin_digest(request->sandbox_launch_digest))
        return false;
    mcp_admin_scope.attempted = true;
    struct cliq_mcp_admin_history history;
    struct stat     birth;
    if (!native_cgroup(passed[0]) || fstat(passed[0], &mcp_admin_scope.anchor_identity) || fstat(passed[1], &birth) || !S_ISREG(birth.st_mode) || birth.st_nlink != 1 || birth.st_uid != geteuid() || (birth.st_mode & 07777) != 0600 ||
        !cliq_mcp_admin_read_history(passed[1], &history, NULL, NULL) || history.count != 1 || history.first.kind != 1 || history.first.controller_pid != getpid() ||
        !cliq_mcp_admin_packet_same(request, &history.first.packet) || !mcp_admin_read_config(passed[2], &mcp_admin_scope.config) || count != 7 + mcp_admin_scope.config.file_count)
        return false;
    char            token[CLIQ_WORKER_TOKEN_BYTES];
    if (!cliq_process_token(getpid(), token) || strcmp(token, history.first.controller_start_token))
        return false;
    mcp_admin_scope.origin = history.first;
    mcp_admin_scope.identity = *request;
    int            *slots[] = {&mcp_admin_scope.anchor, &mcp_admin_scope.birth, &mcp_admin_scope.config_fd, &mcp_admin_scope.helper, &mcp_admin_scope.bwrap, &mcp_admin_scope.script, &mcp_admin_scope.recipe_fd};
    for (size_t i = 0; i < 7; i++) {
        *slots[i] = fcntl(passed[i], F_DUPFD_CLOEXEC, 4);
        if (*slots[i] < 0)
            return false;
    }
    struct stat     recipe;
    if (fstat(mcp_admin_scope.recipe_fd, &recipe) || !S_ISREG(recipe.st_mode) || recipe.st_size <= 0 || (uint64_t) recipe.st_size != mcp_admin_scope.config.recipe_bytes || fcntl(mcp_admin_scope.recipe_fd, F_GET_SEALS) != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
        return false;
    for (uint32_t i = 0; i < mcp_admin_scope.config.file_count; i++) {
        if (!sealed_file_matches(passed[7 + i], mcp_admin_scope.config.files[i].byte_count, mcp_admin_scope.config.files[i].digest))
            return false;
        mcp_admin_scope.files[i] = fcntl(passed[7 + i], F_DUPFD_CLOEXEC, 4);
        if (mcp_admin_scope.files[i] < 0)
            return false;
    }
    char            name[96];
    snprintf(name, sizeof(name), "cliq-mcp-admin-%s", request->nonce);
    if (strcmp(name, request->cgroup_name) || !mcp_admin_step(2) || mkdirat(mcp_admin_scope.anchor, name, 0700))
        return false;
    mcp_admin_scope.cgroup = openat(mcp_admin_scope.anchor, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (mcp_admin_scope.cgroup < 0 || !native_cgroup(mcp_admin_scope.cgroup) || fstat(mcp_admin_scope.cgroup, &mcp_admin_scope.cgroup_identity))
        return false;
    mcp_admin_scope.created = true;
    mcp_admin_scope.identity.cgroup_device = mcp_admin_scope.cgroup_identity.st_dev;
    mcp_admin_scope.identity.cgroup_inode = mcp_admin_scope.cgroup_identity.st_ino;
    if (!mcp_admin_step(3) || !cgroup_empty(mcp_admin_scope.cgroup) || !resources(mcp_admin_scope.cgroup, request))
        return false;
    *response = mcp_admin_scope.identity;
    response->command = CLIQ_MCP_ADMIN_RESERVE;
    return stamp_observation(response);
}
static void
mcp_admin_bubblewrap(void)
{
    int             keep[CLIQ_WORKER_MAX_FDS];
    size_t          count = 0;
    keep[count++] = mcp_admin_scope.helper;
    keep[count++] = mcp_admin_scope.bwrap;
    keep[count++] = mcp_admin_scope.script;
    for (uint32_t i = 0; i < mcp_admin_scope.config.file_count; i++)
        keep[count++] = mcp_admin_scope.files[i];
    if (!retain_descriptors(keep, count))
        _exit(70);
    int             init = independent_image_fd(mcp_admin_scope.helper, 4), bwrap = fcntl(mcp_admin_scope.bwrap, F_DUPFD_CLOEXEC, 4), script = independent_image_fd(mcp_admin_scope.script, 4);
    if (init < 0 || bwrap < 0 || script < 0)
        _exit(70);
    char            descriptors[CLIQ_VERIFIER_MAX_FILES + 2][24];
    snprintf(descriptors[0], 24, "%d", init);
    snprintf(descriptors[1], 24, "%d", script);
    count = 0;
    keep[count++] = init;
    keep[count++] = bwrap;
    keep[count++] = script;
    for (uint32_t i = 0; i < mcp_admin_scope.config.file_count; i++) {
        int             image = independent_image_fd(mcp_admin_scope.files[i], 4);
        if (image < 0)
            _exit(70);
        keep[count++] = image;
        snprintf(descriptors[i + 2], 24, "%d", image);
    } if (!retain_descriptors(keep, count))
        _exit(70);
    char           *arguments[256];
    size_t          at = 0;
#define MCP_ADMIN_ARG(value) do{if(at>=sizeof(arguments)/sizeof(*arguments)-1)_exit(70);arguments[at++]=(char *)(value);}while(0)
    MCP_ADMIN_ARG("bwrap");
    MCP_ADMIN_ARG("--unshare-user");
    MCP_ADMIN_ARG("--uid");
    MCP_ADMIN_ARG("0");
    MCP_ADMIN_ARG("--gid");
    MCP_ADMIN_ARG("0");
    MCP_ADMIN_ARG("--unshare-pid");
    MCP_ADMIN_ARG("--as-pid-1");
    MCP_ADMIN_ARG("--unshare-net");
    MCP_ADMIN_ARG("--unshare-ipc");
    MCP_ADMIN_ARG("--unshare-uts");
    MCP_ADMIN_ARG("--unshare-cgroup");
    MCP_ADMIN_ARG("--new-session");
    MCP_ADMIN_ARG("--die-with-parent");
    MCP_ADMIN_ARG("--cap-drop");
    MCP_ADMIN_ARG("ALL");
    MCP_ADMIN_ARG("--cap-add");
    MCP_ADMIN_ARG("CAP_SYS_ADMIN");
    MCP_ADMIN_ARG("--cap-add");
    MCP_ADMIN_ARG("CAP_SETPCAP");
    MCP_ADMIN_ARG("--clearenv");
    MCP_ADMIN_ARG("--size");
    MCP_ADMIN_ARG("535822336");
    MCP_ADMIN_ARG("--tmpfs");
    MCP_ADMIN_ARG("/");
    MCP_ADMIN_ARG("--dir");
    MCP_ADMIN_ARG("/runtime");
    MCP_ADMIN_ARG("--perms");
    MCP_ADMIN_ARG("0555");
    MCP_ADMIN_ARG("--ro-bind-data");
    MCP_ADMIN_ARG(descriptors[0]);
    MCP_ADMIN_ARG("/runtime/cliq-linux-worker-init");
    MCP_ADMIN_ARG("--perms");
    MCP_ADMIN_ARG("0444");
    MCP_ADMIN_ARG("--file");
    MCP_ADMIN_ARG(descriptors[1]);
    MCP_ADMIN_ARG(CLIQ_MCP_ADMIN_SCRIPT_PATH);
    const char     *directories[] = {"/usr", "/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/lib", "/lib/x86_64-linux-gnu", "/lib64"};
    for (size_t i = 0; i < sizeof(directories) / sizeof(*directories); i++) {
        MCP_ADMIN_ARG("--dir");
        MCP_ADMIN_ARG(directories[i]);
    }
    for (uint32_t i = 0; i < mcp_admin_scope.config.file_count; i++) {
        MCP_ADMIN_ARG("--perms");
        MCP_ADMIN_ARG("0555");
        MCP_ADMIN_ARG(!strcmp(mcp_admin_scope.config.files[i].path, "/usr/bin/node") ? "--file" : "--ro-bind-data");
        MCP_ADMIN_ARG(descriptors[i + 2]);
        MCP_ADMIN_ARG(mcp_admin_scope.config.files[i].path);
    }
    MCP_ADMIN_ARG("--proc");
    MCP_ADMIN_ARG("/proc");
    MCP_ADMIN_ARG("--dev");
    MCP_ADMIN_ARG("/dev");
    MCP_ADMIN_ARG("--size");
    MCP_ADMIN_ARG("1048576");
    MCP_ADMIN_ARG("--tmpfs");
    MCP_ADMIN_ARG("/scratch");
    MCP_ADMIN_ARG("--chdir");
    MCP_ADMIN_ARG("/scratch");
    MCP_ADMIN_ARG("--");
    MCP_ADMIN_ARG("/runtime/cliq-linux-worker-init");
    arguments[at] = NULL;
#undef MCP_ADMIN_ARG
    char           *const environment[] = {"LANG=C", "LC_ALL=C", NULL};
    fexecve(bwrap, arguments, environment);
    _exit(70);
}
static bool
mcp_admin_create_blocked(struct cliq_worker_packet *request, struct cliq_worker_packet *response)
{
    if (!mcp_admin_scope.created || mcp_admin_scope.blocked || mcp_admin_scope.failed || !cliq_mcp_admin_packet_same(request, &mcp_admin_scope.identity) || !mcp_admin_root_current() || !cgroup_empty(mcp_admin_scope.cgroup))
        return false;
    int            *control = mcp_admin_scope.construction, *operation = mcp_admin_scope.construction + 2, *barrier = mcp_admin_scope.construction + 4;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control))
        return false;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, operation))
        return false;
    if (pipe2(barrier, O_CLOEXEC))
        return false;
    mcp_admin_scope.stdout_fd = memfd_create("cliq-mcp-admin-stdout", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    mcp_admin_scope.stderr_fd = memfd_create("cliq-mcp-admin-stderr", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mcp_admin_scope.stdout_fd < 0 || mcp_admin_scope.stderr_fd < 0 || ftruncate(mcp_admin_scope.stdout_fd, 65536) || ftruncate(mcp_admin_scope.stderr_fd, 65536) ||
        fcntl(mcp_admin_scope.stdout_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL) || fcntl(mcp_admin_scope.stderr_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SEAL))
        return false;
    struct scope   *process = &mcp_admin_scope.process;
    if (!mcp_admin_step(4))
        return false;
    process->monitor = fork();
    if (process->monitor < 0)
        return false;
    if (!process->monitor) {
        close(control[0]);
        close(operation[0]);
        close(operation[1]);
        close(barrier[1]);
        char            go;
        if (read(barrier[0], &go, 1) != 1 || go != '1' || dup2(control[1], 3) < 0 || dup2(mcp_admin_scope.stdout_fd, 1) < 0 || dup2(mcp_admin_scope.stderr_fd, 2) < 0 || !configure_limits(request))
            _exit(70);
        mcp_admin_bubblewrap();
    }
    if (!source_close_fd(&control[1]) || !source_close_fd(&barrier[0]))
        return false;
    mcp_admin_scope.channel = control[0];
    control[0] = -1;
    mcp_admin_scope.operation = operation[0];
    operation[0] = -1;
    process->cgroup = process->process_group = mcp_admin_scope.cgroup;
    process->channel = mcp_admin_scope.channel;
    if (!cliq_process_token(process->monitor, process->monitor_start_token))
        return false;
    mcp_admin_scope.identity.monitor_pid = process->monitor;
    memcpy(mcp_admin_scope.identity.monitor_start_token, process->monitor_start_token, sizeof(process->monitor_start_token));
    if (!mcp_admin_step(4))
        return false;
    char            pid[32];
    snprintf(pid, sizeof(pid), "%ld", (long)process->monitor);
    bool            valid = write_control(mcp_admin_scope.cgroup, "cgroup.procs", pid) && write(barrier[1], "1", 1) == 1;
    if (!source_close_fd(&barrier[1]))
        valid = false;
    int             inputs[] = {mcp_admin_scope.config_fd, mcp_admin_scope.recipe_fd, operation[1]};
    struct cliq_worker_packet initial = mcp_admin_scope.identity;
    initial.command = CLIQ_MCP_ADMIN_CREATE_BLOCKED;
    size_t          count;
    struct cliq_worker_packet ready;
    valid = valid && cliq_send(mcp_admin_scope.channel, &initial, inputs, 3) && readable(mcp_admin_scope.channel, 5000) && cliq_receive(mcp_admin_scope.channel, &ready, NULL, 0, &count) && !count && ready.command == CLIQ_WORKER_READY && cliq_mcp_admin_packet_same(&initial, &ready) && inspect_processes(process, &ready);
    if (!source_close_fd(&operation[1]))
        valid = false;
    if (!valid)
        return false;
    /* inspect_processes matched the original proc identities. Validate their
     * complete canonical u64 suffixes before giving snprintf a finite width;
     * the precision must never silently shorten an unchecked token. */
    if (!cliq_source_process_token_valid(ready.init_start_token) || !cliq_source_process_token_valid(process->monitor_start_token))
        return false;
    mcp_admin_scope.identity.pid = process->worker;
    mcp_admin_scope.identity.namespace_init_pid = process->init;
    mcp_admin_scope.identity.pid_namespace_inode = ready.pid_namespace_inode;
    mcp_admin_scope.identity.populated = 1;
    memcpy(mcp_admin_scope.identity.start_token, ready.start_token, sizeof(ready.start_token));
    memcpy(mcp_admin_scope.identity.init_native_start_token, ready.init_start_token, sizeof(ready.init_start_token));
    int             token_length = snprintf(mcp_admin_scope.identity.init_start_token, sizeof(mcp_admin_scope.identity.init_start_token),
        "linux-namespace-init:%ld:%.20s:monitor:%ld:%.20s", (long)process->init,
        ready.init_start_token + strlen("linux-proc-start-ticks:"), (long)process->monitor,
        process->monitor_start_token + strlen("linux-proc-start-ticks:"));
    if (token_length <= 0 || (size_t)token_length >= sizeof(mcp_admin_scope.identity.init_start_token))
        return false;
    process->identity = mcp_admin_scope.identity;
    process->created = true;
    mcp_admin_scope.blocked = true;
    if (!mcp_admin_step(5))
        return false;
    int             flags = fcntl(mcp_admin_scope.operation, F_GETFL);
    if (flags < 0 || fcntl(mcp_admin_scope.operation, F_SETFL, flags | O_NONBLOCK))
        return false;
    *response = mcp_admin_scope.identity;
    response->command = CLIQ_MCP_ADMIN_CREATE_BLOCKED;
    return stamp_observation(response);
}
static bool
mcp_admin_write_bounded(int fd, const unsigned char *bytes, size_t size)
{
    int64_t         start = milliseconds();
    while (size) {
        ssize_t         n = write(fd, bytes, size);
        if (n > 0) {
            bytes += (size_t) n;
            size -= (size_t) n;
            continue;
        } if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd   wait = {fd, POLLOUT, 0};
            if (milliseconds() - start >= 2000 || poll(&wait, 1, 10) < 0)
                return false;
            continue;
        } return false;
    } return true;
}
static bool
mcp_admin_deliver_frame(uint32_t kind, const unsigned char *bytes, size_t size)
{
    unsigned char   header[16];
    uint32_t        fields[] = {CLIQ_MCP_ADMIN_CHANNEL_MAGIC, 1, kind, (uint32_t) size};
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 4; j++)
            header[i * 4 + j] = (unsigned char)(fields[i] >> (8 * j));
    return size && size <= CLIQ_MCP_ADMIN_MAX_CONFIG && mcp_admin_write_bounded(mcp_admin_scope.operation, header, 16) && mcp_admin_write_bounded(mcp_admin_scope.operation, bytes, size);
}
static bool
mcp_admin_pump(void)
{
    if (!mcp_admin_scope.released || mcp_admin_scope.failed || mcp_admin_scope.complete || mcp_admin_scope.incoming)
        return true;
    while (mcp_admin_scope.header_size < 16) {
        ssize_t         n = read(mcp_admin_scope.operation, mcp_admin_scope.header + mcp_admin_scope.header_size, 16 - mcp_admin_scope.header_size);
        if (n > 0) {
            mcp_admin_scope.header_size += (size_t) n;
            continue;
        } if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return true;
        mcp_admin_scope.failed = true;
        return true;
    }
    uint32_t        fields[4] = {0};
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 4; j++)
            fields[i] |= (uint32_t) mcp_admin_scope.header[i * 4 + j] << (8 * j);
    if (fields[0] != CLIQ_MCP_ADMIN_CHANNEL_MAGIC || fields[1] != 1 || (fields[2] != CLIQ_MCP_STAGE && fields[2] != CLIQ_MCP_COMPLETE && fields[2] != CLIQ_MCP_REFUSED) || !fields[3] || fields[3] > CLIQ_MCP_ADMIN_MAX_MESSAGE) {
        mcp_admin_scope.failed = true;
        return true;
    }
    mcp_admin_scope.incoming = malloc(fields[3]);
    if (!mcp_admin_scope.incoming)
        return false;
    mcp_admin_scope.incoming_size = fields[3];
    mcp_admin_scope.incoming_kind = fields[2];
    mcp_admin_scope.incoming_at = 0;
    return true;
}
static bool
mcp_admin_fill_incoming(void)
{
    if (!mcp_admin_pump())
        return false;
    if (!mcp_admin_scope.incoming)
        return true;
    while (mcp_admin_scope.incoming_at < mcp_admin_scope.incoming_size) {
        ssize_t         n = read(mcp_admin_scope.operation, mcp_admin_scope.incoming + mcp_admin_scope.incoming_at, mcp_admin_scope.incoming_size - mcp_admin_scope.incoming_at);
        if (n > 0) {
            mcp_admin_scope.incoming_at += (size_t) n;
            continue;
        } if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return true;
        mcp_admin_scope.failed = true;
        return true;
    }
    if (mcp_admin_scope.incoming_kind == CLIQ_MCP_REFUSED)
        mcp_admin_scope.failed = true;
    else if (mcp_admin_scope.incoming_kind == CLIQ_MCP_COMPLETE) {
        char            expected[128];
        int             bytes = snprintf(expected, sizeof(expected), "{\"complete\":true,\"nonce\":\"%s\"}", mcp_admin_scope.identity.nonce);
        if (mcp_admin_scope.next_phase != 3 || mcp_admin_scope.stage_waiting || mcp_admin_scope.incoming_size != (size_t) bytes || memcmp(expected, mcp_admin_scope.incoming, (size_t) bytes))
            mcp_admin_scope.failed = true;
        else {
            mcp_admin_scope.complete = true;
            mcp_admin_scope.identity.admin_protocol_complete = 1;
            if (!mcp_admin_step(7))
                return false;
        } free(mcp_admin_scope.incoming);
        mcp_admin_scope.incoming = NULL;
    }
    return true;
}
static bool
mcp_admin_stop(struct cliq_worker_packet *response)
{
    if (!mcp_admin_scope.attempted || !mcp_admin_root_current())
        return false;
    struct scope   *process = &mcp_admin_scope.process;
    if (!mcp_admin_scope.dead) {
        for (size_t i = 0; i < 6; i++)
            if (!source_close_fd(&mcp_admin_scope.construction[i]))
                return false;
        struct tracked_set tracked = {0};
        if (mcp_admin_scope.created && !collect_processes(mcp_admin_scope.cgroup, &tracked, 0))
            return false;
        if (process->monitor > 0 && !track_process(&tracked, process->monitor, process->monitor_start_token))
            return false;
        if (mcp_admin_scope.blocked && (!track_process(&tracked, process->init, mcp_admin_scope.identity.init_native_start_token) || !track_process(&tracked, process->worker, mcp_admin_scope.identity.start_token)))
            return false;
        if (mcp_admin_scope.created && !write_control(mcp_admin_scope.cgroup, "cgroup.kill", "1"))
            return false;
        if (process->monitor > 0 && !mcp_admin_scope.monitor_joined && !original_process_absent(process->monitor, process->monitor_start_token)) {
            char            token[CLIQ_WORKER_TOKEN_BYTES];
            if (!cliq_process_token(process->monitor, token) || strcmp(token, process->monitor_start_token) || (kill(process->monitor, SIGKILL) && errno != ESRCH))
                return false;
        }
        if (!source_close_fd(&mcp_admin_scope.channel) || !source_close_fd(&mcp_admin_scope.operation))
            return false;
        process->channel = -1;
        int64_t         start = milliseconds();
        for (;;) {
            int             status;
            pid_t           done;
            while ((done = waitpid(-1, &status, WNOHANG)) > 0)
                if (done == process->monitor) {
                    mcp_admin_scope.monitor_joined = true;
                    mcp_admin_scope.monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                }
            bool            dead = !mcp_admin_scope.created || (mcp_admin_scope.blocked ? held_scope_dead(process) : cgroup_empty(mcp_admin_scope.cgroup));
            if (dead && tracked_absent(&tracked) && (process->monitor <= 0 || mcp_admin_scope.monitor_joined)) {
                mcp_admin_scope.dead = true;
                break;
            } if (milliseconds() - start >= 2000)
                return false;
            struct timespec pause = {0, 10000000};
            nanosleep(&pause, NULL);
        }
        mcp_admin_scope.identity.populated = 0;
        mcp_admin_scope.identity.remaining_descendants = 0;
        mcp_admin_scope.identity.init_reaped = mcp_admin_scope.blocked ? 1 : 0;
        if (!mcp_admin_step(8))
            return false;
    }
    *response = mcp_admin_scope.identity;
    response->command = CLIQ_MCP_ADMIN_STOP;
    return stamp_observation(response);
}
static bool
mcp_admin_natural_join(struct cliq_worker_packet *response)
{
    if (!mcp_admin_fill_incoming())
        return false;
    if (mcp_admin_scope.failed)
        return false;
    if (!mcp_admin_scope.complete) {
        *response = mcp_admin_scope.identity;
        response->command = CLIQ_MCP_ADMIN_POLL;
        return stamp_observation(response);
    }
    struct scope   *process = &mcp_admin_scope.process;
    if (!mcp_admin_scope.monitor_joined) {
        int             status;
        pid_t           done = waitpid(process->monitor, &status, WNOHANG);
        if (!done) {
            *response = mcp_admin_scope.identity;
            response->command = CLIQ_MCP_ADMIN_POLL;
            return stamp_observation(response);
        } if (done != process->monitor)
            return false;
        mcp_admin_scope.monitor_joined = true;
        mcp_admin_scope.monitor_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (!mcp_admin_scope.monitor_success || !held_scope_dead(process))
        return false;
    if (!mcp_admin_scope.dead) {
        mcp_admin_scope.dead = true;
        mcp_admin_scope.identity.populated = 0;
        mcp_admin_scope.identity.remaining_descendants = 0;
        mcp_admin_scope.identity.init_reaped = 1;
        if (!source_close_fd(&mcp_admin_scope.channel) || !source_close_fd(&mcp_admin_scope.operation) || !mcp_admin_step(8))
            return false;
    }
    *response = mcp_admin_scope.identity;
    response->command = CLIQ_MCP_ADMIN_POLL;
    return stamp_observation(response);
}
static bool
mcp_admin_ack(struct cliq_worker_packet *response)
{
    if (!mcp_admin_scope.dead)
        return false;
    if (!mcp_admin_scope.acked) {
        int            *slots[] = {&mcp_admin_scope.stdout_fd, &mcp_admin_scope.stderr_fd, &mcp_admin_scope.config_fd, &mcp_admin_scope.recipe_fd, &mcp_admin_scope.helper, &mcp_admin_scope.bwrap, &mcp_admin_scope.script};
        for (size_t i = 0; i < sizeof(slots) / sizeof(*slots); i++)
            if (!source_close_fd(slots[i]))
                return false;
        for (size_t i = 0; i < CLIQ_VERIFIER_MAX_FILES; i++)
            if (!source_close_fd(&mcp_admin_scope.files[i]))
                return false;
        if (!mcp_admin_root_current() || !source_close_fd(&mcp_admin_scope.cgroup) || unlinkat(mcp_admin_scope.anchor, mcp_admin_scope.identity.cgroup_name, AT_REMOVEDIR))
            return false;
        mcp_admin_scope.created = false;
        if (!mcp_admin_step(9))
            return false;
        mcp_admin_scope.acked = true;
    }
    *response = mcp_admin_scope.identity;
    response->command = CLIQ_MCP_ADMIN_ACK;
    bool            valid = stamp_observation(response);
    if (!source_close_fd(&mcp_admin_scope.birth) || !source_close_fd(&mcp_admin_scope.anchor))
        valid = false;
    free(mcp_admin_scope.incoming);
    mcp_admin_scope.incoming = NULL;
    if (valid)
        mcp_admin_controller_init();
    return valid;
}
static bool
mcp_admin_cleanup_retained(struct cliq_worker_packet *request, int *passed, size_t count, struct cliq_worker_packet *response)
{
    if (count != 2 || mcp_admin_scope.attempted || request->scope || !request->admin_checker_owner_epoch || request->admin_checker_supervisor_pid <= 0 || request->admin_checker_supervisor_pid > INT32_MAX ||
        !cliq_mcp_admin_digest(request->admin_original_birth_digest))
        return false;
    struct ucred    credentials;
    socklen_t       credentials_size = sizeof(credentials);
    char            supervisor_token[CLIQ_WORKER_TOKEN_BYTES];
    if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) || credentials_size != sizeof(credentials) || credentials.pid != request->admin_checker_supervisor_pid || credentials.uid != geteuid() ||
        !cliq_process_token(credentials.pid, supervisor_token) || strcmp(supervisor_token, request->admin_checker_supervisor_token))
        return false;
    int             root = passed[0], birth = passed[1], group = -1;
    passed[0] = passed[1] = -1;
    struct stat     root_identity, held, named;
    struct cliq_mcp_admin_history history, final;
    unsigned char  *snapshot = NULL;
    size_t          bytes = 0;
    bool            valid = native_cgroup(root) && !fstat(root, &root_identity) && cliq_mcp_admin_read_history(birth, &history, &snapshot, &bytes) && history.count && history.last.kind >= 3 &&
    !(history.last.kind == 4 && !history.last.packet.monitor_pid) && cliq_mcp_admin_packet_same(request, &history.first.packet) && history.first.controller_pid != getpid() &&
    history.first.controller_root.device == (uint64_t) root_identity.st_dev && history.first.controller_root.inode == (uint64_t) root_identity.st_ino &&
    original_process_absent((pid_t) history.header.supervisor_pid, history.header.supervisor_start_token) && original_process_absent((pid_t) history.first.controller_pid, history.first.controller_start_token) && !flock(birth, LOCK_EX | LOCK_NB);
    unsigned char   hash[32];
    char            digest[65];
    if (valid) {
        cliq_mcp_admin_hash(snapshot, bytes, hash);
        source_hex(hash, digest);
        valid = !strcmp(digest, request->admin_original_birth_digest);
    } free(snapshot);
    snapshot = NULL;
    char            name[96];
    snprintf(name, sizeof(name), "cliq-mcp-admin-%s", request->nonce);
    bool            present = false;
    const struct cliq_worker_packet *original = &history.last.packet;
    if (valid) {
        group = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        present = group >= 0;
        valid = present ? native_cgroup(group) && !fstat(group, &held) && (uint64_t) held.st_dev == original->cgroup_device && (uint64_t) held.st_ino == original->cgroup_inode && held.st_uid == geteuid() && held.st_gid == getegid() && (held.st_mode & 07777) == 0700 : errno == ENOENT && history.last.kind == 9;
    }
    struct tracked_set tracked = {0};
    if (valid && present)
        valid = collect_processes(group, &tracked, 0);
    if (valid && original->monitor_pid)
        valid = track_process(&tracked, (pid_t) original->monitor_pid, original->monitor_start_token);
    if (valid && history.ready.kind == 5)
        valid = track_process(&tracked, (pid_t) history.ready.packet.pid, history.ready.packet.start_token) && track_process(&tracked, (pid_t) history.ready.packet.namespace_init_pid, history.ready.packet.init_native_start_token);
    if (valid && original->monitor_pid && !original_process_absent((pid_t) original->monitor_pid, original->monitor_start_token))
        valid = stop_retained_subreaper((pid_t) original->monitor_pid, original->monitor_start_token);
    if (valid && present)
        valid = write_control(group, "cgroup.kill", "1");
    int64_t         start = milliseconds();
    valid = valid && start >= 0;
    while (valid && ((present && !cgroup_empty(group)) || !tracked_absent(&tracked))) {
        int64_t         now = milliseconds();
        if (now < start || now - start >= 2000) {
            valid = false;
            break;
        } struct timespec pause = {0, 10000000};
        nanosleep(&pause, NULL);
    }
    valid = valid && original_process_absent((pid_t) history.header.supervisor_pid, history.header.supervisor_start_token) && original_process_absent((pid_t) history.first.controller_pid, history.first.controller_start_token) &&
        cliq_mcp_admin_read_history(birth, &final, &snapshot, &bytes) && final.count == history.count && !memcmp(final.last.digest, history.last.digest, 32);
    if (valid) {
        cliq_mcp_admin_hash(snapshot, bytes, hash);
        source_hex(hash, digest);
        valid = !strcmp(digest, request->admin_original_birth_digest);
    } free(snapshot);
    if (valid && present)
        valid = !fstat(group, &held) && !fstatat(root, name, &named, AT_SYMLINK_NOFOLLOW) && source_stat_same(&held, &named) &&
            (uint64_t) held.st_dev == original->cgroup_device && (uint64_t) held.st_ino == original->cgroup_inode && cgroup_empty(group) && !unlinkat(root, name, AT_REMOVEDIR);
    valid = valid && !fstat(root, &held) && source_stat_same(&held, &root_identity) && fstatat(root, name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT && tracked_absent(&tracked);
    if (!source_close_fd(&group) || !source_close_fd(&birth) || !source_close_fd(&root))
        valid = false;
    if (!valid)
        return false;
    *response = *request;
    response->command = CLIQ_MCP_ADMIN_CLEANUP_RETAINED;
    response->populated = 0;
    response->remaining_descendants = 0;
    response->init_reaped = history.ready.kind == 5 ? 1 : 0;
    response->reservation_observation = history.last.kind;
    return stamp_observation(response);
}
static bool
mcp_admin_command(struct cliq_worker_packet *request, int passed[CLIQ_WORKER_MAX_FDS], size_t count, struct cliq_worker_packet *response, int outputs[CLIQ_SOURCE_TRANSFER_OUTPUTS], size_t * output_count)
{
    if (!cliq_mcp_admin_packet_closed(request))
        return false;
    if ((request->command == CLIQ_MCP_ADMIN_RESERVE || request->command == CLIQ_MCP_ADMIN_CLEANUP_RETAINED) &&
        source_scope.attempted && !(source_scope.preparation && source_scope.retired && source_scope.preparation_completed))
        return false;
    if (request->command == CLIQ_MCP_ADMIN_CLEANUP_RETAINED)
        return mcp_admin_cleanup_retained(request, passed, count, response);
    if (request->command == CLIQ_MCP_ADMIN_RESERVE)
        return mcp_admin_reserve(request, passed, count, response);
    if (!mcp_admin_scope.attempted || !cliq_mcp_admin_packet_same(request, &mcp_admin_scope.identity))
        return false;
    if (request->command == CLIQ_MCP_ADMIN_CREATE_BLOCKED)
        return !count && mcp_admin_create_blocked(request, response);
    if (request->command == CLIQ_MCP_ADMIN_STOP)
        return !count && mcp_admin_stop(response);
    if (request->command == CLIQ_MCP_ADMIN_ACK)
        return !count && mcp_admin_ack(response);
    if (request->command == CLIQ_MCP_ADMIN_RELEASE_RECIPE) {
        if (count || !mcp_admin_scope.blocked || mcp_admin_scope.released || mcp_admin_scope.dead || !mcp_admin_root_current() || !mcp_admin_step(6))
            return false;
        mcp_admin_scope.released = true;
        unsigned char  *recipe = malloc(mcp_admin_scope.config.recipe_bytes);
        if (!recipe)
            return false;
        bool            valid = cliq_mcp_admin_read_exact(mcp_admin_scope.recipe_fd, recipe, mcp_admin_scope.config.recipe_bytes, 0) && mcp_admin_deliver_frame(CLIQ_MCP_CONFIG, recipe, mcp_admin_scope.config.recipe_bytes) && cliq_send(mcp_admin_scope.channel, request, NULL, 0);
        free(recipe);
        *response = mcp_admin_scope.identity;
        response->command = CLIQ_MCP_ADMIN_RELEASE_RECIPE;
        return valid && stamp_observation(response);
    }
    if (request->command == CLIQ_MCP_ADMIN_DELIVER) {
        if (count != 1 || !mcp_admin_scope.stage_waiting || request->admin_phase != mcp_admin_scope.next_phase)
            return false;
        struct stat     file;
        if (fstat(passed[0], &file) || !S_ISREG(file.st_mode) || file.st_size < 1 || file.st_size > CLIQ_MCP_ADMIN_MAX_MESSAGE || fcntl(passed[0], F_GET_SEALS) != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
            return false;
        unsigned char  *bytes = malloc((size_t) file.st_size);
        if (!bytes)
            return false;
        bool            valid = cliq_mcp_admin_read_exact(passed[0], bytes, (size_t) file.st_size, 0) && mcp_admin_deliver_frame(CLIQ_MCP_MESSAGE, bytes, (size_t) file.st_size);
        free(bytes);
        if (valid && request->admin_protocol_complete) {
            mcp_admin_scope.stage_waiting = false;
            mcp_admin_scope.next_phase++;
        } *response = mcp_admin_scope.identity;
        response->command = CLIQ_MCP_ADMIN_DELIVER;
        return valid && stamp_observation(response);
    }
    if (request->command == CLIQ_MCP_ADMIN_POLL) {
        if (count)
            return false;
        if (!mcp_admin_natural_join(response)) {
            if (!mcp_admin_scope.failed || !mcp_admin_stop(response))
                return false;
            response->command = CLIQ_MCP_ADMIN_POLL;
        }
        if (mcp_admin_scope.incoming && mcp_admin_scope.incoming_at == mcp_admin_scope.incoming_size) {
            if (mcp_admin_scope.incoming_kind != CLIQ_MCP_STAGE || mcp_admin_scope.stage_waiting || mcp_admin_scope.next_phase >= 3)
                return false;
            int             frame = memfd_create("cliq-mcp-admin-fixed-frame", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            if (frame < 0 || write(frame, mcp_admin_scope.incoming, mcp_admin_scope.incoming_size) != (ssize_t) mcp_admin_scope.incoming_size || fchmod(frame, 0400) || fcntl(frame, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
                if (frame >= 0)
                    close(frame);
                return false;
            }
            outputs[0] = frame;
            *output_count = 1;
            response->admin_phase = mcp_admin_scope.next_phase;
            mcp_admin_scope.stage_waiting = true;
            free(mcp_admin_scope.incoming);
            mcp_admin_scope.incoming = NULL;
            mcp_admin_scope.header_size = 0;
            mcp_admin_scope.incoming_at = 0;
        }
        return true;
    }
    return false;
}
#endif
