/* Qualification server source only. Root compiles this real static ELF and
 * its existing qualification publisher signs it as mcp_server. It supplies no
 * host/native/SQL/resource proof and is never a production server selector. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#define FIXTURE_LINE_BYTES 1048576u
#ifdef CLIQ_MCP_RECOVERY_STATUS_ONLY
enum { STATUS_ONLY_ADAPTER = 1 };
#else
enum { STATUS_ONLY_ADAPTER = 0 };
#endif
static int reply(const char *bytes) {
    return fputs(bytes, stdout) < 0 || fputc('\n', stdout) == EOF || fflush(stdout) ? 70 : 0;
}
static int oversized_response(void) {
    if (fputs("{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"padding\":\"", stdout) < 0) return 70;
    for (size_t i = 0; i < FIXTURE_LINE_BYTES; i++) if (fputc('x', stdout) == EOF) return 70;
    return reply("\"}}");
}
static int oversized_output(void) {
    // Exceed the fixed maximum recipe, without depending on a particular
    // qualification request's smaller output ceiling or emitting secrets.
    char bytes[4096]; memset(bytes, 'x', sizeof(bytes));
    for (size_t i = 0; i < 16385; i++) if (fwrite(bytes, 1, sizeof(bytes), stderr) != sizeof(bytes)) return 70;
    return fflush(stderr) ? 70 : 0;
}
/* This limited publisher profile has no durable state. A fresh status
 * process can prove the compile-time no-op target exists; it cannot prove
 * that an old process executed a call. Qualification must retain that label. */
enum noop_reply_mode { NOOP_REPLY, NOOP_EFFECT_NO_REPLY, NOOP_EFFECT_EXIT, NOOP_EFFECT_AND_STATUS_NO_REPLY, NOOP_STATUS_MALFORMED, NOOP_MISSING_TARGET };
static int noop_target_exists(const char *target) {
    static const char *const targets[] = {"fixture-existing-target"};
    for (size_t index = 0; index < sizeof(targets) / sizeof(targets[0]); index++)
        if (!strcmp(targets[index], target)) return 1;
    return 0;
}
static int reply_noop_tools(int exists, const char *profile, const char *state) {
    const char *effect = exists ? "No-op effect over an immutable preexisting fixture target; changes no state." :
        "No-op effect requires an immutable fixture target that is absent.";
    const char *status = exists ? "Read-only inspection of a compile-time preexisting no-op target. Never observes or attests prior effect execution." :
        "Read-only lookup of the immutable required target. Never attests prior effect execution.";
    int written = printf("{\"id\":2,\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"description\":\"%s\",\"inputSchema\":{\"additionalProperties\":false,\"properties\":{\"idempotencyKey\":{\"pattern\":\"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$\",\"type\":\"string\"}},\"required\":[\"idempotencyKey\"],\"type\":\"object\"},\"name\":\"stdio_noop_effect\",\"outputSchema\":{\"additionalProperties\":false,\"properties\":{\"originalExecutionObserved\":{\"const\":false,\"type\":\"boolean\"},\"profileClass\":{\"const\":\"%s\",\"type\":\"string\"},\"targetState\":{\"const\":\"%s\",\"type\":\"string\"}},\"required\":[\"originalExecutionObserved\",\"profileClass\",\"targetState\"],\"type\":\"object\"}},{\"description\":\"%s\",\"inputSchema\":{\"additionalProperties\":false,\"properties\":{\"idempotencyKey\":{\"pattern\":\"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$\",\"type\":\"string\"}},\"required\":[\"idempotencyKey\"],\"type\":\"object\"},\"name\":\"stdio_noop_status\",\"outputSchema\":{\"additionalProperties\":false,\"properties\":{\"originalExecutionObserved\":{\"const\":false,\"type\":\"boolean\"},\"profileClass\":{\"const\":\"%s\",\"type\":\"string\"},\"targetState\":{\"const\":\"%s\",\"type\":\"string\"}},\"required\":[\"originalExecutionObserved\",\"profileClass\",\"targetState\"],\"type\":\"object\"},\"annotations\":{\"readOnlyHint\":true,\"destructiveHint\":false,\"idempotentHint\":true,\"openWorldHint\":false}}]}}", effect, profile, state, status, profile, state);
    return written < 0 || fputc('\n', stdout) == EOF || fflush(stdout) ? 70 : 0;
}
static int immutable_noop_profile(enum noop_reply_mode mode) {
    char *line = malloc(FIXTURE_LINE_BYTES + 2u);
    if (!line) return 70;
    const char *expected[] = {"\"method\":\"initialize\"", "\"method\":\"notifications/initialized\"", "\"method\":\"tools/list\""};
    const char *target = mode == NOOP_MISSING_TARGET ? "fixture-missing-target" : "fixture-existing-target";
    int target_exists = noop_target_exists(target);
    const char *profile = target_exists ? "immutable_preexisting_noop_target" : "immutable_missing_noop_target";
    const char *state = target_exists ? "preexisting_noop" : "missing_immutable_target";
    int result = 0;
    for (unsigned stage = 0; stage < 3; stage++) {
        if (!fgets(line, FIXTURE_LINE_BYTES + 2u, stdin) || strlen(line) > FIXTURE_LINE_BYTES ||
            !strchr(line, '\n') || !strstr(line, expected[stage])) { result = 65; goto done; }
        if (!stage && reply("{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"capabilities\":{\"tools\":{}},\"protocolVersion\":\"2025-11-25\",\"serverInfo\":{\"name\":\"cliq-immutable-noop-fixture\",\"version\":\"1\"}}}")) { result = 70; goto done; }
        if (stage == 2 && reply_noop_tools(target_exists, profile, state)) { result = 70; goto done; }
    }
    if (!fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) goto done;
    const char *prefix = "{\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"idempotencyKey\":\"";
    size_t start = strlen(prefix);
    if (strncmp(line, prefix, start) || strlen(line) < start + 43) { result = 65; goto done; }
    for (size_t i = 0; i < 43; i++)
        if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", line[start + i])) { result = 65; goto done; }
    if (!strchr("AEIMQUYcgkosw048", line[start + 42])) { result = 65; goto done; }
    const char *suffix = line + start + 43;
    if (strcmp(suffix, "\"},\"name\":\"stdio_noop_effect\"}}\n") &&
        strcmp(suffix, "\"},\"name\":\"stdio_noop_status\"}}\n")) { result = 65; goto done; }
    int effect = !strcmp(suffix, "\"},\"name\":\"stdio_noop_effect\"}}\n");
    if (STATUS_ONLY_ADAPTER && effect) { result = 65; goto done; }
    /* The effect's fixed target is immutable. A missing precondition makes
     * this request fail locally even when its response is lost. */
    if (effect && !target_exists) goto done;
    if (mode != NOOP_REPLY && (effect || mode == NOOP_EFFECT_AND_STATUS_NO_REPLY)) {
        /* A signed, separate fixture profile may naturally exit after consuming
         * the effect. EOF leaves time for genuine retirement and another claim
         * within the original deadline; it does not attest prior execution. */
        if (mode == NOOP_EFFECT_EXIT) goto done;
        /* Consume the valid effect without replying. A subsequent fixed ping
         * remains responsive: this models a lost response, not a paused task.
         * Production qualification still needs its actual timeout and join. */
        if (fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) {
            if (strcmp(line, "{\"id\":\"fixture-noop-ping\",\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n")) { result = 65; goto done; }
            if (reply("{\"id\":\"fixture-noop-ping\",\"jsonrpc\":\"2.0\",\"result\":{}}")) { result = 70; goto done; }
            if (fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) result = 65;
        }
        goto done;
    }
    if (mode == NOOP_STATUS_MALFORMED) {
        /* The exact signed status tool writes a complete bounded line with
         * invalid JSON, then remains a real live server until its owner
         * retires stdin/process/pipes. The sentinel is fixed public test data. */
        result = reply("{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{\"sentinel\":\"cliq-fixture-refused-status-sentinel\"");
        if (!result && fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) result = 65;
        goto done;
    }
    if (!target_exists) {
        /* The fresh status process independently reads the same immutable
         * target table. It only reports absence, with no old execution claim. */
        result = reply("{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[],\"isError\":false,\"structuredContent\":{\"originalExecutionObserved\":false,\"profileClass\":\"immutable_missing_noop_target\",\"targetState\":\"missing_immutable_target\"}}}");
        if (!result && fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) result = 65;
        goto done;
    }
    if (reply("{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"text\":\"Immutable preexisting no-op target exists; prior execution is unobserved.\",\"type\":\"text\"}],\"isError\":false,\"structuredContent\":{\"originalExecutionObserved\":false,\"profileClass\":\"immutable_preexisting_noop_target\",\"targetState\":\"preexisting_noop\"}}}")) { result = 70; goto done; }
    /* Preserve the ordinary server lifetime until the genuine owner closes
     * stdin or signals this process; no second call is accepted. */
    if (fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) result = 65;
done:
    free(line); return result;
}
int main(int argc, char **argv) {
    if (!STATUS_ONLY_ADAPTER && argc == 2 && !strcmp(argv[1], "immutable_noop_profile")) return immutable_noop_profile(NOOP_REPLY);
    if (argc == 2 && !strcmp(argv[1], "--immutable-noop-effect-no-reply")) return immutable_noop_profile(NOOP_EFFECT_NO_REPLY);
    if (!STATUS_ONLY_ADAPTER && argc == 2 && !strcmp(argv[1], "--immutable-noop-effect-exit-no-reply")) return immutable_noop_profile(NOOP_EFFECT_EXIT);
    if (argc == 2 && !strcmp(argv[1], "--immutable-noop-effect-and-status-no-reply")) return immutable_noop_profile(NOOP_EFFECT_AND_STATUS_NO_REPLY);
    if (argc == 2 && !strcmp(argv[1], "--immutable-noop-effect-no-reply-status-malformed")) return immutable_noop_profile(NOOP_STATUS_MALFORMED);
    if (argc == 2 && !strcmp(argv[1], "--immutable-noop-status-observes-target-only")) return immutable_noop_profile(NOOP_EFFECT_NO_REPLY);
    if (argc == 2 && !strcmp(argv[1], "--immutable-noop-missing-required-target")) return immutable_noop_profile(NOOP_MISSING_TARGET);
    if (STATUS_ONLY_ADAPTER) return 64;
    const char *mode = argc == 2 ? argv[1] : "known";
    if (argc > 2 || (strcmp(mode, "known") && strcmp(mode, "ping") && strcmp(mode, "hang") &&
        strcmp(mode, "early_exit") && strcmp(mode, "fork_holder") && strcmp(mode, "invalid_json") &&
        strcmp(mode, "oversize_response") && strcmp(mode, "oversize_output") && strcmp(mode, "result_exit"))) return 64;
    char *line = malloc(FIXTURE_LINE_BYTES + 2u);
    if (!line) return 70;
    unsigned stage = 0, effects = 0; int result = 0;
    while (fgets(line, FIXTURE_LINE_BYTES + 2u, stdin)) {
        size_t length = strlen(line);
        if (!length || length > FIXTURE_LINE_BYTES || line[length - 1] != '\n') { result = 65; break; }
        if (!stage) {
            if (!strstr(line, "\"method\":\"initialize\"")) { result = 65; break; }
            if (!strcmp(mode, "early_exit")) { result = 42; break; }
            if (!strcmp(mode, "invalid_json")) { result = reply("{\"id\":1,"); break; }
            if (!strcmp(mode, "oversize_response")) { result = oversized_response(); break; }
            if (!strcmp(mode, "oversize_output")) { result = oversized_output(); break; }
            if (!strcmp(mode, "ping")) {
                if (reply("{\"id\":\"fixture-ping\",\"jsonrpc\":\"2.0\",\"method\":\"ping\"}")) { result = 70; break; }
                stage = 1; continue;
            }
        } else if (stage == 1) {
            if (strcmp(line, "{\"id\":\"fixture-ping\",\"jsonrpc\":\"2.0\",\"result\":{}}\n")) { result = 65; break; }
        }
        if (stage <= 1) {
            if (reply("{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"capabilities\":{\"tools\":{}},\"protocolVersion\":\"2025-11-25\",\"serverInfo\":{\"name\":\"cliq-static-stdio-fixture\",\"version\":\"1\"}}}")) { result = 70; break; }
            stage = 2;
        } else if (stage == 2) {
            if (!strstr(line, "\"method\":\"notifications/initialized\"")) { result = 65; break; }
            stage = 3;
        } else if (stage == 3) {
            if (!strstr(line, "\"method\":\"tools/list\"") ||
                reply("{\"id\":2,\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"description\":\"Actual contained static fixture call\",\"inputSchema\":{\"additionalProperties\":false,\"properties\":{},\"type\":\"object\"},\"name\":\"stdio_echo\"}]}}")) { result = 65; break; }
            stage = 4;
        } else {
            if (!strstr(line, "\"method\":\"tools/call\"") || !strstr(line, "\"name\":\"stdio_echo\"") || ++effects != 1) { result = 65; break; }
            if (!strcmp(mode, "fork_holder")) {
                pid_t child = fork();
                if (child < 0) { result = 70; break; }
                if (!child) for (;;) pause();
            }
            if (!strcmp(mode, "hang")) for (;;) pause();
            if (reply("{\"id\":3,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"text\":\"called once\",\"type\":\"text\"}],\"isError\":false}}")) { result = 70; break; }
            if (!strcmp(mode, "result_exit")) break;
            stage = 5;
        }
    }
    free(line); return result;
}

