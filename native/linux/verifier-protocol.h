#ifndef CLIQ_VERIFIER_PROTOCOL_H
#define CLIQ_VERIFIER_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define CLIQ_VERIFIER_CONFIG_MAGIC UINT32_C(0x43565131)
#define CLIQ_VERIFIER_MAX_FILES 32
#define CLIQ_VERIFIER_MAX_ARGS 64
#define CLIQ_VERIFIER_MAX_ENV 128
#define CLIQ_VERIFIER_STRING_BYTES 65536
#define CLIQ_VERIFIER_PATH_BYTES 4096

enum cliq_verifier_termination {
    CLIQ_VERIFIER_PENDING = 0,
    CLIQ_VERIFIER_EXIT = 1,
    CLIQ_VERIFIER_SIGNAL = 2,
    CLIQ_VERIFIER_SPAWN_ERROR = 3,
    CLIQ_VERIFIER_TIMEOUT = 4,
    CLIQ_VERIFIER_RESOURCE = 5,
    /* Actual RELEASE-to-whole-domain-stop observation, not a wait status. */
    CLIQ_VERIFIER_CONTROLLER_STOP = 6
};

/* Sealed, bounded native projection of the exact decoded command/environment.
 * This is not a new wire/artifact format or permission source. */
struct cliq_verifier_config {
    uint32_t magic, version, file_count, argument_count, environment_count, string_bytes;
    uint64_t timeout_ms, output_limit;
    char executable[CLIQ_VERIFIER_PATH_BYTES];
    char cwd[CLIQ_VERIFIER_PATH_BYTES];
    uint32_t arguments[CLIQ_VERIFIER_MAX_ARGS];
    uint32_t environment[CLIQ_VERIFIER_MAX_ENV];
    char strings[CLIQ_VERIFIER_STRING_BYTES];
    struct {
        char path[CLIQ_VERIFIER_PATH_BYTES];
        char digest[65];
        uint64_t byte_count;
    } files[CLIQ_VERIFIER_MAX_FILES];
};

static inline bool cliq_verifier_path(const char *path) {
    size_t length = strnlen(path, CLIQ_VERIFIER_PATH_BYTES);
    if (length < 2 || length == CLIQ_VERIFIER_PATH_BYTES || path[0] != '/' || path[length - 1] == '/' || strchr(path, '\\')) return false;
    const char *component = path + 1;
    for (const char *cursor = component; ; cursor++) {
        if (*cursor != '/' && *cursor != '\0') continue;
        size_t bytes = (size_t)(cursor - component);
        if (bytes == 0 || bytes > 255 || (bytes == 1 && component[0] == '.') ||
            (bytes == 2 && component[0] == '.' && component[1] == '.')) return false;
        if (*cursor == '\0') return true;
        component = cursor + 1;
    }
}

static inline bool cliq_verifier_mapping_path(const char *path) {
    if (strcmp(path, "/usr/bin/node") == 0 || strcmp(path, "/lib64/ld-linux-x86-64.so.2") == 0) return true;
    const char *prefixes[] = { "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t length = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], length) != 0 || !path[length]) continue;
        for (const char *at = path + length; *at; at++) {
            if (!((*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z') || (*at >= '0' && *at <= '9') ||
                *at == '.' || *at == '_' || *at == '-' || *at == '+')) return false;
        }
        return true;
    }
    return false;
}

static inline bool cliq_verifier_config_valid(const struct cliq_verifier_config *config) {
    if (config->magic != CLIQ_VERIFIER_CONFIG_MAGIC || config->version != 1 ||
        config->file_count == 0 || config->file_count > CLIQ_VERIFIER_MAX_FILES ||
        config->argument_count == 0 || config->argument_count > CLIQ_VERIFIER_MAX_ARGS ||
        config->environment_count > CLIQ_VERIFIER_MAX_ENV || config->string_bytes == 0 ||
        config->string_bytes > CLIQ_VERIFIER_STRING_BYTES || config->strings[config->string_bytes - 1] != '\0' ||
        config->timeout_ms == 0 || config->timeout_ms > UINT64_C(3600000) ||
        config->output_limit < 1 || config->output_limit > UINT64_C(67108864) ||
        strcmp(config->executable, "/usr/bin/node") != 0 ||
        (strcmp(config->cwd, "/work") != 0 && (!cliq_verifier_path(config->cwd) || strncmp(config->cwd, "/work/", 6) != 0))) return false;
    for (uint32_t i = 0; i < config->argument_count; i++) {
        uint32_t at = config->arguments[i];
        if (at >= config->string_bytes || (at != 0 && config->strings[at - 1] != '\0') ||
            !memchr(config->strings + at, '\0', config->string_bytes - at)) return false;
    }
    if (strcmp(config->strings + config->arguments[0], config->executable) != 0) return false;
    for (uint32_t i = 0; i < config->environment_count; i++) {
        uint32_t at = config->environment[i];
        if (at >= config->string_bytes || (at != 0 && config->strings[at - 1] != '\0') ||
            !memchr(config->strings + at, '\0', config->string_bytes - at) || !strchr(config->strings + at, '=')) return false;
    }
    bool executable = false;
    for (uint32_t i = 0; i < config->file_count; i++) {
        if (!cliq_verifier_path(config->files[i].path) || !cliq_verifier_mapping_path(config->files[i].path) || config->files[i].byte_count == 0 ||
            config->files[i].byte_count > UINT64_C(268435456) ||
            strnlen(config->files[i].digest, 65) != 64) return false;
        for (uint32_t j = 0; j < i; j++) if (strcmp(config->files[i].path, config->files[j].path) == 0) return false;
        if (strcmp(config->files[i].path, config->executable) == 0) executable = true;
    }
    return executable;
}

#endif
