/* Test-only translation unit of the actual production image. Fixed roles,
 * real close/reuse, no extra NAPI methods or production fault interfaces. */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <errno.h>
#include <fcntl.h>
#include <node_api.h>
#include <sqlite3ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
SQLITE_EXTENSION_INIT3
static int retirement_native_close(int descriptor);
#define close(descriptor) retirement_native_close(descriptor)
#include "../../../native/state-owner/credential-vfs.h"
static int retirement_native_resources(credential_context *ctx);
#define credential_retire_resources(ctx) retirement_native_resources(ctx)
#include "../../../native/state-owner/state-owner.c"
#undef credential_retire_resources
#undef close

static credential_context *retiring, *injected_context;
static int injected, reused_descriptor = -1, owned_descriptors[256];
static unsigned int owned_count, expected_closes;
static int expected_remaining[CREDENTIAL_ROLE_COUNT];
static int available[CREDENTIAL_ROLE_COUNT];
static const char *const fixed_roles[] = {"root", "credentials", "lock", "main", "wal", "journal", "runtime", "global"};

static void retirement_verify_at_exit(void) {
  credential_context *ctx = injected_context;
  struct stat actual, zero;
  unsigned char byte = 1;
  if (ctx == NULL || !ctx->uncertain || !atomic_load(&credential_process.poisoned) ||
      atomic_load(&credential_process.active) != ctx || ctx->counts.closes != expected_closes ||
      reused_descriptor < 0 || fstat(reused_descriptor, &actual) != 0 || stat("/dev/zero", &zero) != 0 ||
      actual.st_rdev != zero.st_rdev || read(reused_descriptor, &byte, 1) != 1 || byte != 0) _exit(98);
  for (int role = 0; role < CREDENTIAL_ROLE_COUNT; ++role) {
    if (ctx->descriptors[role] != expected_remaining[role]) _exit(98);
    if (expected_remaining[role] >= 0 &&
        (fstat(expected_remaining[role], &actual) != 0 ||
         !credential_same_object(&actual, &ctx->identities[role]))) _exit(98);
  }
  if (fputs("CLIQ_CREDENTIAL_RETIREMENT_VERIFIED\n", stderr) < 0 || fflush(stderr) != 0) _exit(98);
}
static int retirement_native_resources(credential_context *ctx) {
  retiring = ctx;
  memcpy(available, ctx->descriptors, sizeof(available));
  int result = credential_retire_resources(ctx);
  retiring = NULL;
  return result;
}
static int retirement_native_close(int descriptor) {
  credential_context *ctx = retiring;
  const char *requested = getenv("CLIQ_CREDENTIAL_RETIREMENT_ROLE");
  int target = CREDENTIAL_ROLE_COUNT;
  if (requested != NULL) {
    for (int role = 0; role < CREDENTIAL_ROLE_COUNT; ++role) {
      if (strcmp(requested, fixed_roles[role]) == 0) target = role;
    }
  }
  struct stat actual;
  if (injected || ctx == NULL || target == CREDENTIAL_ROLE_COUNT || ctx->live_files != 0 ||
      ctx->uncertain || ctx->fenced || ctx->counts.closes == 0 || ctx->descriptors[target] != -1 ||
      fstat(descriptor, &actual) != 0 || !credential_same_object(&actual, &ctx->identities[target]))
    return close(descriptor);
  injected = 1;
  injected_context = ctx;
  reused_descriptor = descriptor;
  /* Independent fixed retirement order, not a snapshot recomputed from the
   * already-mutated implementation. Acquisition may own only a prefix set. */
  static const enum credential_role order[] = {CREDENTIAL_JOURNAL, CREDENTIAL_WAL,
    CREDENTIAL_CREDENTIALS, CREDENTIAL_ROOT, CREDENTIAL_MAIN, CREDENTIAL_LOCK,
    CREDENTIAL_RUNTIME, CREDENTIAL_GLOBAL};
  memcpy(expected_remaining, available, sizeof(expected_remaining));
  expected_closes = 0;
  for (size_t index = 0; index < sizeof(order) / sizeof(order[0]); ++index) {
    if (available[order[index]] >= 0) expected_closes++;
    expected_remaining[order[index]] = -1;
    if ((int)order[index] == target) break;
  }
  if (close(descriptor) != 0 || atexit(retirement_verify_at_exit) != 0) _exit(98);
  while (owned_count < sizeof(owned_descriptors) / sizeof(owned_descriptors[0])) {
    int replacement = open("/dev/zero", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (replacement < 0) _exit(98);
    owned_descriptors[owned_count++] = replacement;
    if (replacement == descriptor) { errno = EIO; return -1; }
    if (replacement > descriptor) _exit(98);
  }
  _exit(98);
}
