/* Test-only close-consumption experiment, never linked into production.
 * No production fault interface, path/FD selector or second SQLite engine. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Include system declarations before replacing candidate call sites. */
static int retirement_probe_close(int descriptor);
#define close(descriptor) retirement_probe_close(descriptor)
#include "credential-vfs-probe.c"
#undef close

static int injected = 0;
static int test_owned_descriptors[256];
static unsigned int test_owned_count = 0;

static enum credential_role retirement_role(void) {
  const char *requested = getenv("CLIQ_CREDENTIAL_VFS_RETIREMENT_ROLE");
  if (requested != NULL) {
    for (int role = ROOT; role < ROLE_COUNT; ++role) {
      if (strcmp(requested, roles[role]) == 0) return (enum credential_role)role;
    }
  }
  return ROLE_COUNT;
}

static int retirement_probe_close(int descriptor) {
  enum credential_role target = retirement_role();
  struct stat actual;
  /* consume_close has already incremented closes and consumed its numeric FD.
   * This cannot fire for checked_close's temporary directory descriptors or
   * for a live pager: the selected held role must now be absent and its actual
   * inode must match the originally retained role. Only six fixed roles exist. */
  if (injected || target == ROLE_COUNT || !prepared || retired || uncertain ||
      fenced || live_files != 0 || counts.closes == 0 || descriptors[target] != -1 ||
      fstat(descriptor, &actual) != 0 || !same_object(&actual, &identities[target]))
    return close(descriptor);

  injected = 1;
  if (close(descriptor) != 0) return -1;
  /* Actually reuse the released number, without dup2 or closing an unknown
   * descriptor. Earlier consumed slots may be lower, so retain every newly
   * opened, test-owned /dev/zero FD until the target is reached. Missing exact
   * reuse is a fixture failure, never a simulated candidate close error. */
  while (test_owned_count < sizeof(test_owned_descriptors) / sizeof(test_owned_descriptors[0])) {
    int replacement = open("/dev/zero", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (replacement < 0) _exit(98);
    test_owned_descriptors[test_owned_count++] = replacement;
    if (replacement == descriptor) {
      errno = EIO;
      return -1;
    }
    if (replacement > descriptor) _exit(98);
  }
  _exit(98);
}
