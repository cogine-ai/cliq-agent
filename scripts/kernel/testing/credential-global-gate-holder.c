/* Test-only competing exclusive gate. No arguments, DB I/O or native export. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  (void)argv;
  const char *home = getenv("HOME");
  if (argc != 1 || home == NULL || home[0] != '/') return 2;
  int root = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int runtime = root < 0 ? -1 : openat(root, "runtime", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int gate = runtime < 0 ? -1 : openat(runtime, "kernel-global.lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  struct stat actual;
  if (gate < 0 || fstat(gate, &actual) != 0 || !S_ISREG(actual.st_mode) || actual.st_nlink != 1 ||
      (actual.st_mode & 07777) != 0600 || actual.st_uid != geteuid() || actual.st_gid != getegid() ||
      fsync(gate) != 0 || fsync(runtime) != 0 || flock(gate, LOCK_EX | LOCK_NB) != 0) return 3;
  if (puts("READY") < 0 || fflush(stdout) != 0 || getchar() != '\n') return 4;
  if (close(gate) != 0 || close(runtime) != 0 || close(root) != 0) return 5;
  return 0;
}
