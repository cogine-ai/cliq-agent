/* Test-only load-time guard sensitivity. An unreadable pointer on a foreign
 * pthread must be rejected before any context read. This is not a real UAF
 * reproduction, process-lifetime qualification or production fault hook. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../../../native/state-owner/state-owner.c"

static void *thread_guard_check(void *unreadable) {
  if (credential_owner_context((const credential_context *)unreadable)) _exit(98);
  return NULL;
}
__attribute__((constructor)) static void thread_guard_probe(void) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) _exit(98);
  void *unreadable = mmap(NULL, (size_t)page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (unreadable == MAP_FAILED) _exit(98);
  pthread_t foreign;
  if (pthread_create(&foreign, NULL, thread_guard_check, unreadable) != 0 ||
      pthread_join(foreign, NULL) != 0 || munmap(unreadable, (size_t)page_size) != 0) _exit(98);
  if (fputs("CLIQ_CREDENTIAL_FOREIGN_THREAD_GUARD_VERIFIED\n", stderr) < 0 || fflush(stderr) != 0) _exit(98);
}
