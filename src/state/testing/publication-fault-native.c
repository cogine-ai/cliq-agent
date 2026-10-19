/* Test-only build of the actual publisher. Production has no syscall fault
 * controls. Consume a failing close before reporting uncertainty, matching the
 * real close contract in which its numeric descriptor may already be reused. */
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
static int publication_fault_close(int fd);
static struct dirent *publication_fault_readdir(DIR *directory);
static int publication_fault_mkdirat(int parent, const char *name, mode_t mode);
static int publication_fault_symlinkat(const char *target, int parent, const char *name);
#define close publication_fault_close
#define readdir publication_fault_readdir
#define mkdirat publication_fault_mkdirat
#define symlinkat publication_fault_symlinkat
#include "quarantine-fault-native.c"
#undef close
#undef readdir
#undef mkdirat
#undef symlinkat
static int publication_fault_close(int fd) {
    int error = inject("close");
    if (!error) {
        char observed[PATH_MAX]; int named = 0;
#ifdef __APPLE__
        named = fcntl(fd, F_GETPATH, observed) == 0;
#else
        char locator[64]; snprintf(locator, sizeof(locator), "/proc/self/fd/%d", fd);
        ssize_t length = readlink(locator, observed, sizeof(observed) - 1);
        if (length >= 0 && (size_t)length < sizeof(observed) - 1) { observed[length] = '\0'; named = 1; }
#endif
        const char suffix[] = "/runtime/publications";
        if (named && strlen(observed) >= sizeof(suffix) - 1 && !strcmp(observed + strlen(observed) - (sizeof(suffix) - 1), suffix))
            error = inject("namespace_parent_close");
    }
    int status = close(fd);
    if (error) { errno = error; return -1; }
    return status;
}
static struct dirent *publication_fault_readdir(DIR *directory) {
    int error = inject("readdir");
    if (error) { errno = error; return NULL; }
    return readdir(directory);
}
static int publication_fault_mkdirat(int parent, const char *name, mode_t mode) {
    int status = mkdirat(parent, name, mode);
    if (status < 0) return status;
    int error = inject("after_mkdir");
    if (error) { errno = error; return -1; }
    return 0;
}
static int publication_fault_symlinkat(const char *target, int parent, const char *name) {
    int status = symlinkat(target, parent, name);
    if (status < 0) return status;
    int error = inject("after_symlink");
    if (error) { errno = error; return -1; }
    return 0;
}
