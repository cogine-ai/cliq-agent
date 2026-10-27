#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/wait.h>
#include "dependency-npm-image.h"

static volatile sig_atomic_t cancelled;
static void cancel(int signal_number) { (void)signal_number; cancelled = 1; }
static size_t descriptors(void) {
    DIR *directory = opendir("/proc/self/fd"); assert(directory); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    assert(!closedir(directory)); return count;
}
static size_t count_files(int root) {
    int copy = openat(root, ".", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW); assert(copy >= 0); DIR *directory = fdopendir(copy); assert(directory);
    struct dirent *entry; size_t result = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat info; assert(!fstatat(root, entry->d_name, &info, AT_SYMLINK_NOFOLLOW));
        if (S_ISDIR(info.st_mode)) {
            int child = openat(root, entry->d_name, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
            assert(child >= 0); result += count_files(child); assert(!close(child));
        } else { assert(S_ISREG(info.st_mode) && info.st_nlink == 1 && (info.st_mode & 0777) == 0400); result++; }
    }
    assert(!closedir(directory)); return result;
}
int main(int argc, char **argv) {
    assert(argc == 2); umask(0077); size_t initial = descriptors();
    int image = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW); assert(image >= 0);
    char positive[] = "/tmp/cliq-npm-image-positive-XXXXXX"; assert(mkdtemp(positive));
    int root = open(positive, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW); assert(root >= 0);
    assert(cliq_npm_materialize(image, root, &cancelled) == CLIQ_NPM_IMAGE_OK);
    assert(count_files(root) == 2408);
    int cli = openat(root, "bin/npm-cli.js", O_RDONLY | O_CLOEXEC | O_NOFOLLOW); assert(cli >= 0); assert(!close(cli));
    assert(cliq_npm_materialize(image, root, &cancelled) == CLIQ_NPM_IMAGE_REFUSED); assert(!close(root));

    char negative[] = "/tmp/cliq-npm-image-negative-XXXXXX"; assert(mkdtemp(negative));
    root = open(negative, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW); assert(root >= 0);
    cancelled = 1; assert(cliq_npm_materialize(image, root, &cancelled) == CLIQ_NPM_IMAGE_CANCELLED); cancelled = 0;
    struct stat info; assert(cliq_npm_empty_root(root, &info) == CLIQ_NPM_IMAGE_OK);
    assert(!chmod(argv[1], 0600));
    int writable = open(argv[1], O_RDWR | O_CLOEXEC | O_NOFOLLOW); assert(writable >= 0);
    assert(cliq_npm_materialize(writable, root, &cancelled) == CLIQ_NPM_IMAGE_REFUSED); assert(!close(writable)); assert(!chmod(argv[1], 0400));
    assert(!chmod(argv[1], 0600)); assert(cliq_npm_materialize(image, root, &cancelled) == CLIQ_NPM_IMAGE_REFUSED); assert(!chmod(argv[1], 0400));
    assert(!chmod(argv[1], 0600)); writable = open(argv[1], O_RDWR | O_CLOEXEC | O_NOFOLLOW); assert(writable >= 0);
    unsigned char byte; assert(pread(writable, &byte, 1, 100) == 1); unsigned char changed = byte ^ 1;
    assert(pwrite(writable, &changed, 1, 100) == 1); assert(!close(writable)); assert(!chmod(argv[1], 0400));
    assert(cliq_npm_materialize(image, root, &cancelled) == CLIQ_NPM_IMAGE_REFUSED); assert(cliq_npm_empty_root(root, &info) == CLIQ_NPM_IMAGE_OK);
    assert(!chmod(argv[1], 0600)); writable = open(argv[1], O_RDWR | O_CLOEXEC | O_NOFOLLOW); assert(writable >= 0);
    assert(pwrite(writable, &byte, 1, 100) == 1); assert(!close(writable)); assert(!chmod(argv[1], 0400));
    assert(!close(root));

    char partial[] = "/tmp/cliq-npm-image-cancel-XXXXXX"; assert(mkdtemp(partial));
    int channel[2]; assert(!pipe2(channel, O_CLOEXEC)); pid_t child = fork(); assert(child >= 0);
    if (!child) {
        assert(!close(channel[0])); struct sigaction action = {0}; action.sa_handler = cancel; assert(!sigaction(SIGTERM, &action, NULL));
        int held = open(partial, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW); assert(held >= 0);
        enum cliq_npm_image_status status = cliq_npm_materialize(image, held, &cancelled);
        assert(!close(held)); assert(!close(image)); unsigned char result = (unsigned char)status;
        assert(write(channel[1], &result, 1) == 1); assert(!close(channel[1])); _exit(0);
    }
    assert(!close(channel[1]));
    /* Observe a genuinely materialized file, never a producer pause/hook. */
    char path[8192]; assert(snprintf(path, sizeof(path), "%s/LICENSE", partial) > 0);
    bool started = false;
    for (size_t i = 0; i < 2000; i++) { if (!lstat(path, &info)) { started = true; break; } usleep(1000); }
    assert(started); assert(!kill(child, SIGTERM)); unsigned char status;
    assert(read(channel[0], &status, 1) == 1); assert(status == CLIQ_NPM_IMAGE_CANCELLED); assert(!close(channel[0]));
    int ended; assert(waitpid(child, &ended, 0) == child && WIFEXITED(ended) && WEXITSTATUS(ended) == 0);
    assert(!close(image)); assert(descriptors() == initial);
    puts("{\"component\":\"fixed-official-npm-materialization\",\"sourceFiles\":2408,\"completeFileHashes\":true,\"realPartialCancelJoined\":true,\"fdDelta\":0,\"installedQualification\":false}");
    return 0;
}
