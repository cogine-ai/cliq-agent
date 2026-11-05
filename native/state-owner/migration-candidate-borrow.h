#ifndef CLIQ_MIGRATION_CANDIDATE_BORROW_H
#define CLIQ_MIGRATION_CANDIDATE_BORROW_H
/* Private same-translation-unit friendship. No caller FD/path/Boolean enters
 * these functions; the genuine parent produces all four actual observations. */
typedef struct migration_filesystem migration_filesystem;
typedef struct {
    int image_fd;
    struct stat image;
    uint64_t byte_count;
    char full_digest[65];
} migration_candidate_borrow;
static int migrate_scope_borrow_candidate(migration_filesystem *scope, napi_env env,
    migration_candidate_borrow *borrow);
static int migrate_scope_check_candidate(migration_filesystem *scope, napi_env env,
    const migration_candidate_borrow *borrow);
static int migrate_scope_release_candidate(migration_filesystem *scope, napi_env env,
    migration_candidate_borrow *borrow);
#endif
