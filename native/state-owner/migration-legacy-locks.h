#ifndef CLIQ_MIGRATION_LEGACY_LOCKS_H
#define CLIQ_MIGRATION_LEGACY_LOCKS_H
/* Private methods of the existing original MigrationFilesystem, not a second
 * authority object. Include this declaration before that scope's definition. */
typedef struct migration_legacy_locks migration_legacy_locks;
static int migrate_legacy_locks_custody(migration_filesystem *scope);
static int migrate_legacy_locks_validate(migration_filesystem *scope);
static int migrate_legacy_locks_ready(migration_filesystem *scope);
static int migrate_legacy_locks_assert_current(migration_filesystem *scope);
static int migrate_legacy_locks_owns(migration_filesystem *scope, const struct stat *identity);
static int migrate_legacy_locks_can_retire(migration_filesystem *scope);
static void migrate_legacy_locks_free(migration_filesystem *scope);
static napi_value migrate_legacy_locks_prepare_next(napi_env env, napi_callback_info info);
static napi_value migrate_legacy_locks_assert(napi_env env, napi_callback_info info);
static napi_value migrate_legacy_locks_release(napi_env env, napi_callback_info info);
#endif
