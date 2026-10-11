/*
 * Test-only loading-mechanism probe. This is not a credential VFS: it neither
 * protects descriptors nor supplies a production storage authority.
 *
 * SQLite calls use only the API table supplied by Node's extension loader.
 * Do not link this probe to another SQLite library.
 */
#include <node_api.h>
#include <sqlite3ext.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

SQLITE_EXTENSION_INIT1

#if defined(_WIN32)
#define CLIQ_PROBE_EXPORT __declspec(dllexport)
#else
#define CLIQ_PROBE_EXPORT __attribute__((visibility("default")))
#endif

static int initialized = 0;
static int private_registered = 0;
static sqlite3_vfs *base_vfs = NULL;
static sqlite3_vfs private_vfs;
static atomic_uint main_opens = 0;
static atomic_uint open_calls = 0;
static const char private_vfs_name[] = "cliq-sqlite-vfs-mechanism-v1";

/* Deliberately do not open anything. This callback proves routing and code
 * lifetime, not database I/O or descriptor protection. */
static int diagnostic_open(sqlite3_vfs *vfs, sqlite3_filename name,
                           sqlite3_file *file, int flags, int *out_flags) {
  static const char marker[] = "CLIQ_SQLITE_VFS_MECHANISM_OPEN\n";
  (void)vfs;
  (void)name;
  file->pMethods = NULL;
  if (out_flags != NULL) {
    *out_flags = 0;
  }
  atomic_fetch_add_explicit(&open_calls, 1, memory_order_relaxed);
  if ((flags & SQLITE_OPEN_MAIN_DB) != 0) {
    atomic_fetch_add_explicit(&main_opens, 1, memory_order_relaxed);
  }
  (void)write(STDERR_FILENO, marker, sizeof(marker) - 1);
  return SQLITE_CANTOPEN;
}

static int diagnostic_full_path(sqlite3_vfs *vfs, const char *name,
                                int output_size, char *output) {
  size_t length;
  (void)vfs;
  if (name == NULL || output == NULL || output_size <= 0) {
    return SQLITE_CANTOPEN;
  }
  for (length = 0; length < (size_t)output_size; ++length) {
    if (name[length] == '\0') {
      memcpy(output, name, length + 1);
      return SQLITE_OK;
    }
  }
  return SQLITE_CANTOPEN;
}

static int diagnostic_delete(sqlite3_vfs *vfs, const char *name,
                             int sync_directory) {
  (void)vfs;
  (void)name;
  (void)sync_directory;
  return SQLITE_IOERR_DELETE;
}

static int diagnostic_access(sqlite3_vfs *vfs, const char *name, int flags,
                             int *result) {
  (void)vfs;
  (void)name;
  (void)flags;
  *result = 0;
  return SQLITE_OK;
}

static int initialize_api(const sqlite3_api_routines *api) {
  if (api == NULL || api->sourceid == NULL || api->vfs_find == NULL ||
      api->vfs_register == NULL ||
      (initialized && sqlite3_api != api)) {
    return SQLITE_ERROR;
  }
  if (initialized) {
    return SQLITE_OK;
  }
  SQLITE_EXTENSION_INIT2(api);
  base_vfs = sqlite3_vfs_find(NULL);
  if (base_vfs == NULL || base_vfs->szOsFile < (int)sizeof(sqlite3_file) ||
      base_vfs->mxPathname <= 0) {
    return SQLITE_ERROR;
  }
  initialized = 1;
  return SQLITE_OK;
}

static int register_private_vfs(void) {
  int result;
  if (private_registered) {
    return sqlite3_vfs_find(private_vfs_name) == &private_vfs
               ? SQLITE_OK
               : SQLITE_ERROR;
  }
  if (sqlite3_vfs_find(private_vfs_name) != NULL) {
    return SQLITE_ERROR;
  }
  private_vfs = *base_vfs;
  private_vfs.pNext = NULL;
  private_vfs.zName = private_vfs_name;
  private_vfs.xOpen = diagnostic_open;
  private_vfs.xFullPathname = diagnostic_full_path;
  private_vfs.xDelete = diagnostic_delete;
  private_vfs.xAccess = diagnostic_access;
  result = sqlite3_vfs_register(&private_vfs, 0);
  if (result == SQLITE_OK) {
    private_registered = 1;
  }
  return result;
}

CLIQ_PROBE_EXPORT int sqlite3_cliqvfsmechanism_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  int result;
  (void)database;
  (void)error;
  result = initialize_api(api);
  if (result == SQLITE_OK) {
    result = register_private_vfs();
  }
  return result == SQLITE_OK ? SQLITE_OK_LOAD_PERMANENTLY : result;
}

/* No VFS is registered by the scoped entry point, so unloading it cannot
 * leave SQLite with a callback into an unmapped image. */
CLIQ_PROBE_EXPORT int sqlite3_cliqvfsscopemechanism_init(
    sqlite3 *database, char **error, const sqlite3_api_routines *api) {
  (void)database;
  (void)error;
  return initialize_api(api);
}

static napi_status set_boolean(napi_env env, napi_value object,
                               const char *name, int value) {
  napi_value property;
  napi_status result = napi_get_boolean(env, value != 0, &property);
  return result == napi_ok
             ? napi_set_named_property(env, object, name, property)
             : result;
}

static napi_status set_number(napi_env env, napi_value object,
                              const char *name, double value) {
  napi_value property;
  napi_status result = napi_create_double(env, value, &property);
  return result == napi_ok
             ? napi_set_named_property(env, object, name, property)
             : result;
}

static napi_status set_source_id(napi_env env, napi_value object) {
  napi_value property;
  napi_status result = initialized
                           ? napi_create_string_utf8(
                                 env, sqlite3_sourceid(), NAPI_AUTO_LENGTH,
                                 &property)
                           : napi_get_null(env, &property);
  return result == napi_ok
             ? napi_set_named_property(env, object, "sourceId", property)
             : result;
}

static napi_value observe(napi_env env, napi_callback_info info) {
  napi_value result;
  (void)info;
  if (napi_create_object(env, &result) != napi_ok ||
      set_boolean(env, result, "initialized", initialized) != napi_ok ||
      set_number(env, result, "mainOpens",
                 atomic_load_explicit(&main_opens, memory_order_relaxed)) !=
          napi_ok ||
      set_number(env, result, "totalOpens",
                 atomic_load_explicit(&open_calls, memory_order_relaxed)) !=
          napi_ok ||
      set_boolean(env, result, "defaultUnchanged",
                  !initialized || sqlite3_vfs_find(NULL) == base_vfs) !=
          napi_ok ||
      set_boolean(env, result, "privateRegistered",
                  private_registered &&
                      sqlite3_vfs_find(private_vfs_name) == &private_vfs) !=
          napi_ok ||
      set_source_id(env, result) != napi_ok) {
    return NULL;
  }
  return result;
}

static napi_value initialize_napi(napi_env env, napi_value exports) {
  napi_value method;
  if (napi_create_function(env, "observe", NAPI_AUTO_LENGTH, observe, NULL,
                           &method) != napi_ok ||
      napi_set_named_property(env, exports, "observe", method) != napi_ok) {
    return NULL;
  }
  return exports;
}

NAPI_MODULE(cliq_sqlite_vfs_mechanism_probe, initialize_napi)
