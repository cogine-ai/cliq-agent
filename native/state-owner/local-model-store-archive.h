/* C-private bridge for the existing original kernel archive holder. No
 * descriptor, path selector, NAPI callback, SQLite engine or execution
 * authority is returned. Include before kernel-archive.c; implementation is
 * included by local-model-store.c in the same signed translation unit. */
#ifndef CLIQ_LOCAL_MODEL_STORE_ARCHIVE_H
#define CLIQ_LOCAL_MODEL_STORE_ARCHIVE_H
typedef struct cliq_model_store_archive cliq_model_store_archive;
enum cliq_model_store_archive_kind {
  CLIQ_MODEL_STORE_REGISTRY = 1, CLIQ_MODEL_STORE_JOURNAL = 2,
  CLIQ_MODEL_STORE_LOCK = 3, CLIQ_MODEL_STORE_OBJECT = 4, CLIQ_MODEL_STORE_TEMPORARY = 5
};
struct cliq_model_store_archive_entry {
  char relative_path[160];
  enum cliq_model_store_archive_kind kind;
  struct stat identity;
};
struct cliq_model_store_archive_directories { struct stat store, objects; };
/* Main-thread begin: the exact original migration binding must equal the
 * model scope's separate EX-derived source. No pager/source may be live.
 * The scope is strongly retained and cannot close until main-thread end. */
static inline int cliq_model_store_archive_begin(napi_env env, napi_value model_scope,
  migration_credential_gate *original, cliq_model_store_archive **output);
/* Worker-safe, only under the original archive owner's own mutex/lifetime.
 * No NAPI, mutable StateOwner bookkeeping, clock or thread authority is read. */
static inline int cliq_model_store_archive_assert(cliq_model_store_archive *source);
static inline int cliq_model_store_archive_directories(cliq_model_store_archive *source,
  struct cliq_model_store_archive_directories *directories);
/* 1=one captured fixed entry, 0=complete, -1=refused. A byte pass consumes the
 * full current entry and close_current before advancing. A metadata-only
 * census explicitly finish_metadata instead; it proves no bytes were read.
 * Names are never authority. */
static inline int cliq_model_store_archive_next(cliq_model_store_archive *source,
  struct cliq_model_store_archive_entry *entry);
static inline int cliq_model_store_archive_read(cliq_model_store_archive *source,
  unsigned char bytes[65536], size_t *size);
/* Original registry/journal/lock FD leases are ended, never dup/closed here;
 * their same model-store owner retains the pending-byte guards. Original
 * object/scanner descriptions opened by this visitor are actually closed. */
static inline int cliq_model_store_archive_close_current(cliq_model_store_archive *source);
/* Metadata-only census: validates the exact current named/held identity and
 * actually consumes this visitor's description/lease. Never a full-read,
 * hash, unchanged-content or successful-snapshot proof. Only the archive's
 * previous complete hash plus original metadata/all-and-only comparison can
 * justify its final census. The returned identity remains next()'s sample. */
static inline int cliq_model_store_archive_finish_metadata(cliq_model_store_archive *source);
/* A second full enumeration is available to the owning archive's all-and-only
 * metadata/index verification. It is not a second snapshot or pager. */
static inline int cliq_model_store_archive_rewind(cliq_model_store_archive *source);
/* Main-thread only, after the actual archive worker join. Uncertain close or
 * custody retains both this source and its original model-store/EX reference. */
static inline int cliq_model_store_archive_end(napi_env env, cliq_model_store_archive *source);
/* Data failure/cancellation only, after the owning worker has really joined.
 * It verifies original custody and consumes owned descriptions without
 * blessing changed snapshot bytes or permitting any resumed store operation.
 * A physical close/identity uncertainty still retains the original borrow. */
static inline int cliq_model_store_archive_cancel(napi_env env, cliq_model_store_archive *source);
#endif
