#ifndef MPM_HS_CACHE_H
#define MPM_HS_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <hs.h>

#include "hash_lookup3.h" /* for hashlittle2_safe */
#include "hash_table.h"
#include "debug.h"        /* for SCLogDebug, SCLogWarning */
#include "mem.h"          /* for SCMalloc, SCFree */
#include "path.h"         /* for SCPathExists, PathMerge */
#include "util-mpm-hs-core.h"  /* for PatternDatabase, PatternDatabaseCache */

/**
 * Iterator context for saving Hyperscan DBs to cache.
 */
typedef struct HsIteratorData {
    PatternDatabaseCache *pd_stats;
    const char *cache_path;
} HsIteratorData;

/**
 * Load Hyperscan DB from disk cache.
 *
 * @param hs_db pointer to the deserialized Hyperscan database
 * @param hs_db_hash unique hash of the pattern database
 * @param dirpath directory containing the cache file
 * @return 0 on success, -1 on failure
 */
int HSLoadCache(hs_database_t **hs_db, uint64_t hs_db_hash, const char *dirpath);

/**
 * Compute a 64-bit hash representing the PatternDatabase.
 * Used for determining cache file name.
 */
uint64_t HSHashDb(const PatternDatabase *pd);

/**
 * Save Hyperscan DB to cache using iterator pattern.
 */
void HSSaveCacheIterator(void *data, void *aux);

#endif // MPM_HS_CACHE_H
