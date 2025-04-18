#ifdef BUILD_HYPERSCAN

#include "bugon.h"
#include "debug.h"
#include "hash_lookup3.h"
#include "hash_table.h"
#include "hyperscan.h"
#include "mem.h"
#include "mpm.h"
#include "mpm_hs.h"
#include "mpm_hs_core.h"
#include "mpm_hs_cache.h"
#include "mpmcmp.h"
#include "mpm_ctx.h"
#include "mpm_config.h"
#include "mpm_table.h"
#include "optimize.h"
#include "path.h"
#include "prefilter.h"
#include "sig_id.h"
#include "thread_lock.h"
#include "unittest.h"

#include <hs.h>

void SCHSInitCtx(MpmCtx *);
void SCHSInitThreadCtx(MpmCtx *, MpmThreadCtx *);
void SCHSDestroyCtx(MpmCtx *);
void SCHSDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCHSAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCHSAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint8_t);
int SCHSPreparePatterns(MpmConfig *mpm_conf, MpmCtx *mpm_ctx);
uint32_t SCHSSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, const uint32_t buflen);
void SCHSPrintInfo(MpmCtx *mpm_ctx);
void SCHSPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);


/* size of the hash table used to speed up pattern insertions initially */
#define INIT_HASH_SIZE 65536

/* Initial size of the global database hash (used for de-duplication). */
#define INIT_DB_HASH_SIZE 1000

/* Global prototype scratch, built incrementally as Hyperscan databases are
 * built and then cloned for each thread context. Access is serialised via
 * g_scratch_proto_mutex. */
static hs_scratch_t *g_scratch_proto = NULL;
static SCMutex g_scratch_proto_mutex = SCMUTEX_INITIALIZER;

/* Global hash table of Hyperscan databases, used for de-duplication. Access is
 * serialised via g_db_table_mutex. */
static HashTable *g_db_table = NULL;
static SCMutex g_db_table_mutex = SCMUTEX_INITIALIZER;

/**
 * \internal
 * \brief
 */
static void *SCHSMalloc(size_t size)
{
    return malloc(size);
}

/**
 * \internal
 * \brief
 */
static void SCHSFree(void *ptr)
{
    free(ptr);
}

/** \brief Register Suricata malloc/free with Hyperscan.
 *
 * Requests that Hyperscan use Suricata's allocator for allocation of
 * databases, scratch space, etc.
 */
static void SCHSSetAllocators(void)
{
    hs_error_t err = hs_set_allocator(SCHSMalloc, SCHSFree);
    if (err != HS_SUCCESS) {
        FatalError("Failed to set Hyperscan allocator.");
    }
}

/**
 * \internal
 * \brief Creates a hash of the pattern.  We use it for the hashing process
 *        during the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 *
 * \retval hash A 32 bit unsigned hash.
 */
static inline uint32_t SCHSInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

/**
 * \internal
 * \brief Looks up a pattern.  We use it for the hashing process during
 *        the initial pattern insertion time, to cull duplicate sigs.
 *
 * \param ctx    Pointer to the HS ctx.
 * \param pat    Pointer to the pattern.
 * \param patlen Pattern length.
 * \param flags  Flags.  We don't need this.
 *
 * \retval hash A 32 bit unsigned hash.
 * 
 * SCHSPattern -> mpm-hs-core.h에 명시됨
 * bugon.h, mpmcmp.h 사용
 */
static inline SCHSPattern *SCHSInitHashLookup(SCHSCtx *ctx, uint8_t *pat,
                                              uint16_t patlen, uint16_t offset,
                                              uint16_t depth, char flags,
                                              uint32_t pid)
{
    uint32_t hash = SCHSInitHashRaw(pat, patlen);

    if (ctx->init_hash == NULL) {
        return NULL;
    }

    SCHSPattern *t = ctx->init_hash[hash];
    for (; t != NULL; t = t->next) {
        /* Since Hyperscan uses offset/depth, we must distinguish between
         * patterns with the same ID but different offset/depth here. */
        if (t->id == pid && t->offset == offset && t->depth == depth) {
            BUG_ON(t->len != patlen);
            BUG_ON(SCMemcmp(t->original_pat, pat, patlen) != 0);
            return t;
        }
    }

    return NULL;
}

/**
 * \internal
 * \brief Allocates a new pattern instance.
 *
 * \param mpm_ctx Pointer to the mpm context.
 *
 * \retval p Pointer to the newly created pattern.
 * 
 * SCHSPattern -> mpm-hs-core.h에 명시됨
 * mpm.h, mpm_ctx.h, optimize.h 사용
 */
static inline SCHSPattern *SCHSAllocPattern(MpmCtx *mpm_ctx)
{
    SCHSPattern *p = SCCalloc(1, sizeof(SCHSPattern), SCHSPattern);
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCHSPattern);

    return p;
}

/**
 * \internal
 * \brief Used to free SCHSPattern instances.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param p       Pointer to the SCHSPattern instance to be freed.
 * \param free    Free the above pointer or not.
 * 
 * mpm_ctx.h 사용
 */
static inline void SCHSFreePattern(MpmCtx *mpm_ctx, SCHSPattern *p)
{
    if (p != NULL && p->original_pat != NULL) {
        SCFree(p->original_pat);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->sids != NULL) {
        SCFree(p->sids);
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(SCHSPattern);
    }
}


static inline uint32_t SCHSInitHash(SCHSPattern *p)
{
    uint32_t hash = p->len * p->original_pat[0];
    if (p->len > 1)
        hash += p->original_pat[1];

    return (hash % INIT_HASH_SIZE);
}

/**
 * SCHSCtx -> mpm-hs-core.h 사용
 */
static inline int SCHSInitHashAdd(SCHSCtx *ctx, SCHSPattern *p)
{
    uint32_t hash = SCHSInitHash(p);

    if (ctx->init_hash == NULL) {
        return -1;
    }

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    SCHSPattern *tt = NULL;
    SCHSPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}

/**
 * \internal
 * \brief Add a pattern to the mpm-hs context.
 *
 * \param mpm_ctx Mpm context.
 * \param pat     Pointer to the pattern.
 * \param patlen  Length of the pattern.
 * \param pid     Pattern id
 * \param sid     Signature id (internal id).
 * \param flags   Pattern's MPM_PATTERN_* flags.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 * 
 * SigIntId -> 기존 suricata-common.h 사용
 *          -> sig_id.h 사용
 * debug.h 사용
 */
static int SCHSAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                          uint16_t offset, uint16_t depth, uint32_t pid,
                          SigIntId sid, uint8_t flags)
{
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;

    if (offset != 0) {
        flags |= MPM_PATTERN_FLAG_OFFSET;
    }
    if (depth != 0) {
        flags |= MPM_PATTERN_FLAG_DEPTH;
    }

    if (patlen == 0) {
        SCLogWarning("pattern length 0");
        return 0;
    }

    /* check if we have already inserted this pattern */
    SCHSPattern *p =
        SCHSInitHashLookup(ctx, pat, patlen, offset, depth, flags, pid);
    if (p == NULL) {
        SCLogDebug("Allocing new pattern");

        /* p will never be NULL */
        p = SCHSAllocPattern(mpm_ctx);

        p->len = patlen;
        p->flags = flags;
        p->id = pid;

        p->offset = offset;
        p->depth = depth;

        p->original_pat = SCMalloc(patlen, uint8_t);
        if (p->original_pat == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->original_pat, pat, patlen);

        /* put in the pattern hash */
        if (SCHSInitHashAdd(ctx, p) != 0)
            goto error;

        mpm_ctx->pattern_cnt++;

        if (!(mpm_ctx->flags & MPMCTX_FLAGS_NODEPTH)) {
            if (depth) {
                mpm_ctx->maxdepth = MAX(mpm_ctx->maxdepth, depth);
                SCLogDebug("%p: depth %u max %u", mpm_ctx, depth, mpm_ctx->maxdepth);
            } else {
                mpm_ctx->flags |= MPMCTX_FLAGS_NODEPTH;
                mpm_ctx->maxdepth = 0;
                SCLogDebug("%p: alas, no depth for us", mpm_ctx);
            }
        }

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0) {
            mpm_ctx->minlen = patlen;
        } else {
            if (mpm_ctx->minlen > patlen)
                mpm_ctx->minlen = patlen;
        }

        p->sids_size = 1;
        p->sids = SCMalloc(p->sids_size * sizeof(SigIntId), SigIntId);
        BUG_ON(p->sids == NULL);
        p->sids[0] = sid;
    } else {
        /* TODO figure out how we can be called multiple times for the same CTX with the same sid */

        int found = 0;
        uint32_t x = 0;
        for (x = 0; x < p->sids_size; x++) {
            if (p->sids[x] == sid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            SigIntId *sids = SCRealloc(p->sids, (sizeof(SigIntId) * (p->sids_size + 1)), SigIntId);
            BUG_ON(sids == NULL);
            p->sids = sids;
            p->sids[p->sids_size] = sid;
            p->sids_size++;
        }
    }

    return 0;

error:
    SCHSFreePattern(mpm_ctx, p);
    return -1;
}

static SCHSCompileData *CompileDataAlloc(unsigned int pattern_cnt)
{
    SCHSCompileData *cd = SCCalloc(pattern_cnt, sizeof(SCHSCompileData), SCHSCompileData);
    if (cd == NULL) {
        goto error;
    }

    cd->pattern_cnt = pattern_cnt;

    cd->ids = SCCalloc(pattern_cnt, sizeof(unsigned int), unsigned int);
    if (cd->ids == NULL) {
        goto error;
    }

    cd->flags = SCCalloc(pattern_cnt, sizeof(unsigned int), unsigned int);
    if (cd->flags == NULL) {
        goto error;
    }

    cd->expressions = SCCalloc(pattern_cnt, sizeof(char *), char *);
    if (cd->expressions == NULL) {
        goto error;
    }

    cd->ext = SCCalloc(pattern_cnt, sizeof(hs_expr_ext_t *), hs_expr_ext_t *);
    if (cd->ext == NULL) {
        goto error;
    }

    return cd;

error:
    SCLogDebug("SCHSCompileData alloc failed");
    if (cd) {
        SCFree(cd->ids);
        SCFree(cd->flags);
        SCFree(cd->expressions);
        SCFree(cd->ext);
        SCFree(cd);
    }
    return NULL;
}

static void CompileDataFree(SCHSCompileData *cd)
{
    if (cd == NULL) {
        return;
    }

    SCFree(cd->ids);
    SCFree(cd->flags);
    if (cd->expressions) {
        for (unsigned int i = 0; i < cd->pattern_cnt; i++) {
            SCFree(cd->expressions[i]);
        }
        SCFree(cd->expressions);
    }
    if (cd->ext) {
        for (unsigned int i = 0; i < cd->pattern_cnt; i++) {
            SCFree(cd->ext[i]);
        }
        SCFree(cd->ext);
    }
    SCFree(cd);
}

/**
 * hashlittle_safe -> 기존 lookup3.h 사용
 *                 -> hash_lookup3.h 사용
 *                 -> 컴파일 시 util-hash-lookup3.c 필요
 */
static uint32_t SCHSPatternHash(const SCHSPattern *p, uint32_t hash)
{
    BUG_ON(p->original_pat == NULL);
    BUG_ON(p->sids == NULL);

    hash = hashlittle_safe(&p->len, sizeof(p->len), hash);
    hash = hashlittle_safe(&p->flags, sizeof(p->flags), hash);
    hash = hashlittle_safe(p->original_pat, p->len, hash);
    hash = hashlittle_safe(&p->id, sizeof(p->id), hash);
    hash = hashlittle_safe(&p->offset, sizeof(p->offset), hash);
    hash = hashlittle_safe(&p->depth, sizeof(p->depth), hash);
    hash = hashlittle_safe(&p->sids_size, sizeof(p->sids_size), hash);
    hash = hashlittle_safe(p->sids, p->sids_size * sizeof(SigIntId), hash);
    return hash;
}

/* SCMemcmp -> mpm_cmp.h 사용 */
static char SCHSPatternCompare(const SCHSPattern *p1, const SCHSPattern *p2)
{
    if ((p1->len != p2->len) || (p1->flags != p2->flags) ||
        (p1->id != p2->id) || (p1->offset != p2->offset) ||
        (p1->depth != p2->depth) || (p1->sids_size != p2->sids_size)) {
        return 0;
    }

    if (SCMemcmp(p1->original_pat, p2->original_pat, p1->len) != 0) {
        return 0;
    }

    if (SCMemcmp(p1->sids, p2->sids, p1->sids_size * sizeof(p1->sids[0])) !=
        0) {
        return 0;
    }

    return 1;
}

/**
 * PatternDatabase -> 기존 util-mpm-hs-core.h 사용
 * hashword -> 기존 util-hash-lookup3.h, .c에서 사용
 */
static uint32_t PatternDatabaseHash(HashTable *ht, void *data, uint16_t len)
{
    /** 
     * -- cpp error code --
     * const PatternDatabase *pd = data;
     */
    const PatternDatabase *pd = (const PatternDatabase *)data;
    uint32_t hash = 0;
    hash = hashword(&pd->pattern_cnt, 1, hash);

    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        hash = SCHSPatternHash(pd->parray[i], hash);
    }

    hash %= ht->array_size;
    return hash;
}

static char PatternDatabaseCompare(void *data1, uint16_t len1, void *data2,
                                   uint16_t len2)
{
    /**
     * -- cpp error code --
     * const PatternDatabase *pd1 = data1;
     * const PatternDatabase *pd2 = data2;
     */
    const PatternDatabase *pd1 = (const PatternDatabase *)data1;
    const PatternDatabase *pd2 = (const PatternDatabase *)data2;

    if (pd1->pattern_cnt != pd2->pattern_cnt) {
        return 0;
    }

    for (uint32_t i = 0; i < pd1->pattern_cnt; i++) {
        if (SCHSPatternCompare(pd1->parray[i], pd2->parray[i]) == 0) {
            return 0;
        }
    }

    return 1;
}

/**
 * PatternDatabase -> 기존 util-mpm-hs-core.h 사용
 * BUG_ON -> bugon.h 사용
 */
static void PatternDatabaseFree(PatternDatabase *pd)
{
    BUG_ON(pd->ref_cnt != 0);

    if (pd->parray != NULL) {
        for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
            SCHSPattern *p = pd->parray[i];
            if (p != NULL) {
                SCFree(p->original_pat);
                SCFree(p->sids);
                SCFree(p);
            }
        }
        SCFree(pd->parray);
    }

    hs_free_database(pd->hs_db);

    SCFree(pd);
}

static void PatternDatabaseTableFree(void *data)
{
    /* Stub function handed to hash table; actual freeing of PatternDatabase
     * structures is done in MPM destruction when the ref_cnt drops to zero. */
}

/* SCHSPattern -> 기존 util-mpm-hs-core.h 사용 */
static PatternDatabase *PatternDatabaseAlloc(uint32_t pattern_cnt)
{
    PatternDatabase *pd = SCCalloc(1, sizeof(PatternDatabase), PatternDatabase);
    if (pd == NULL) {
        return NULL;
    }
    pd->pattern_cnt = pattern_cnt;
    pd->ref_cnt = 0;
    pd->hs_db = NULL;
    pd->cached = false;

    /* alloc the pattern array */
    pd->parray = (SCHSPattern **)SCCalloc(pd->pattern_cnt, sizeof(SCHSPattern *), SCHSPattern *);
    if (pd->parray == NULL) {
        SCFree(pd);
        return NULL;
    }

    return pd;
}

/**
 * SCHSCtx -> mpm-hs-core.h 사용
 *  MpmCtx -> mpm_ctx.h 사용
 * SCLogDebug -> debug.h 사용
 */
static int HSCheckPatterns(MpmCtx *mpm_ctx, SCHSCtx *ctx)
{
    if (mpm_ctx->pattern_cnt == 0 || ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }
    return 1;
}

/**
 * PatternDatabase -> 기존 util-mpm-hs-core.h 사용
 * SCHSPattern -> 기존 util-mpm-hs-core.h 사용
 */
static void HSPatternArrayPopulate(SCHSCtx *ctx, PatternDatabase *pd)
{
    for (uint32_t i = 0, p = 0; i < INIT_HASH_SIZE; i++) {
        SCHSPattern *node = ctx->init_hash[i];
        SCHSPattern *nnode = NULL;
        while (node != NULL) {
            nnode = node->next;
            node->next = NULL;
            pd->parray[p++] = node;
            node = nnode;
        }
    }
}

static void HSPatternArrayInit(SCHSCtx *ctx, PatternDatabase *pd)
{
    HSPatternArrayPopulate(ctx, pd);
    /* we no longer need the hash, so free its memory */
    SCFree(ctx->init_hash);
    ctx->init_hash = NULL;
}

/**
 * HashTableInit -> hash_table.h 사용
 *               -> 기존 util-hash.c에 정의됨
 *               -> hash_table.c 사용
 */
static int HSGlobalPatternDatabaseInit(void)
{
    if (g_db_table == NULL) {
        g_db_table = HashTableInit(INIT_DB_HASH_SIZE, PatternDatabaseHash,
                                   PatternDatabaseCompare,
                                   PatternDatabaseTableFree);
        if (g_db_table == NULL) {
            return -1;
        }
    }
    return 0;
}

/* SCLogError -> debug.h 사용 */
static void HSLogCompileError(hs_compile_error_t *compile_err)
{
    SCLogError("failed to compile hyperscan database");
    if (compile_err) {
        SCLogError("compile error: %s", compile_err->message);
        hs_free_compile_error(compile_err);
    }
}

/**
 * SCMutexLock, SCMutexUnlock -> 기존 threads.h에 정의됨
 *                            -> thread_lock.h 사용
 */
static int HSScratchAlloc(const hs_database_t *db)
{
    SCMutexLock(&g_scratch_proto_mutex);
    hs_error_t err = hs_alloc_scratch(db, &g_scratch_proto);
    SCMutexUnlock(&g_scratch_proto_mutex);
    if (err != HS_SUCCESS) {
        SCLogError("failed to allocate scratch");
        return -1;
    }
    return 0;
}

/* HSErrorToStr -> 기존 util-mpm-hs-core.h, .c에 정의 */
static int PatternDatabaseGetSize(PatternDatabase *pd, size_t *db_size)
{
    hs_error_t err = hs_database_size(pd->hs_db, db_size);
    if (err != HS_SUCCESS) {
        SCLogError("failed to query database size: %s", HSErrorToStr(err));
        return -1;
    }
    return 0;
}

/* PatternDatabase -> 기존 util-mpm-hs-core.h 사용 */
static void SCHSCleanupOnError(PatternDatabase *pd, SCHSCompileData *cd)
{
    if (pd) {
        PatternDatabaseFree(pd);
    }
    if (cd) {
        CompileDataFree(cd);
    }
}

/* SCHSPattern = mpm-hs-core.h에 명시 */
static int CompileDataExtensionsInit(hs_expr_ext_t **ext, const SCHSPattern *p)
{
    if (p->flags & (MPM_PATTERN_FLAG_OFFSET | MPM_PATTERN_FLAG_DEPTH)) {
        *ext = SCCalloc(1, sizeof(hs_expr_ext_t), hs_expr_ext_t);
        if ((*ext) == NULL) {
            return -1;
        }
        if (p->flags & MPM_PATTERN_FLAG_OFFSET) {
            (*ext)->flags |= HS_EXT_FLAG_MIN_OFFSET;
            (*ext)->min_offset = p->offset + p->len;
        }
        if (p->flags & MPM_PATTERN_FLAG_DEPTH) {
            (*ext)->flags |= HS_EXT_FLAG_MAX_OFFSET;
            (*ext)->max_offset = p->offset + p->depth;
        }
    }

    return 0;
}

/**
 * \brief Initialize the pattern database - try to get existing pd
 * from the global hash table, or load it from disk if caching is enabled.
 *
 * \param PatternDatabase* [in/out] Pointer to the pattern database to use.
 * \param SCHSCompileData* [in] Pointer to the compile data.
 * \retval 0 On success, negative value on failure.
 * 
 * HSHashDb, HSLoadCache -> 기존 util-mpm-hs-cache.h, .c 적용
 */

static int PatternDatabaseGetCached(
        PatternDatabase **pd, SCHSCompileData *cd, const char *cache_dir_path)
{
    /* Check global hash table to see if we've seen this pattern database
     * before, and reuse the Hyperscan database if so. */
    
    /**
     * -- cpp error code --
     * PatternDatabase *pd_cached = HashTableLookup(g_db_table, *pd, 1);
     */
    PatternDatabase *pd_cached = (PatternDatabase *)HashTableLookup(g_db_table, *pd, 1);

    if (pd_cached != NULL) {
        SCLogDebug("Reusing cached database %p with %" PRIu32
                   " patterns (ref_cnt=%" PRIu32 ")",
                   pd_cached->hs_db, pd_cached->pattern_cnt,
                   pd_cached->ref_cnt);
        pd_cached->ref_cnt++;
        PatternDatabaseFree(*pd);
        CompileDataFree(cd);
        *pd = pd_cached;
        return 0;
    } else if (cache_dir_path) {
        pd_cached = *pd;
        uint64_t db_lookup_hash = HSHashDb(pd_cached);
        if (HSLoadCache(&pd_cached->hs_db, db_lookup_hash, cache_dir_path) == 0) {
            pd_cached->ref_cnt = 1;
            pd_cached->cached = true;
            if (HSScratchAlloc(pd_cached->hs_db) != 0) {
                goto recover;
            }
            if (HashTableAdd(g_db_table, pd_cached, 1) < 0) {
                goto recover;
            }
            CompileDataFree(cd);
            return 0;

        recover:
            pd_cached->ref_cnt = 0;
            pd_cached->cached = false;
            return -1;
        }
    }

    return -1; // not cached
}

static int PatternDatabaseCompile(PatternDatabase *pd, SCHSCompileData *cd)
{
    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        const SCHSPattern *p = pd->parray[i];
        cd->ids[i] = i;
        /**
         * 매칭이 한 번 일어나면 그 이후는 무시 
         * (성능 최적화를 위해 다중 매칭을 방지)
         */
        cd->flags[i] = HS_FLAG_SINGLEMATCH;

        /**
         * mpm에서의 대소문자 무시 플래그가 있다면,
         * hs에서의 대소문자 무시 플래그 세우는 파트 
         */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            cd->flags[i] |= HS_FLAG_CASELESS;
        }
        cd->expressions[i] = HSRenderPattern(p->original_pat, p->len);
        if (CompileDataExtensionsInit(&cd->ext[i], p) != 0) {
            return -1;
        }
    }

    hs_compile_error_t *compile_err = NULL;
    hs_error_t err = hs_compile_ext_multi((const char *const *)cd->expressions, cd->flags, cd->ids,
            (const hs_expr_ext_t *const *)cd->ext, cd->pattern_cnt, HS_MODE_BLOCK, NULL, &pd->hs_db,
            &compile_err);
    if (err != HS_SUCCESS) {
        HSLogCompileError(compile_err);
        return -1;
    }

    if (HSScratchAlloc(pd->hs_db) != 0) {
        return -1;
    }

    if (HashTableAdd(g_db_table, pd, 1) < 0) {
        return -1;
    }
    pd->ref_cnt = 1;
    return 0;
}

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_conf Pointer to the generic MPM matcher configuration
 * \param mpm_ctx Pointer to the mpm context.
 * 
 * MpmConfig, MpmCtx -> 기존 util-mpm.h 사용
 *                   -> 각각 mpm_config.h, mpm_ctx.h 사용
 * SCMutexLock, SCMutexUnlock -> thread_lock.h 사용
 */
int SCHSPreparePatterns(MpmConfig *mpm_conf, MpmCtx *mpm_ctx)
{
    const char *cache_path = NULL;

    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;

    if (HSCheckPatterns(mpm_ctx, ctx) == 0) {
        return 0;
    }

    SCHSCompileData *cd = CompileDataAlloc(mpm_ctx->pattern_cnt);
    PatternDatabase *pd = PatternDatabaseAlloc(mpm_ctx->pattern_cnt);
    if (cd == NULL || pd == NULL) {
        goto error;
    }

    HSPatternArrayInit(ctx, pd);
    pd->no_cache = !(mpm_ctx->flags & MPMCTX_FLAGS_CACHE_TO_DISK);
    /* Serialise whole database compilation as a relatively easy way to ensure
     * dedupe is safe. */
    SCMutexLock(&g_db_table_mutex);
    if (HSGlobalPatternDatabaseInit() == -1) {
        SCMutexUnlock(&g_db_table_mutex);
        goto error;
    }

    cache_path = pd->no_cache || !mpm_conf ? NULL : mpm_conf->cache_dir_path;
    if (PatternDatabaseGetCached(&pd, cd, cache_path) == 0 && pd != NULL) {
        ctx->pattern_db = pd;
        if (PatternDatabaseGetSize(pd, &ctx->hs_db_size) != 0) {
            SCMutexUnlock(&g_db_table_mutex);
            goto error;
        }

        if (pd->ref_cnt == 1) {
            // freshly allocated
            mpm_ctx->memory_cnt++;
            mpm_ctx->memory_size += ctx->hs_db_size;
        }
        SCMutexUnlock(&g_db_table_mutex);
        return 0;
    }

    BUG_ON(ctx->pattern_db != NULL); /* already built? */
    BUG_ON(mpm_ctx->pattern_cnt == 0);

    if (PatternDatabaseCompile(pd, cd) != 0) {
        SCMutexUnlock(&g_db_table_mutex);
        goto error;
    }

    ctx->pattern_db = pd;
    if (PatternDatabaseGetSize(pd, &ctx->hs_db_size) != 0) {
        SCMutexUnlock(&g_db_table_mutex);
        goto error;
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += ctx->hs_db_size;

    SCMutexUnlock(&g_db_table_mutex);
    CompileDataFree(cd);
    return 0;

error:
    SCHSCleanupOnError(pd, cd);
    return -1;
}

/**
 * \brief Cache the initialized and compiled ruleset
 * 
 * SCLogDebug -> debug.h 사용
 * SCCreateDirectoryTree -> 기존 util-path.h, .c 사용
 *                       -> path.h 사용
 *                       -> 기존 util-path.c의 내용도 포함
 */
static int SCHSCacheRuleset(MpmConfig *mpm_conf)
{
    if (!mpm_conf || !mpm_conf->cache_dir_path) {
        return -1;
    }

    SCLogDebug("Caching the loaded ruleset to %s", mpm_conf->cache_dir_path);
    if (SCCreateDirectoryTree(mpm_conf->cache_dir_path, true) != 0) {
        SCLogWarning("Failed to create Hyperscan cache folder, make sure "
                     "the  parent folder is writeable "
                     "or adjust sgh-mpm-caching-path setting (%s)",
                mpm_conf->cache_dir_path);
        return -1;
    }
    PatternDatabaseCache pd_stats = { 0 };
    struct HsIteratorData iter_data = { .pd_stats = &pd_stats,
        .cache_path = mpm_conf->cache_dir_path };
    SCMutexLock(&g_db_table_mutex);
    HashTableIterate(g_db_table, HSSaveCacheIterator, &iter_data);
    SCMutexUnlock(&g_db_table_mutex);
    SCLogNotice("Rule group caching - loaded: %u newly cached: %u total cacheable: %u",
            pd_stats.hs_dbs_cache_loaded_cnt, pd_stats.hs_dbs_cache_saved_cnt,
            pd_stats.hs_cacheable_dbs_cnt);
    return 0;
}

/**
 * \brief Init the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * 
 * MpmThreadCtx -> 기존 util-mpm.h 사용
 *              -> mpm_thread_ctx.h 사용
 * SCHSThreadCtx -> 기존 mpm-hs-core.h 사용
 */
void SCHSInitThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    SCHSThreadCtx *ctx = SCCalloc(1, sizeof(SCHSThreadCtx), SCHSThreadCtx);
    if (ctx == NULL) {
        exit(EXIT_FAILURE);
    }
    mpm_thread_ctx->ctx = ctx;

    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(SCHSThreadCtx);

    ctx->scratch = NULL;
    ctx->scratch_size = 0;

    SCMutexLock(&g_scratch_proto_mutex);

    if (g_scratch_proto == NULL) {
        /* There is no scratch prototype: this means that we have not compiled
         * any Hyperscan databases. */
        SCMutexUnlock(&g_scratch_proto_mutex);
        SCLogDebug("No scratch space prototype");
        return;
    }

    hs_error_t err = hs_clone_scratch(g_scratch_proto,
                                      (hs_scratch_t **)&ctx->scratch);

    SCMutexUnlock(&g_scratch_proto_mutex);

    if (err != HS_SUCCESS) {
        FatalError("Unable to clone scratch prototype");
    }

    err = hs_scratch_size(ctx->scratch, &ctx->scratch_size);
    if (err != HS_SUCCESS) {
        FatalError("Unable to query scratch size");
    }

    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += ctx->scratch_size;
}

/**
 * \brief Initialize the HS context.
 *
 * \param mpm_ctx       Mpm context.
 * 
 * SCHSCtx -> mpm-hs-core.h 사용
 * SCHSPattern = mpm-hs-core.h에 명시됨
 */
void SCHSInitCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->ctx != NULL)
        return;

    mpm_ctx->ctx = SCCalloc(1, sizeof(SCHSCtx), SCHSCtx);
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(SCHSCtx);

    /* initialize the hash we use to speed up pattern insertions */
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCCalloc(INIT_HASH_SIZE, sizeof(SCHSPattern *), SCHSPattern *);
    if (ctx->init_hash == NULL) {
        exit(EXIT_FAILURE);
    }
}

/**
 * \brief Destroy the mpm thread context.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * 
 * MpmCtx -> 기존 util-mpm.h 사용
 * SCHSPrintSearchStats -> 현재 .c 정의(비어있음)
 */
void SCHSDestroyThreadCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    SCHSPrintSearchStats(mpm_thread_ctx);

    if (mpm_thread_ctx->ctx != NULL) {
        SCHSThreadCtx *thr_ctx = (SCHSThreadCtx *)mpm_thread_ctx->ctx;

        if (thr_ctx->scratch != NULL) {
            hs_free_scratch(thr_ctx->scratch);
            mpm_thread_ctx->memory_cnt--;
            mpm_thread_ctx->memory_size -= thr_ctx->scratch_size;
        }

        SCFree(mpm_thread_ctx->ctx);
        mpm_thread_ctx->ctx = NULL;
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(SCHSThreadCtx);
    }
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * 
 * HashTableRemove -> 기존 util-hash.h, .c 사용
 *                 -> hash_table.h, .c에 정의
 */
void SCHSDestroyCtx(MpmCtx *mpm_ctx)
{
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash != NULL) {
        SCFree(ctx->init_hash);
        ctx->init_hash = NULL;
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(SCHSPattern *));
    }

    /* Decrement pattern database ref count, and delete it entirely if the
     * count has dropped to zero. */
    SCMutexLock(&g_db_table_mutex);
    PatternDatabase *pd = ctx->pattern_db;
    if (pd) {
        BUG_ON(pd->ref_cnt == 0);
        pd->ref_cnt--;
        if (pd->ref_cnt == 0) {
            HashTableRemove(g_db_table, pd, 1);
            PatternDatabaseFree(pd);
        }
    }
    SCMutexUnlock(&g_db_table_mutex);

    SCFree(mpm_ctx->ctx);
    mpm_ctx->ctx = NULL;
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(SCHSCtx);
}

/** 
 * Hyperscan MPM match event handler 
 * 
 * PrefilterRuleStore -> 기존 util-prefilter.h 사용
 *                    -> prefilter.h 사용
 * PrefilterAddSids -> 기존 util-prefilter.h, .c에 정의됨
 *                  -> prefilter.h, .c 사용
 */
static int SCHSMatchEvent(unsigned int id, unsigned long long from,
                          unsigned long long to, unsigned int flags,
                          void *ctx)
{
    /**
     * cpp error code
     * SCHSCallbackCtx *cctx = ctx;
     */
    SCHSCallbackCtx *cctx = (SCHSCallbackCtx *)ctx;
    PrefilterRuleStore *pmq = cctx->pmq;
    const PatternDatabase *pd = cctx->ctx;
    const SCHSPattern *pat = pd->parray[id];

    SCLogDebug("Hyperscan Match %" PRIu32 ": id=%" PRIu32 " @ %" PRIuMAX
               " (pat id=%" PRIu32 ")",
               cctx->match_count, (uint32_t)id, (uintmax_t)to, pat->id);

    PrefilterAddSids(pmq, pat->sids, pat->sids_size);

    cctx->match_count++;
    return 0;
}

/**
 * \brief The Hyperscan search function.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param pmq            Pointer to the Pattern Matcher Queue to hold
 *                       search matches.
 * \param buf            Buffer to be searched.
 * \param buflen         Buffer length.
 *
 * \retval matches Match count.
 */
uint32_t SCHSSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, const uint32_t buflen)
{
    uint32_t ret = 0;
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;
    SCHSThreadCtx *hs_thread_ctx = (SCHSThreadCtx *)(mpm_thread_ctx->ctx);
    const PatternDatabase *pd = ctx->pattern_db;

    if (unlikely(buflen == 0)) {
        return 0;
    }

    SCHSCallbackCtx cctx = {.pmq = pmq, .ctx = ctx->pattern_db, .match_count = 0};

    /* scratch should have been cloned from g_scratch_proto at thread init. */
    hs_scratch_t *scratch = hs_thread_ctx->scratch;
    BUG_ON(pd->hs_db == NULL);
    BUG_ON(scratch == NULL);

    hs_error_t err = hs_scan(pd->hs_db, (const char *)buf, buflen, 0, scratch,
                             SCHSMatchEvent, &cctx);
    if (err != HS_SUCCESS) {
        /* An error value (other than HS_SCAN_TERMINATED) from hs_scan()
         * indicates that it was passed an invalid database or scratch region,
         * which is not something we can recover from at scan time. */
        SCLogError("Hyperscan returned error %d", err);
        exit(EXIT_FAILURE);
    } else {
        ret = cctx.match_count;
    }

    return ret;
}

/**
 * \brief Add a case insensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patlen  The pattern length.
 * \param offset  The pattern offset.
 * \param depth   The pattern depth.
 * \param pid     The pattern id.
 * \param sid     The pattern signature id.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCHSAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return SCHSAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

/**
 * \brief Add a case sensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patlen  The pattern length.
 * \param offset  The pattern offset.
 * \param depth   The pattern depth.
 * \param pid     The pattern id.
 * \param sid     The pattern signature id.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCHSAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                     uint16_t offset, uint16_t depth, uint32_t pid,
                     SigIntId sid, uint8_t flags)
{
    return SCHSAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

void SCHSPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
}

void SCHSPrintInfo(MpmCtx *mpm_ctx)
{
    SCHSCtx *ctx = (SCHSCtx *)mpm_ctx->ctx;

    printf("MPM HS Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  SCHSCtx:       %" PRIuMAX "\n", (uintmax_t)sizeof(SCHSCtx));
    printf("  SCHSPattern    %" PRIuMAX "\n", (uintmax_t)sizeof(SCHSPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("\n");

    if (ctx) {
        PatternDatabase *pd = ctx->pattern_db;
        char *db_info = NULL;
        if (hs_database_info(pd->hs_db, &db_info) == HS_SUCCESS) {
            printf("HS Database Info: %s\n", db_info);
            SCFree(db_info);
        }
        printf("HS Database Size: %" PRIuMAX " bytes\n",
               (uintmax_t)ctx->hs_db_size);
    }

    printf("\n");
}

static MpmConfig *SCHSConfigInit(void)
{
    MpmConfig *c = SCCalloc(1, sizeof(MpmConfig), MpmConfig);
    return c;
}

static void SCHSConfigDeinit(MpmConfig **c)
{
    if (c != NULL) {
        SCFree(*c);
        (*c) = NULL;
    }
}

static void SCHSConfigCacheDirSet(MpmConfig *c, const char *dir_path)
{
    c->cache_dir_path = dir_path;
}

/************************** Mpm Registration ***************************/

/**
 * \brief Register the Hyperscan MPM.
 */
void MpmHSRegister(void)
{
    mpm_table[MPM_HS].name = "hs";
    mpm_table[MPM_HS].InitCtx = SCHSInitCtx;
    mpm_table[MPM_HS].InitThreadCtx = SCHSInitThreadCtx;
    mpm_table[MPM_HS].DestroyCtx = SCHSDestroyCtx;
    mpm_table[MPM_HS].DestroyThreadCtx = SCHSDestroyThreadCtx;
    mpm_table[MPM_HS].ConfigInit = (void *(*)(void))SCHSConfigInit;
    mpm_table[MPM_HS].ConfigDeinit = (void (*)(void **))SCHSConfigDeinit;
    mpm_table[MPM_HS].ConfigCacheDirSet = (void (*)(void *, const char *))SCHSConfigCacheDirSet;
    mpm_table[MPM_HS].AddPattern = SCHSAddPatternCS;
    mpm_table[MPM_HS].AddPatternNocase = SCHSAddPatternCI;
    mpm_table[MPM_HS].Prepare = (int (*)(void *, MpmCtx *))SCHSPreparePatterns;
    mpm_table[MPM_HS].CacheRuleset = (int (*)(void *))SCHSCacheRuleset;
    mpm_table[MPM_HS].Search = SCHSSearch;
    mpm_table[MPM_HS].PrintCtx = SCHSPrintInfo;
    mpm_table[MPM_HS].PrintThreadCtx = SCHSPrintSearchStats;
#ifdef UNITTESTS
    mpm_table[MPM_HS].RegisterUnittests = SCHSRegisterTests;
#endif
    mpm_table[MPM_HS].feature_flags = MPM_FEATURE_FLAG_DEPTH | MPM_FEATURE_FLAG_OFFSET;
    /* Set Hyperscan memory allocators */
    SCHSSetAllocators();
}

/**
 * \brief Clean up global memory used by all Hyperscan MPM instances.
 *
 * Currently, this is just the global scratch prototype.
 */
void MpmHSGlobalCleanup(void)
{
    SCMutexLock(&g_scratch_proto_mutex);
    if (g_scratch_proto) {
        SCLogDebug("Cleaning up Hyperscan global scratch");
        hs_free_scratch(g_scratch_proto);
        g_scratch_proto = NULL;
    }
    SCMutexUnlock(&g_scratch_proto_mutex);

    SCMutexLock(&g_db_table_mutex);
    if (g_db_table != NULL) {
        SCLogDebug("Clearing Hyperscan database cache");
        HashTableFree(g_db_table);
        g_db_table = NULL;
    }
    SCMutexUnlock(&g_db_table_mutex);
}

/*************************************Unittests********************************/

#ifdef UNITTESTS

/* 단일 case-sensitive 문자열 "abcd"가 입력 버퍼에서 매칭되는지 확인 */
static int SCHSTest01(void)
{
    int result = 0;
    /* MPM 컨텍스트, 스레드 컨텍스트, 룰 저장소 초기화 */
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /**
     * 1 match 
     * 대소문자 구분 등록
     */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    /* 룰 ID를 담는 prefilter용 rule set 초기화 */
    PmqSetup(&pmq);

    /* Hyperscan DB 컴파일 및 scratch space 준비 */
    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";

    /* 매칭 */
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 등록한 패턴이 입력 버퍼와 일치하지 않을 경우, Hyperscan 매칭 결과가 0임을 확인하는 비매칭 테스트 */
static int SCHSTest02(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 여러 개의 서로 다른 패턴을 등록하고, 입력 버퍼에서 모두 정확히 매칭되는지 확인 */
static int SCHSTest03(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);
    
    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 여러 개의 패턴 중 하나만 매칭되는 경우 테스트 */
static int SCHSTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 대소문자를 구분하지 않는 패턴들이 모두 매칭되는지 검증하는 테스트 */
static int SCHSTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/**
 * 패턴과 입력이 동일할 때 매칭이 되는지 테스트 (test1과 buf가 다름) 
 * 일반 리터럴은 DFA/NFA 구조를 사용해 처리
 */
static int SCHSTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcd";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 중첩된 다양한 길이의 반복 문자열 패턴 매칭 테스트 */
static int SCHSTest07(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* should match 30 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30,
                    0, 0, 5, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 6)
        result = 1;
    else
        printf("6 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 매칭되지 않아야 하는 케이스 테스트 */
static int SCHSTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    uint32_t cnt =
        SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 정확히 일치하는 짧은 패턴 매칭 테스트 */
static int SCHSTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    uint32_t cnt =
        SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 큰 텍스트 블록 내에서의 입력이 매칭되는지 테스트 */
static int SCHSTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 서로 중첩되거나 접두/접미 관계에 있는 문자열 등록 및 테스트 */
static int SCHSTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    const char *buf = NULL;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq);

    if (SCHSPreparePatterns(NULL, &mpm_ctx) == -1)
        goto end;

    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    result = 1;

    /* 기대 매칭: "he" → 1건 */
    buf = "he";
    result &= (SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);

    /* 기대 매칭: "he", "she" → 2건 */
    buf = "she";
    result &= (SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);

    /* 기대 매칭: "his" → 1건 */
    buf = "his";
    result &= (SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 1);

    /* 기대 매칭: "he", "hers" → 2건 */
    buf = "hers";
    result &= (SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                          strlen(buf)) == 2);

end:
    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 겹치는 문자열 패턴 테스트 */
static int SCHSTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 긴 문자열을 정확히 매칭하는지 테스트 (긴 헤더/본문 필터링 하는지) */
static int SCHSTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test13과 동일한 테스트 (한 글자 추가됨) */
static int SCHSTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test13과 동일한 테스트 (한 글자 추가됨) */
static int SCHSTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test13과 동일한 테스트 (단, test13 보다 한 글자 적음)*/
static int SCHSTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test13과 동일한 테스트 (단, test13 보다 두 글자 적음) */
static int SCHSTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test13과 동일한 테스트 (26자) */
static int SCHSTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    const char pat[] = "abcde"
                       "fghij"
                       "klmno"
                       "pqrst"
                       "uvwxy"
                       "z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcde"
                "fghij"
                "klmno"
                "pqrst"
                "uvwxy"
                "z";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 긴 문자열이 들어오면 Hyperscan이 내부적으로 다르게 처리하는지 테스트 */
static int SCHSTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 */
    const char pat[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/**
 * test19와 동일한 테스트
 * Hyperscan은 리터럴 길이가 32바이트 이상이면 내부적으로 DFA/NFA 경로를 사용하지 않고,
 * "Large Literal Matcher (LLM)" 라는 특수 최적화 경로로 분기
 */
static int SCHSTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 */
    const char pat[] = "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "AAAAA"
                "AAAAA"
                "AAAAA"
                "AAAAA"
                "AAAAA"
                "AAAAA"
                "AA";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/**
 * test6과 동일 
 * 짧은 반복 리터럴은 Hyperscan에서 "short literal matcher" 라는 빠른 매칭 경로로 처리
 */
static int SCHSTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    uint32_t cnt =
        SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 부분 중첩된 패턴이 모두 탐지되는지 테스트 */
static int SCHSTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 정확히 같은 문자와 대소문자만 매칭되는지 테스트 */
static int SCHSTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    uint32_t cnt =
        SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test23과 동일한 테스트 (단, 대소문자 무시) */
static int SCHSTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    uint32_t cnt =
        SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 대소문자 무시해 모든 패턴이 매칭되는지 테스트 */
static int SCHSTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 패턴을 대소문자 무시/구분으로 등록 후 매칭하는 테스트 */
static int SCHSTest26(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "works";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* 대소문자 구분으로 패턴 등록 후 테스트 */
static int SCHSTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "tone";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/* test27과 동일한 테스트 */
static int SCHSTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_HS);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCHSPreparePatterns(NULL, &mpm_ctx);
    SCHSInitThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    const char *buf = "tONE";
    uint32_t cnt = SCHSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf,
                              strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCHSDestroyCtx(&mpm_ctx);
    SCHSDestroyThreadCtx(&mpm_ctx, &mpm_thread_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);
    return result;
}

/**
 * test27, 28과 반대로 대소문자 무시해 패턴 등록 후,
 * 패턴과 매칭되는지 테스트
 * (원본 test29와 다름 원본은 suricata end-to-end test)
 */
static int SCHSTest29(void)
{
    int result = 0;

    /* 테스트 대상 입력 버퍼 */
    uint8_t *test_payload = (uint8_t *)"UNION SELECT username, password FROM users";
    uint32_t test_len = (uint32_t)strlen((char *)test_payload);

    /* MPM 컨텍스트 및 초기화 */
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    SCHSInitCtx(&mpm_ctx);

    /* 패턴 등록 (대소문자 무시) */
    const char *pattern = "select";
    int ret = SCHSAddPatternCI(&mpm_ctx, (uint8_t *)pattern, (uint16_t)strlen(pattern),
                               0, 0, 1, 0, MPM_PATTERN_FLAG_NOCASE);
    if (ret != 0) {
        printf("SCHSTest29: Pattern 추가 실패\n");
        return 0;
    }

    /* Hyperscan DB 컴파일 */
    if (SCHSPreparePatterns(NULL, &mpm_ctx) != 0) {
        printf("SCHSTest29: DB 컴파일 실패\n");
        SCHSDestroyCtx(&mpm_ctx);
        return 0;
    }

    /* 쓰레드 컨텍스트 초기화 */
    MpmThreadCtx tctx;
    memset(&tctx, 0, sizeof(MpmThreadCtx));
    SCHSInitThreadCtx(&mpm_ctx, &tctx);

    /* PreFilterRuleStore 설정 */
    PrefilterRuleStore pmq;
    memset(&pmq, 0, sizeof(PrefilterRuleStore));
    PmqSetup(&pmq);

    /* 매칭 수행 */
    uint32_t match = SCHSSearch(&mpm_ctx, &tctx, &pmq, test_payload, test_len);

    /* 자원 해제 */
    SCHSDestroyThreadCtx(&mpm_ctx, &tctx);
    SCHSDestroyCtx(&mpm_ctx);

    /* 스택 변수이므로 해제 말고 초기화만 */
    //PmqFree(&pmq);
    PmqCleanup(&pmq);

    /* 결과 평가 */
    if (match > 0) {
        printf("SCHSTest29 패턴 매칭 성공 (match=%u)\n", match);
        result = 1;
    } else {
        printf("SCHSTest29 패턴 매칭 실패\n");
    }

    return result;
}


// static int SCHSTest29(void)
// {
//     uint8_t buf[] = "onetwothreefourfivesixseveneightnine";
//     uint16_t buflen = sizeof(buf) - 1;
//     Packet *p = NULL;
//     ThreadVars th_v;
//     DetectEngineThreadCtx *det_ctx = NULL;
//     int result = 0;

//     memset(&th_v, 0, sizeof(th_v));
//     p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

//     DetectEngineCtx *de_ctx = DetectEngineCtxInit();
//     if (de_ctx == NULL)
//         goto end;
//     de_ctx->mpm_matcher = MPM_HS;

//     de_ctx->flags |= DE_QUIET;

//     de_ctx->sig_list = SigInit(
//         de_ctx, "alert tcp any any -> any any "
//                 "(content:\"onetwothreefourfivesixseveneightnine\"; sid:1;)");
//     if (de_ctx->sig_list == NULL)
//         goto end;
//     de_ctx->sig_list->next =
//         SigInit(de_ctx, "alert tcp any any -> any any "
//                         "(content:\"onetwothreefourfivesixseveneightnine\"; "
//                         "fast_pattern:3,3; sid:2;)");
//     if (de_ctx->sig_list->next == NULL)
//         goto end;

//     SigGroupBuild(de_ctx);
//     DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

//     SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
//     if (PacketAlertCheck(p, 1) != 1) {
//         printf("if (PacketAlertCheck(p, 1) != 1) failure\n");
//         goto end;
//     }
//     if (PacketAlertCheck(p, 2) != 1) {
//         printf("if (PacketAlertCheck(p, 1) != 2) failure\n");
//         goto end;
//     }

//     result = 1;
// end:
//     if (de_ctx != NULL) {
//         SigGroupCleanup(de_ctx);
//         SigCleanSignatures(de_ctx);

//         DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
//         DetectEngineCtxFree(de_ctx);
//     }

//     UTHFreePackets(&p, 1);
//     return result;
// }

void SCHSRegisterTests(void)
{
    UtRegisterTest("SCHSTest01", SCHSTest01);
    UtRegisterTest("SCHSTest02", SCHSTest02);
    UtRegisterTest("SCHSTest03", SCHSTest03);
    UtRegisterTest("SCHSTest04", SCHSTest04);
    UtRegisterTest("SCHSTest05", SCHSTest05);
    UtRegisterTest("SCHSTest06", SCHSTest06);
    UtRegisterTest("SCHSTest07", SCHSTest07);
    UtRegisterTest("SCHSTest08", SCHSTest08);
    UtRegisterTest("SCHSTest09", SCHSTest09);
    UtRegisterTest("SCHSTest10", SCHSTest10);
    UtRegisterTest("SCHSTest11", SCHSTest11);
    UtRegisterTest("SCHSTest12", SCHSTest12);
    UtRegisterTest("SCHSTest13", SCHSTest13);
    UtRegisterTest("SCHSTest14", SCHSTest14);
    UtRegisterTest("SCHSTest15", SCHSTest15);
    UtRegisterTest("SCHSTest16", SCHSTest16);
    UtRegisterTest("SCHSTest17", SCHSTest17);
    UtRegisterTest("SCHSTest18", SCHSTest18);
    UtRegisterTest("SCHSTest19", SCHSTest19);
    UtRegisterTest("SCHSTest20", SCHSTest20);
    UtRegisterTest("SCHSTest21", SCHSTest21);
    UtRegisterTest("SCHSTest22", SCHSTest22);
    UtRegisterTest("SCHSTest23", SCHSTest23);
    UtRegisterTest("SCHSTest24", SCHSTest24);
    UtRegisterTest("SCHSTest25", SCHSTest25);
    UtRegisterTest("SCHSTest26", SCHSTest26);
    UtRegisterTest("SCHSTest27", SCHSTest27);
    UtRegisterTest("SCHSTest28", SCHSTest28);
    UtRegisterTest("SCHSTest29", SCHSTest29);
}
#endif /* UNITTESTS */
#endif /* BUILD_HYPERSCAN */
