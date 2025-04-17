#ifndef STANDALONE_MPM_HS_CORE_H
#define STANDALONE_MPM_HS_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <hs.h>            /* Hyperscan API */
#include "sig_id.h"        /* SigIntId 정의 */
#include "prefilter.h"     /* PrefilterRuleStore 정의 */

/**
 * Single Hyperscan pattern definition.
 */
typedef struct SCHSPattern_ {
    uint16_t len;
    uint8_t flags;
    uint8_t *original_pat;
    uint32_t id;

    uint16_t offset;
    uint16_t depth;

    uint32_t sids_size;
    SigIntId *sids;

    struct SCHSPattern_ *next;
} SCHSPattern;

/**
 * A compiled pattern database instance with reference counting.
 */
typedef struct PatternDatabase_ {
    SCHSPattern **parray;     /* pattern 배열 */
    hs_database_t *hs_db;     /* Hyperscan DB */
    uint32_t pattern_cnt;

    uint32_t ref_cnt;
    bool cached;
    bool no_cache;
} PatternDatabase;

/**
 * Hyperscan 엔진 전체 컨텍스트.
 */
typedef struct SCHSCtx_ {
    SCHSPattern **init_hash;
    PatternDatabase *pattern_db;
    size_t hs_db_size;
} SCHSCtx;

/**
 * Hyperscan thread-local scratch context.
 */
typedef struct SCHSThreadCtx_ {
    hs_scratch_t *scratch;
    size_t scratch_size;
} SCHSThreadCtx;

/**
 * Hyperscan 콜백 컨텍스트.
 * - PrefilterRuleStore: 탐지된 룰 ID 저장
 * - PatternDatabase: 매칭된 DB 참조
 */
typedef struct SCHSCallbackCtx_ {
    PrefilterRuleStore *pmq;
    PatternDatabase *ctx;
    uint32_t match_count;
} SCHSCallbackCtx;

/**
 * Hyperscan DB 캐시 통계.
 */
typedef struct PatternDatabaseCache_ {
    uint32_t hs_cacheable_dbs_cnt;
    uint32_t hs_dbs_cache_loaded_cnt;
    uint32_t hs_dbs_cache_saved_cnt;
} PatternDatabaseCache;

/**
 * \brief Pattern database information used only as input to the Hyperscan
 *
 * 정규표현식 컴파일용 구조체.
 * - 여러 패턴들을 Hyperscan으로 컴파일할 때 사용
 */
typedef struct SCHSCompileData_ {
    uint32_t pattern_cnt;
    uint32_t *ids;
    uint32_t *flags;
    char **expressions;
    hs_expr_ext_t **ext;
} SCHSCompileData;

/**
 * Hyperscan 오류 코드 → 문자열 변환 함수
 */
const char *HSErrorToStr(hs_error_t error_code);

#endif /* MPM_HS_CORE_H */
