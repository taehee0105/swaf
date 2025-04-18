/* Hyperscan DB 구성, 매칭 관리 */

#ifndef SWAF_MPM_HS_CORE_H
#define SWAF_MPM_HS_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <hs.h>

#include "prefilter.h"
#include "sig_id.h"

/* 단일 Hyperscan 패턴을 표현하는 구조체 */
typedef struct SCHSPattern_ {
    uint16_t len;                 /* 패턴 길이 */
    uint8_t flags;                /* 패턴 플래그 (nocase 등) */
    uint8_t *original_pat;        /* 원본 패턴 문자열 */
    uint32_t id;                  /* 내부 ID */

    uint16_t offset;              /* 탐지 시작 오프셋 */
    uint16_t depth;               /* 탐지 종료 지점 */

    uint32_t sids_size;           /* 시그니처 ID 개수 */
    SigIntId *sids;               /* 시그니처 ID 배열 */

    struct SCHSPattern_ *next;    /* 연결 리스트 용 포인터 */
} SCHSPattern;

/* Hyperscan DB와 그에 연결된 패턴 목록을 담는 구조체 */
typedef struct PatternDatabase_ {
    SCHSPattern **parray;         /* 패턴 포인터 배열 */
    hs_database_t *hs_db;         /* Hyperscan 컴파일된 DB */
    uint32_t pattern_cnt;         /* 총 패턴 수 */

    uint32_t ref_cnt;             /* 참조 카운터 (공유될 경우) */
    bool cached;                  /* 캐시로부터 불러온 경우 */
    bool no_cache;                /* 캐시 비활성화 여부 */
} PatternDatabase;

/* Hyperscan 엔진 전역 컨텍스트 */
typedef struct SCHSCtx_ {
    SCHSPattern **init_hash;      /* 패턴 삽입 시 해시 배열 */
    PatternDatabase *pattern_db;  /* 최종 Hyperscan DB 참조 */
    size_t hs_db_size;            /* Hyperscan DB 크기 */
} SCHSCtx;

/* Hyperscan 쓰레드별 scratch 영역 컨텍스트 */
typedef struct SCHSThreadCtx_ {
    hs_scratch_t *scratch;        /* 쓰레드 전용 scratch 공간 */
    size_t scratch_size;          /* scratch 메모리 크기 */
} SCHSThreadCtx;

/* Hyperscan 콜백에서 사용하는 컨텍스트 */
typedef struct SCHSCallbackCtx_ {
    PrefilterRuleStore *pmq;      /* 탐지된 시그니처 ID 저장소 */
    PatternDatabase *ctx;         /* 현재 매칭 대상 DB */
    uint32_t match_count;         /* 총 매칭 횟수 */
} SCHSCallbackCtx;

/* Hyperscan DB 캐시 관련 통계 정보 */
typedef struct PatternDatabaseCache_ {
    uint32_t hs_cacheable_dbs_cnt;      /* 캐시 가능한 DB 수 */
    uint32_t hs_dbs_cache_loaded_cnt;   /* 캐시에서 로드된 DB 수 */
    uint32_t hs_dbs_cache_saved_cnt;    /* 디스크에 저장된 DB 수 */
} PatternDatabaseCache;

/**
 * Hyperscan 컴파일 시 사용하는 중간 데이터 구조체
 * - 여러 패턴들을 컴파일할 때 사용됨
 */
typedef struct SCHSCompileData_ {
    uint32_t pattern_cnt;         /* 패턴 수 */
    uint32_t *ids;                /* 각 패턴의 ID 배열 */
    uint32_t *flags;              /* 각 패턴의 플래그 배열 */
    char **expressions;           /* 정규표현식 문자열 배열 */
    hs_expr_ext_t **ext;          /* 각 패턴의 컴파일 확장 옵션 */
} SCHSCompileData;

/* Hyperscan 오류 코드 → 사람이 읽을 수 있는 문자열로 변환 */
const char *HSErrorToStr(hs_error_t error_code);

#endif /* SWAF_MPM_HS_CORE_H */