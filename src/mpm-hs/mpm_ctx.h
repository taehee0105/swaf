/* MPM 구성 컨텍스트 헤더 */

#ifndef SWAF_MPM_CTX_H
#define SWAF_MPM_CTX_H

#include <stdint.h>
#include <hs/hs.h>

#include "sig_id.h"

/* 패턴 플래그 정의 */
#define MPM_PATTERN_FLAG_NOCASE    0x01
#define MPM_PATTERN_FLAG_DEPTH     0x04
#define MPM_PATTERN_FLAG_OFFSET    0x08

#define MPMCTX_FLAGS_NODEPTH       (1 << 1)
#define MPMCTX_FLAGS_CACHE_TO_DISK (1 << 2)

/* 패턴 구조체 */
typedef struct MpmPattern_ {
    uint16_t len;
    uint8_t flags;
    uint8_t *original_pat;

    uint16_t offset;
    uint16_t depth;

    uint32_t id;
    uint32_t sids_size;
    SigIntId *sids;

    struct MpmPattern_ *next;
} MpmPattern;

/* Thread-local 구조 */
typedef struct MpmThreadCtx_ {
    void *ctx;                /* 실제론 SCHSThreadCtx*로 캐스팅해서 사용 */
    uint32_t memory_cnt;
    uint32_t memory_size;
} MpmThreadCtx;

/* Hyperscan 기반 MPM 컨텍스트 */
typedef struct MpmCtx_ {
    void *ctx;                /* SCHSCtx* 등 내부 엔진 구조체 */
    uint8_t mpm_type;
    uint8_t flags;
    uint16_t maxdepth;

    uint32_t pattern_cnt;
    uint16_t minlen;
    uint16_t maxlen;

    uint32_t memory_cnt;
    uint32_t memory_size;
    uint32_t max_pat_id;

    MpmPattern **init_hash;
} MpmCtx;

#endif /* SWAF_MPM_CTX_H */