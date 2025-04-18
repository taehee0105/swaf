/**
 * MPM 엔진 선택/호출을 위한 함수 테이블 정의 헤더
 * 
 * 기존 Suricata에서는 Aho-Corasick 등과 같은
 * 다른 MPM 엔진을 사용할 때도 이용
 * 현재 swaf는 hyperscan only, 
 * 하지만 굳이 구조를 바꿀 필요는 없다고 판단
 */
#ifndef SWAF_MPM_TABLE_H
#define SWAF_MPM_TABLE_H

#include "mpm_ctx.h"
#include "prefilter.h"
#include "sig_id.h"

/* 엔진 기능 플래그 */
#define MPM_FEATURE_FLAG_DEPTH    (1 << 0)
#define MPM_FEATURE_FLAG_OFFSET   (1 << 1)

/* 엔진 테이블 항목 정의 */
typedef struct MpmTableElmt_ {
    const char *name;
    void (*InitCtx)(MpmCtx *);
    void (*InitThreadCtx)(MpmCtx *, MpmThreadCtx *);
    void (*DestroyCtx)(MpmCtx *);
    void (*DestroyThreadCtx)(MpmCtx *, MpmThreadCtx *);
    int (*AddPattern)(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int (*AddPatternNocase)(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int (*Prepare)(void *, MpmCtx *);
    int (*CacheRuleset)(void *);
    void *(*ConfigInit)(void);
    void (*ConfigDeinit)(void **);
    void (*ConfigCacheDirSet)(void *, const char *);
    uint32_t (*Search)(const MpmCtx *, MpmThreadCtx *, PrefilterRuleStore *, const uint8_t *, uint32_t);
    void (*PrintCtx)(MpmCtx *);
    void (*PrintThreadCtx)(MpmThreadCtx *);
#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
    uint8_t feature_flags;
} MpmTableElmt;

/* 테이블 선언 */
extern MpmTableElmt mpm_table[MPM_TABLE_SIZE];
extern uint8_t mpm_default_matcher;

#endif /* SWAF_MPM_TABLE_H */