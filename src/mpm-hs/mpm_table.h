/* MPM 엔진 선택/호출을 위한 함수 테이블 정의 헤더 */
#ifndef __WAF_MPM_TABLE_H__
#define __WAF_MPM_TABLE_H__

#include "mpm_ctx.h"
#include "sig_id.h"
#include "prefilter.h"

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

#endif // __WAF_MPM_TABLE_H__

