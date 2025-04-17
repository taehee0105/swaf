/* MPM 엔진 API 정의 헤더 */

#ifndef __WAF_MPM_H__
#define __WAF_MPM_H__

#include <stdint.h>
#include "mpm_ctx.h"     /* MpmCtx, MpmThreadCtx 구조체 정의 */
#include "sig_id.h"      /* SigIntId 정의 */
#include "prefilter.h"   /* PrefilterRuleStore 정의 */

/* Matcher 타입 정의 (필요 시 확장 가능) */
enum {
    MPM_NOTSET = 0,
    MPM_HS,
    MPM_TABLE_SIZE,
};

/**
 * MPM 엔진을 위한 인터페이스 함수들
 */

/**
 * MPM 컨텍스트 초기화
 * @param mpm_ctx 사용할 MpmCtx 구조체
 * @param matcher 사용할 매칭 엔진 타입
 */
void MpmInitCtx(MpmCtx *mpm_ctx, uint8_t matcher);

/**
 * MPM 쓰레드 컨텍스트 초기화
 */
void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher);

/**
 * MPM 쓰레드 컨텍스트 해제
 */
void MpmDestroyThreadCtx(MpmThreadCtx *mpm_thread_ctx, const uint16_t matcher);

/**
 * 패턴 등록 (Case-Sensitive)
 */
int MpmAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth, uint32_t pid,
                    SigIntId sid, uint8_t flags);

/**
 * 패턴 등록 (Case-Insensitive)
 */
int MpmAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth, uint32_t pid,
                    SigIntId sid, uint8_t flags);

/**
 * 일반 패턴 등록
 */
int MpmAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                  uint16_t offset, uint16_t depth, uint32_t pid,
                  SigIntId sid, uint8_t flags);

/**
 * 패턴 메모리 해제
 */
void MpmFreePattern(MpmCtx *mpm_ctx, MpmPattern *p);

/**
 * 실제 패턴 매칭 수행 (검색)
 */
uint32_t MpmSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *thread_ctx,
                   PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen);

#endif /* __WAF_MPM_H__ */

