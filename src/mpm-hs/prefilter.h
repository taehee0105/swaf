/* 탐지된 룰 ID(SigIntId) 동적 저장, 관리 헤더 */

#ifndef SWAF_PREFILTER_H
#define SWAF_PREFILTER_H

#include <stdint.h>
#include <stdbool.h>

#include "debug.h"
#include "mem.h"
#include "sig_id.h"

/**
 * @brief 탐지된 룰 ID들을 저장하는 컨테이너
 */
typedef struct PrefilterRuleStore_ {
    SigIntId *rule_id_array;      /* 탐지된 룰 ID 배열 */
    uint32_t rule_id_array_cnt;   /* 현재 사용된 룰 ID 개수 */
    uint32_t rule_id_array_size;  /* 할당된 배열의 전체 크기 */
} PrefilterRuleStore;

int PrefilterAddSidsResize(PrefilterRuleStore *pmq, uint32_t new_size);

#define PMQ_RESET(pmq) ((pmq)->rule_id_array_cnt = 0)

static inline void PrefilterAddSids(PrefilterRuleStore *pmq, const SigIntId *sids, uint32_t sids_size)
{
    if (sids_size > 0) {
        uint32_t new_size = pmq->rule_id_array_cnt + sids_size;
        if (new_size > pmq->rule_id_array_size) {
            if (PrefilterAddSidsResize(pmq, new_size) == 0) {
                sids_size = pmq->rule_id_array_size - pmq->rule_id_array_cnt;
            }
        }
        SCLogDebug("Adding %u sids", sids_size);
        SigIntId *ptr = pmq->rule_id_array + pmq->rule_id_array_cnt;
        SigIntId *end = ptr + sids_size;
        do {
            *ptr++ = *sids++;
        } while (ptr != end);
        pmq->rule_id_array_cnt += sids_size;
    }
}

int PmqSetup(PrefilterRuleStore *pmq);
void PmqReset(PrefilterRuleStore *pmq);
void PmqCleanup(PrefilterRuleStore *pmq);
void PmqFree(PrefilterRuleStore *pmq);

#endif /* SWAF_PREFILTER_H */