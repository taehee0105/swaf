/* 패턴 매칭 결과에 대응되는 룰 ID(SigIntId) 저장, 관리 헤더 */

#ifndef PREFILTER_H
#define PREFILTER_H

#include <stdint.h>
#include <stdbool.h>
#include "sig_id.h"   /* for SigIntId */
#include "debug.h"    /* for SCLogDebug, SCLogError */
#include "mem.h"      /* for SCMalloc, SCRealloc, SCFree */

/**
 * @brief Structure to hold a list of matched rule IDs
 */
typedef struct PrefilterRuleStore_ {
    SigIntId *rule_id_array;      /* Array of rule IDs */
    uint32_t rule_id_array_cnt;   /* Number of rule IDs in the array */
    uint32_t rule_id_array_size;  /* Allocated size of the array */
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

#endif /* PREFILTER_H */
