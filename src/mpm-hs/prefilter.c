/* 탐지된 룰 ID(SigIntId) 동적 저장, 관리 */

#include "debug.h"
#include "mem.h"
#include "optimize.h"
#include "prefilter.h"

/* 룰 ID 배열의 크기 동적으로 증가 */
int PrefilterAddSidsResize(PrefilterRuleStore *pmq, uint32_t new_size)
{
    new_size *= 2;  /* 2배 크기로 realloc */
    SigIntId *new_array = (SigIntId *)SCRealloc(pmq->rule_id_array,
                                                new_size * sizeof(SigIntId), 
                                                SigIntId);
    if (unlikely(new_array == NULL)) {
        /* 실패하면 요청한 정확한 크기로 재시도 */
        new_size /= 2;
        new_array = (SigIntId *)SCRealloc(pmq->rule_id_array,
                                          new_size * sizeof(SigIntId), 
                                          SigIntId);
        /**
         * 또 다시 실패 시 경고 출력 후 실패 반환
         * likely/unlikely -> 실패 가능성 분기 최적화
         */
        if (unlikely(new_array == NULL)) {
            SCLogError("Failed to realloc rule ID array. Some matches may be lost");
            return 0;
        }
    }
    pmq->rule_id_array = new_array;
    pmq->rule_id_array_size = new_size;
    return new_size;
}

/* PrefilterRuleStore 구조체 배열 초기화 */
int PmqSetup(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return -1;

    pmq->rule_id_array = (SigIntId *)SCMalloc(16 * sizeof(SigIntId), SigIntId);
    if (pmq->rule_id_array == NULL)
        return -1;

    pmq->rule_id_array_cnt = 0;
    pmq->rule_id_array_size = 16;
    return 0;
}

/**
 * 탐지된 룰 ID 개수 0으로 초기화
 * 다음 새로운 요청을 처리하기 위한 함수
 * 요청마다 매번 free -> malloc은 비효율적
 */
void PmqReset(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;
    pmq->rule_id_array_cnt = 0;
}

/* rule_id_array 메모리 해제 및 포인터 NULL 처리 */
void PmqCleanup(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;

    if (pmq->rule_id_array != NULL) {
        SCFree(pmq->rule_id_array);
        pmq->rule_id_array = NULL;
    }
    pmq->rule_id_array_size = 0;
    pmq->rule_id_array_cnt = 0;
}

void PmqFree(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;
    PmqCleanup(pmq);
    SCFree(pmq);
}