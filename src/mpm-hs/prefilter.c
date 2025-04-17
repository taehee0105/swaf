#include "prefilter.h"
#include "mem.h"
#include "debug.h"
#include "optimize.h"

int PrefilterAddSidsResize(PrefilterRuleStore *pmq, uint32_t new_size)
{
    new_size *= 2;  // double the size to allow room for future additions
    SigIntId *new_array = (SigIntId *)SCRealloc(pmq->rule_id_array,
                                                new_size * sizeof(SigIntId), 
                                                SigIntId);
    if (unlikely(new_array == NULL)) {
        // try again with exact size
        new_size /= 2;
        new_array = (SigIntId *)SCRealloc(pmq->rule_id_array,
                                          new_size * sizeof(SigIntId), 
                                          SigIntId);
        if (unlikely(new_array == NULL)) {
            SCLogError("Failed to realloc rule ID array. Some matches may be lost");
            return 0;
        }
    }
    pmq->rule_id_array = new_array;
    pmq->rule_id_array_size = new_size;
    return new_size;
}

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

void PmqReset(PrefilterRuleStore *pmq)
{
    if (pmq == NULL)
        return;
    pmq->rule_id_array_cnt = 0;
}

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
