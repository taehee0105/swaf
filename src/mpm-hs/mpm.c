/* Simplified and adapted from Suricata's util-mpm.c for standalone Hyperscan MPM use */

#include <stdlib.h>
#include <string.h>

#include "mpm.h"               // Custom header for MpmCtx, MpmThreadCtx, etc.
#include "mpm_table.h"
#include "util-mpm-hs.h"       // Hyperscan matcher registration and core logic
#include "mem.h"               // For SCMalloc, SCRealloc, SCFree

MpmTableElmt mpm_table[MPM_TABLE_SIZE];
uint8_t mpm_default_matcher = MPM_HS;  // Default to Hyperscan

void MpmInitCtx(MpmCtx *mpm_ctx, uint8_t matcher) {
    mpm_ctx->mpm_type = matcher;
    if (mpm_table[matcher].InitCtx)
        mpm_table[matcher].InitCtx(mpm_ctx);
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher) {
    if (mpm_table[matcher].InitThreadCtx)
        mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx);
}

void MpmDestroyThreadCtx(MpmThreadCtx *mpm_thread_ctx, const uint16_t matcher) {
    if (mpm_table[matcher].DestroyThreadCtx)
        mpm_table[matcher].DestroyThreadCtx(NULL, mpm_thread_ctx);
}

int MpmAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags) {
    if (mpm_table[mpm_ctx->mpm_type].AddPattern)
        return mpm_table[mpm_ctx->mpm_type].AddPattern(mpm_ctx, pat, patlen,
                                                       offset, depth, pid, sid, flags);
    return -1;
}

int MpmAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags) {
    if (mpm_table[mpm_ctx->mpm_type].AddPatternNocase)
        return mpm_table[mpm_ctx->mpm_type].AddPatternNocase(mpm_ctx, pat, patlen,
                                                             offset, depth, pid, sid, flags);
    return -1;
}

int MpmAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                 uint16_t offset, uint16_t depth,
                 uint32_t pid, SigIntId sid, uint8_t flags) {
    if (flags & MPM_PATTERN_FLAG_NOCASE)
        return MpmAddPatternCI(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
    else
        return MpmAddPatternCS(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

uint32_t MpmSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *thread_ctx,
                   PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen) {
    if (mpm_table[mpm_ctx->mpm_type].Search)
        return mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx, thread_ctx, pmq, buf, buflen);
    return 0;
}

void MpmPrintCtx(MpmCtx *mpm_ctx) {
    if (mpm_table[mpm_ctx->mpm_type].PrintCtx)
        mpm_table[mpm_ctx->mpm_type].PrintCtx(mpm_ctx);
}

void MpmPrintThreadCtx(MpmThreadCtx *thread_ctx) {
    // Optional implementation for debugging
}

void MpmTableSetup(void) {
    memset(mpm_table, 0, sizeof(mpm_table));
    mpm_default_matcher = MPM_HS;
    MpmHSRegister();
}

