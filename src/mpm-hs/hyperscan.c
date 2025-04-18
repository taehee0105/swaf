/* 16진수 패턴을 ASCII로 변환 */

#include <stdio.h>
#include <stdint.h>

#include "hyperscan.h"
#include "mem.h"

char *HSRenderPattern(const uint8_t *pat, uint16_t pat_len)
{
    if (pat == NULL) {
        return NULL;
    }

    const size_t hex_len = (pat_len * 4) + 1;
    char *str = SCCalloc(1, hex_len, char);
    if (str == NULL) {
        return NULL;
    }

    char *sp = str;
    for (uint16_t i = 0; i < pat_len; i++) {
        snprintf(sp, 5, "\\x%02x", pat[i]);
        sp += 4;
    }
    *sp = '\0';
    return str;
}