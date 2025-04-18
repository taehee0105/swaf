/* 정확도, 대소문자 구분, 길이 기반 비교 함수 제공 헤더 */

#ifndef SWAF_MEMCMP_H
#define SWAF_MEMCMP_H

#include <string.h>
#include <ctype.h>

static inline int SCMemcmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n) == 0 ? 0 : 1;
}

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t n)
{
    /** 
     * -- cpp error code --
     *  const unsigned char *a = s1;
     * const unsigned char *b = s2;
     */
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;
    
    for (size_t i = 0; i < n; i++) {
        if (a[i] != tolower(b[i]))
            return 1;
    }
    return 0;
}

static inline int SCBufferCmp(const void *s1, size_t len1,
                              const void *s2, size_t len2)
{
    if (len1 == len2)
        return SCMemcmp(s1, s2, len1);
    else if (len1 < len2)
        return -1;
    return 1;
}

#endif /* SWAF_MEMCMP_H */