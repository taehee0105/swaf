/* 메모리 할당, 해제 매크로 제공 헤더 */

#ifndef SWAF_MEM_H
#define SWAF_MEM_H

#include <stdlib.h>
#include <string.h>

/**
 * -- cpp error code --
 * 
 * #define SCMalloc(sz)            malloc((sz))
 * #define SCCalloc(nm, sz)        calloc((nm), (sz))
 * #define SCRealloc(ptr, sz)      realloc((ptr), (sz))
 * #define SCStrdup(s)             strdup((s))
 * #define SCStrndup(s, n)         strndup((s), (n))
 * #define SCFree(p)               free((p))
*/

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

/* 기본 메모리 할당 매크로 (명시적 캐스팅 포함) */
#define SCMalloc(sz, type)              ((type *)malloc((sz)))
#define SCCalloc(nm, sz, type)          ((type *)calloc((nm), (sz)))
#define SCRealloc(ptr, sz, type)        ((type *)realloc((ptr), (sz)))
#define SCStrdup(s)                     strdup((s))
#define SCStrndup(s, n)                 strndup((s), (n))
#define SCFree(p)                       free((p))

/* 정렬된 메모리 할당 */
#define SCMallocAligned(size, align)    waf_posix_memalign_wrapper((size), (align))
#define SCFreeAligned(p)                free((p))

/**
 * x86_64 환경에서 malloc은 기본적으로 16B 정렬
 * 16B가 아닌 다른 정렬 수가 필요할 때 사용
 * 
 * EX>
 * void *ptr;
 * posix_memalign(&ptr, 32, 128);  // 32바이트 정렬된 128바이트 블록
 * 
 * 나중에 필요 시 사용 
 */
#ifdef false
static inline void *waf_posix_memalign_wrapper(size_t size, size_t align) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) != 0)
        return NULL;
    return ptr;
}
#endif

#endif /* SWAF_MEM_H */