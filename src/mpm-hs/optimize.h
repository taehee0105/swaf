/* 조건 분기 최적화(likely/unlikely)와 메모리 정렬/동기화 최적화 매크로 헤더 */

#ifndef __WAF_OPTIMIZE_H__
#define __WAF_OPTIMIZE_H__

#if defined(__GNUC__) || defined(__clang__)
    #ifndef likely
    #define likely(x)   __builtin_expect(!!(x), 1)
    #endif

    #ifndef unlikely
    #define unlikely(x) __builtin_expect(!!(x), 0)
    #endif
#else
    #define likely(x)   (x)
    #define unlikely(x) (x)
#endif

/* 메모리 배리어 (필요할 경우만 사용) */
#define cc_barrier() __asm__ __volatile__("" ::: "memory")
#define hw_barrier() __sync_synchronize()

#endif // __WAF_OPTIMIZE_H__

