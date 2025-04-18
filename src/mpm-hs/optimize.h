/* 조건 분기 최적화(likely/unlikely), 메모리 정렬/동기화 최적화 매크로 정의 헤더 */

#ifndef SWAF_OPTIMIZE_H
#define SWAF_OPTIMIZE_H

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


/* memory barrier (필요할 경우만 사용) */

/**
 * 컴파일러 최적화 방지 
 * 메모리 접근 순서가 컴파일러의 재배치에 의해 변경되는 걸 막음
 */
#define cc_barrier() __asm__ __volatile__("" ::: "memory")

/**
 * h/w memory barrier 
 * 멀티코어 환경에서 CPU가 명령어를 out-of-order 실행하지 않도록 강제
 * __sync_synchronize() -> GCC 내장 함수 (read/write 메모리 접근 순서 보장)
 */
#define hw_barrier() __sync_synchronize()

#endif /* SWAF_OPTIMIZE_H */