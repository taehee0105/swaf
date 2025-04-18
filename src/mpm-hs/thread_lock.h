/* 뮤텍스 wrapping 헤더 */
#ifndef SWAF_THREAD_LOCK_H
#define SWAF_THREAD_LOCK_H

#include <pthread.h>

typedef pthread_mutex_t SCMutex;

#define SCMUTEX_INITIALIZER       PTHREAD_MUTEX_INITIALIZER
#define SCMutexInit(mutex, attr) pthread_mutex_init((mutex), (attr))
#define SCMutexDestroy(mutex)    pthread_mutex_destroy((mutex))
#define SCMutexLock(mutex)       pthread_mutex_lock((mutex))
#define SCMutexUnlock(mutex)     pthread_mutex_unlock((mutex))

#endif /* SWAF_THREAD_LOCK_H */