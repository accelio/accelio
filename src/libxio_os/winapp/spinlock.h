#ifndef __SPINLOCK_WIN_H___
#define __SPINLOCK_WIN_H___

#ifdef __cplusplus
extern "C" {
#endif

#define  YIELD_ITERATION	30	/* yield after 30 iterations */
#define MAX_SLEEP_ITERATION	40
#define SEED_VAL		100


struct spinlock {
	volatile long	dest;
	long		exchange;
	long		compare;

};
typedef struct spinlock spinlock_t;

#define PTHREAD_PROCESS_PRIVATE       0

static __inline int spin_lock_init(spinlock_t *spinlock)
{
	spinlock->dest = 0;
	spinlock->exchange = SEED_VAL;
	spinlock->compare = 0;
	return 0;
}

static __inline int spin_lock_init2(spinlock_t *lock, int pshared)
{
	(void *)pshared;
	return spin_lock_init(lock);
}

static __inline int spin_lock_destroy(spinlock_t *spinlock)
{
	// nothing to do
	return 0;
}

static __inline void spin_lock(spinlock_t *spinlock)
{
	int iterations = 0;

	while (1) {
		/* A thread already owning the lock shouldn't be
		 * allowed to wait to acquire the lock - reentrant safe
		 */
		if (spinlock->dest == GetCurrentThreadId())
			break;

		/* Spinning in a loop of interlockedxxx calls can reduce
		 * the available  memory bandwidth and slow down the
		 * rest of the system. Interlocked calls are expensive in
		 * their use of the system memory bus. It is better to
		 * see if the 'dest' value is what it is expected and then
		 * retry interlockedxx.
		 */
		if (InterlockedCompareExchangeAcquire(&spinlock->dest,
						     spinlock->exchange,
						     spinlock->compare) == 0) {
			/* assign CurrentThreadId to dest to make it
			 * re-entrant safe
			 */
			spinlock->dest = GetCurrentThreadId();
			/* lock acquired */
			break;
		}

		/* spin wait to acquire */
		while (spinlock->dest != spinlock->compare) {
			if (iterations >= YIELD_ITERATION) {
				if (iterations + YIELD_ITERATION >=
						MAX_SLEEP_ITERATION)
					Sleep(0);

				if (iterations < MAX_SLEEP_ITERATION) {
					iterations = 0;
					SwitchToThread();
				}
			}
			/* Yield processor on multi-processor but if
			 * on single processor then give other thread
			 * the CPU
			 */
			iterations++;
			if (xio_get_num_processors() > 1)
				YieldProcessor();
			else
				SwitchToThread();
		}
	}
}

static __inline int spin_try_lock(spinlock_t *spinlock)
{
	if (spinlock->dest == GetCurrentThreadId())
		return 0;

	if (InterlockedCompareExchangeAcquire(&spinlock->dest, spinlock->exchange,
					     spinlock->compare) == 0) {
		spinlock->dest = GetCurrentThreadId();
		return 1;
	}
	return 0;
}

static __inline int spin_locked(spinlock_t *spinlock)
{
	return InterlockedAddAcquire(&spinlock->dest, 0);
}

static __inline void spin_unlock(spinlock_t *spinlock)
{
	if (spinlock->dest != GetCurrentThreadId())
		return;

	InterlockedCompareExchangeRelease(&spinlock->dest, spinlock->compare,
					  GetCurrentThreadId());
}
#ifdef __cplusplus
}
#endif

#endif // ! __SPINLOCK_WIN_H___