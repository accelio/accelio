#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/slab.h>

/*---------------------------------------------------------------------------*/
/* defines								     */
/*---------------------------------------------------------------------------*/
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a) < (b)) ? (b) : (a))
#endif

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#define __ALIGN_XIO_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_XIO(x, a)		__ALIGN_XIO_MASK(x, (typeof(x))(a)-1)
#define ALIGN(x, a)			__ALIGN_XIO((x), (a))

#ifndef roundup
# define roundup(x, y)  ((((x) + ((y) - 1)) / (y)) * (y))
#endif /* !defined(roundup) */

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

#endif

struct mutex {
	pthread_mutex_t lock;
};

static inline void mutex_init(struct mutex *mtx)
{
	pthread_mutex_init(&mtx->lock, NULL);
}

static inline void mutex_destroy(struct mutex *mtx)
{
	pthread_mutex_destroy(&mtx->lock);
}

static inline void mutex_lock(struct mutex *mtx)
{
	pthread_mutex_lock(&mtx->lock);
}

static inline void mutex_unlock(struct mutex *mtx)
{
	pthread_mutex_unlock(&mtx->lock);
}

/*
 * https://github.com/ErikDubbelboer/udp-tcp-speed-test/blob/
 *	master/udp/flooding/spinlock.h
 */

typedef volatile int spinlock_t;

static inline void spin_lock_init(spinlock_t* spinlock)
{
	__sync_lock_release(spinlock);
}

static inline void spin_lock(spinlock_t* spinlock)
{
	while (!__sync_bool_compare_and_swap(spinlock, 0, 1)) {
		while (*spinlock) {
			asm volatile("pause\n": : :"memory");
		}
	}
}

static inline int spin_try_lock(spinlock_t* spinlock)
{
	if (__sync_bool_compare_and_swap(spinlock, 0, 1)) {
		return 1;
	}

	return 0;
}

static inline int spin_locked(spinlock_t* spinlock) {
	return *spinlock;
}

static inline void spin_unlock(spinlock_t* spinlock) {
	__sync_lock_release(spinlock);
}

static inline char *kstrdup(const char *s, gfp_t gfp)
{
	/* Make sure code transfered to kernel will work as expected */
	assert(gfp == GFP_KERNEL);
	return strdup(s);
}
#endif /* _LINUX_KERNEL_H */
