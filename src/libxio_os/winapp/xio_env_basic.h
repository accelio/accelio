#ifndef BASIC_ENV_H
#define BASIC_ENV_H

#include <stddef.h> /* will bring offsetof  */

#define inline __inline

#define PTHREAD_MUTEX_INITIALIZER {(PRTL_CRITICAL_SECTION_DEBUG)-1,-1,0,0,0,0}
typedef struct pthread_mutexattr{ int a; } pthread_mutexattr_t;
typedef CRITICAL_SECTION pthread_mutex_t;
static int pthread_mutex_lock(pthread_mutex_t *m)
{
	EnterCriticalSection(m);
	return 0;
}

static int pthread_mutex_unlock(pthread_mutex_t *m)
{
	LeaveCriticalSection(m);
	return 0;
}

static int pthread_mutex_trylock(pthread_mutex_t *m)
{
	return TryEnterCriticalSection(m) ? 0 : EBUSY;
}

static int pthread_mutex_init(pthread_mutex_t *m, pthread_mutexattr_t *a)
{
	(void)a;
	InitializeCriticalSection(m);

	return 0;
}

static int pthread_mutex_destroy(pthread_mutex_t *m)
{
	DeleteCriticalSection(m);
	return 0;
}


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
/*
#define __ALIGN_XIO_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_XIO(x, a)		__ALIGN_XIO_MASK(x, (typeof(x))(a)-1)
#define ALIGN(x, a)			__ALIGN_XIO((x), (a))
//*/
//AVNER - TODO: check!
#define ALIGN(_n, _alignment)  (((_n)+(_alignment)-1) & ~((_alignment)-1))

#ifndef roundup
# define roundup(x, y)  ((((x) + ((y) - 1)) / (y)) * (y))
#endif /* !defined(roundup) */


extern const char hex_asc[];
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]


/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifndef container_of
	#ifndef _MSC_VER
	#define container_of(ptr, type, member) ({			\
		const typeof(((type *)0)->member) * __mptr = (ptr);	\
		(type *)((char *)__mptr - offsetof(type, member)); })
	#else
	#define container_of(ptr, type, member) \
		((type *)((char *)(ptr)-(unsigned long)(&((type *)0L)->member)))
	#endif
#endif

#define __MUTEX_INITIALIZER(lockname)				\
		{						\
			PTHREAD_MUTEX_INITIALIZER		\
		}						\

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)

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

#endif /* BASIC_ENV_H */
