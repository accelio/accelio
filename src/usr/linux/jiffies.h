#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <linux/kernel.h>
#include <xio_os.h>
/*
#include <linux/types.h>
#include <time.h>
#include <sys/timex.h>
*/

/*
 *	These inlines deal with timer wrapping correctly. You are
 *	strongly encouraged to use them
 *	1. Because people otherwise forget
 *	2. Because if the timer wrap changes in future you won't have to
 *	   alter your driver code.
 *
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a,b)		\
	 ((long)((b) - (a)) < 0)
#define time_before(a,b)	time_after(b,a)

#define time_after_eq(a,b)	\
	 ((long)((a) - (b)) >= 0)
#define time_before_eq(a,b)	time_after_eq(b,a)

/*
 * Calculate whether a is in the range of [b, c].
 */
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))

/*
 * Calculate whether a is in the range of [b, c).
 */
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))

/* Same as above, but does so with platform independent 64bit types.
 * These must be used when utilizing jiffies_64 (i.e. return value of
 * get_jiffies_64() */
#define time_after64(a,b)	\
	 ((__s64)((b) - (a)) < 0)
#define time_before64(a,b)	time_after64(b,a)

#define time_after_eq64(a,b)	\
	 ((__s64)((a) - (b)) >= 0)
#define time_before_eq64(a,b)	time_after_eq64(b,a)

#define time_in_range64(a, b, c) \
	(time_after_eq64(a, b) && \
	 time_before_eq64(a, c))


#endif
