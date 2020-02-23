#ifndef __SYSDEF_H__
#define __SYSDEF_H__

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

/* Get gettid has no Glibc wrapper, so we need to
 * define it as below
 */
#ifndef gettid
#define gettid()	syscall(__NR_gettid)
#endif

#ifndef sys_malloc
#define sys_malloc(sz)	malloc(sz)
#endif

#ifndef sys_free
#define sys_free(ptr)	free(ptr)
#endif

#ifndef bzero
#define bzero(p, n)	memset(p, 0, n)
#endif

#endif	/* __SYSDEF_H__ */
