#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#ifndef LOG
#define DBG	0x00000001
#define INF	0x00000002
#define WRN	0x00000004
#define ERR	0x00000008

/* Default trace level */
unsigned int _bpt_trace_level = INF;

#define LOG(_lvl_, _fmt_, ...)						\
	do {								\
		if ((_lvl_) >= _bpt_trace_level) {			\
			printf("[BPT]%s(%d):", __FUNCTION__, __LINE__); \
			printf(_fmt_, ##__VA_ARGS__);			\
		}							\
	} while (0)
#endif	/* LOG */

#endif	/* __LOG_H__ */
