#ifndef __BPTREE_H__
#define __BPTREE_H__

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

typedef void * bptree_t;
typedef unsigned char bpt_level;
typedef unsigned long long bpt_pageno_t;
typedef unsigned char boolean_t;

struct bpt_iostat {
	volatile unsigned long long reads;
	volatile unsigned long long writes;
	volatile unsigned long long cache_miss;
	volatile unsigned long long cache_hit;
	volatile unsigned long long cache_retire;
};

extern bptree_t bpt_open(const char *name, unsigned int page_bits,
			   unsigned int entry_max);
extern void bpt_close(bptree_t h);
extern int bpt_insertkey(bptree_t h, unsigned char *key,
			 unsigned int len, bpt_level level,
			 bpt_pageno_t page_no);
extern int bpt_deletekey(bptree_t h, unsigned char *key,
			 unsigned int len, bpt_level level);
extern unsigned int bpt_firstkey(bptree_t h, unsigned char *key,
				 unsigned int len);
extern unsigned int bpt_nextkey(bptree_t h, unsigned int slot);
extern void bpt_getiostat(bptree_t h, struct bpt_iostat *iostat);

#endif	/* __BPTREE_H__ */
