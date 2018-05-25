#ifndef __BPTREE_H__
#define __BPTREE_H__

#include "bpttypes.h"

struct bpt_mgr;

struct bpt_iostat {
	volatile unsigned long long pool_maps;
	volatile unsigned long long pool_unmaps;
	volatile unsigned long long latch_hits;
	volatile unsigned long long latch_evicts;
};

extern struct bpt_mgr *
bpt_openmgr(const char *name, unsigned int page_bits,
	    unsigned int pool_max, unsigned int hash_size);
extern bptree_t bpt_open(struct bpt_mgr *mgr);
extern void bpt_closemgr(struct bpt_mgr *mgr);
extern void bpt_close(bptree_t h);
extern int bpt_insertkey(bptree_t h, unsigned char *key,
			 unsigned int len, bpt_level_t level,
			 pageno_t page_no);
extern int bpt_deletekey(bptree_t h, unsigned char *key,
			 unsigned int len, bpt_level_t level);
extern pageno_t bpt_findkey(bptree_t h, unsigned char *key,
			    unsigned int len);
extern unsigned int bpt_firstkey(bptree_t h, unsigned char *key,
				 unsigned int len);
extern unsigned int bpt_nextkey(bptree_t h, unsigned int slot);
extern void bpt_getiostat(bptree_t h, struct bpt_iostat *iostat);

#endif	/* __BPTREE_H__ */
