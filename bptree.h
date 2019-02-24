#ifndef __BPTREE_H__
#define __BPTREE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "bpttypes.h"

struct bpt_mgr;

struct bpt_iostat {
	volatile uint64_t pool_maps;
	volatile uint64_t pool_unmaps;
	volatile uint64_t latch_hits;
	volatile uint64_t latch_evicts;
};

extern struct bpt_mgr *
bpt_openmgr(const char *name, uint32_t page_bits,
	    uint32_t pool_max, uint32_t hash_size);
extern bptree_t bpt_open(struct bpt_mgr *mgr);
extern void bpt_closemgr(struct bpt_mgr *mgr);
extern void bpt_close(bptree_t h);
extern int bpt_insertkey(bptree_t h, unsigned char *key,
			 uint32_t len, bpt_level_t level,
			 pageno_t page_no);
extern int bpt_deletekey(bptree_t h, unsigned char *key,
			 uint32_t len, bpt_level_t level);
extern pageno_t bpt_findkey(bptree_t h, unsigned char *key,
			    uint32_t len);
extern uint32_t bpt_firstkey(bptree_t h, unsigned char *key,
			     uint32_t len);
extern uint32_t bpt_nextkey(bptree_t h, uint32_t slot);
extern void bpt_getiostat(bptree_t h, struct bpt_iostat *iostat);

#ifdef __cplusplus
}
#endif

#endif	/* __BPTREE_H__ */
