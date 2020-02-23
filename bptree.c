#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include "sysdef.h"
#include "bptree.h"
#include "bptdef.h"
#include "bpt_private.h"
#include "log.h"
#include "rbtrace.h"

static void bpt_putnodeno(unsigned char *dst, nodeno_t node_no)
{
	int i = NODE_NUM_BYTES;

	while (i--) {
		dst[i] = (unsigned char)node_no;
		if (node_no) {
			node_no >>= 8;
		}
	}
}

static nodeno_t bpt_getnodeno(unsigned char *src)
{
	nodeno_t node_no = 0;
	int i;

	for (i = 0; i < NODE_NUM_BYTES; i++) {
		node_no <<= 8;
		node_no += src[i];
	}

	return node_no;
}

int keycmp(struct bpt_key *key1, unsigned char *key2, unsigned int len2)
{
	int ret;
	unsigned short len1 = key1->len;

	ret = memcmp(key1->key, key2, len1 > len2 ? len2 : len1);
	if (ret) {
		return ret;
	}
	if (len1 > len2) {
		return 1;
	}
	if (len1 < len2) {
		return -1;
	}
	return 0;
}

static struct bpt_node *
bpt_node(struct bptree *bpt, struct bpt_pool *pool,
	 nodeno_t node_no)
{
	struct bpt_node *node;
	unsigned int subnode;

	subnode = (unsigned int)(node_no & bpt->mgr->pool_mask);
	node = (struct bpt_node *)(pool->map + (subnode << bpt->mgr->node_bits));

	return node;
}

static void bpt_initlatch(struct bpt_latch *latch)
{
	bzero(latch, sizeof(*latch));

	rwlock_init(&latch->rdwr);
	rwlock_init(&latch->access);
	rwlock_init(&latch->parent);
}

static int bpt_mapsegment(struct bptree *bpt, struct bpt_pool *pool,
			  nodeno_t node_no)
{
	off_t offset;
	int flags;

	bpt->status = 0;
	offset = (node_no & ~bpt->mgr->pool_mask) << bpt->mgr->node_bits;

	flags = PROT_READ | PROT_WRITE;
	pool->map = mmap(NULL, (bpt->mgr->pool_mask + 1) << bpt->mgr->node_bits,
			 flags, MAP_SHARED, bpt->mgr->fd, offset);
	if (pool->map == MAP_FAILED) {
		bpt->status = -1;
	} else {
		__sync_fetch_and_add(&bpt->mgr->latchmgr->iostat.pool_maps, 1);
	}

	return bpt->status;
}

static void bpt_linklatch(struct bptree *bpt, unsigned short hash_val,
			  unsigned short victim, nodeno_t node_no)
{
	struct bpt_latch *latch;

	latch = &bpt->mgr->latches[victim];
	if ((latch->next = bpt->mgr->latchmgr->latch_tbl[hash_val].slot)) {
		bpt->mgr->latches[latch->next].prev = victim;
	}

	bpt->mgr->latchmgr->latch_tbl[hash_val].slot = victim;
	latch->node_no = node_no;
	latch->hashv = hash_val;
	latch->prev = 0;
}

static
struct bpt_latch *
bpt_pinlatch(struct bptree *bpt, nodeno_t node_no)
{
	struct bpt_latch *latch;
	struct bpt_mgr *mgr;
	struct bpt_latch_mgr *latchmgr;
	unsigned short hashv;
	unsigned short avail;
	unsigned short slot;
	unsigned short victim;
	unsigned short idx;

	latch = NULL;
	mgr = bpt->mgr;
	latchmgr = mgr->latchmgr;
	hashv = node_no % mgr->latchmgr->tbl_size;
	avail = 0;

	/* Try to find the latch table entry and pin it for this node */
	spin_rdlock(&latchmgr->latch_tbl[hashv].lock);

	if ((slot = latchmgr->latch_tbl[hashv].slot)) {
		do {
			latch = &mgr->latches[slot];
			if (node_no == latch->node_no) {
				break;
			}
		} while ((slot = latch->next));
	}
	if (slot) {
		__sync_fetch_and_add(&latch->pin, 1);
	}

	spin_rdunlock(&latchmgr->latch_tbl[hashv].lock);

	if (slot) {
		/* Found the latch and pinned it */
		__sync_fetch_and_add(&latchmgr->iostat.latch_hits, 1);
		goto out;
	}

	/* Latch not found, reacquire write lock as we may allocate a
	 * new entry from buckets
	 */
	spin_wrlock(&latchmgr->latch_tbl[hashv].lock);

	if ((slot = latchmgr->latch_tbl[hashv].slot)) {
		do {
			latch = &mgr->latches[slot];
			if (node_no == latch->node_no) {
				break;
			}
			if ((latch->pin == 0) && (avail == 0)) {
				/* bookmark the first unpinned latch */
				avail = slot;
			}
		} while ((slot = latch->next));
	}

	/* Found our entry, or take an unpinned one */
	if (slot || (slot = avail)) {
		latch = &mgr->latches[slot];
		__sync_fetch_and_add(&latch->pin, 1);
		latch->node_no = node_no;
		spin_wrunlock(&latchmgr->latch_tbl[hashv].lock);
		goto out;
	}

	/* Entry not found, and no unpinned latch. Allocate a new entry
	 * if buckets are not full
	 */
	victim = __sync_fetch_and_add(&latchmgr->latch_deployed, 1) + 1;
	if (victim < latchmgr->nr_latch_total) {
		latch = &mgr->latches[victim];
		bpt_initlatch(latch);
		__sync_fetch_and_add(&latch->pin, 1);
		bpt_linklatch(bpt, hashv, victim, node_no);
		spin_wrunlock(&latchmgr->latch_tbl[hashv].lock);
		__sync_fetch_and_add(&latchmgr->iostat.latch_hits, 1);
		goto out;
	}

	/* Restore latch deployed counter */
	victim = __sync_fetch_and_add(&latchmgr->latch_deployed, -1);

	/* Scan all the buckets and try to find a victim to evict */
	while (true) {
		victim = __sync_fetch_and_add(&latchmgr->victim, 1);
		if ((victim %= latchmgr->nr_latch_total)) {
			latch = &mgr->latches[victim];
		} else {
			continue;
		}

		/* Take control of the slot from other threads */
		if (latch->pin || !spin_trywrlock(&latch->busy)) {
			continue;
		}

		idx = latch->hashv;

		/* Try to acquire write lock on hash chain
		 * Skip entry if not obtained or has outstanding locks
		 */
		if (!spin_trywrlock(&latchmgr->latch_tbl[idx].lock)) {
			spin_wrunlock(&latch->busy);
			continue;
		}

		if (latch->pin) {
			spin_wrunlock(&latch->busy);
			spin_wrunlock(&latchmgr->latch_tbl[idx].lock);
			continue;
		}

		/* Unlink available victim from its hash chain */
		if (latch->prev) {
			mgr->latches[latch->prev].next = latch->next;
		} else {
			latchmgr->latch_tbl[idx].slot = latch->next;
		}

		if (latch->next) {
			mgr->latches[latch->next].prev = latch->prev;
		}

		spin_wrunlock(&latchmgr->latch_tbl[idx].lock);

		/* Pin it and link to our hash chain */
		__sync_fetch_and_add(&latch->pin, 1);
		bpt_linklatch(bpt, hashv, victim, node_no);

		spin_wrunlock(&latchmgr->latch_tbl[hashv].lock);
		spin_wrunlock(&latch->busy);
		__sync_fetch_and_add(&latchmgr->iostat.latch_evicts, 1);
		goto out;
	}

 out:
	return latch;
}

static void bpt_unpinlatch(struct bpt_latch *latch)
{
	__sync_fetch_and_add(&latch->pin, -1);
}

static void bpt_linkpool(struct bptree *bpt, struct bpt_pool *pool,
			 nodeno_t node_no, int hash_val)
{
	struct bpt_pool *node;
	unsigned int slot;

	pool->hash_prev = pool->hash_next = NULL;
	pool->basenode = node_no & ~bpt->mgr->pool_mask;
	pool->pin = CLOCK_BIT + 1;

	slot = bpt->mgr->pool_tbl[hash_val];
	if (slot) {
		node = &bpt->mgr->pools[slot];
		pool->hash_next = node;
		node->hash_prev = pool;
	}

	bpt->mgr->pool_tbl[hash_val] = pool->slot;
}

static
struct bpt_pool *
bpt_findpool(struct bptree *bpt, nodeno_t node_no,
	     unsigned int hash_val)
{
	struct bpt_pool *pool;
	unsigned int slot;

	pool = NULL;

	if ((slot = bpt->mgr->pool_tbl[hash_val])) {
		pool = &bpt->mgr->pools[slot];
	} else {
		goto out;
	}

	/* Get the base node which node_no lies in */
	node_no &= ~bpt->mgr->pool_mask;

	while (pool->basenode != node_no) {
		if ((pool = pool->hash_next)) {
			continue;
		} else {
			goto out;
		}
	}

 out:
	return pool;
}

static
struct bpt_pool *
bpt_pinpool(struct bptree *bpt, nodeno_t node_no)
{
	unsigned int slot;
	unsigned int hashv;
	unsigned int idx;
	unsigned int victim;
	struct bpt_mgr *mgr;
	struct bpt_pool *pool;
	struct bpt_pool *node;

	mgr = bpt->mgr;

	/* Lock the node pool bucket */
	hashv = (unsigned int)(node_no >> mgr->seg_bits) % mgr->tbl_size;
	spin_wrlock(&mgr->pool_tbl_locks[hashv]);

	/* Lookup the node in hash table, if found just increase
	 * pin count and return
	 */
	if ((pool = bpt_findpool(bpt, node_no, hashv))) {
		__sync_fetch_and_or(&pool->pin, CLOCK_BIT);
		__sync_fetch_and_add(&pool->pin, 1);
		spin_wrunlock(&bpt->mgr->pool_tbl_locks[hashv]);
		goto out;
	}

	/* Allocate a new pool node and add to hash table */
	slot = __sync_fetch_and_add(&mgr->pool_cnt, 1);
	if (++slot < mgr->pool_max) {
		pool = &mgr->pools[slot];
		pool->slot = slot;

		if (bpt_mapsegment(bpt, pool, node_no)) {
			pool = NULL;
			goto out;
		}

		bpt_linkpool(bpt, pool, node_no, hashv);
		spin_wrunlock(&mgr->pool_tbl_locks[hashv]);
		goto out;
	}

	/* Node pool is full. Find a pool entry to evict */
	__sync_fetch_and_add(&mgr->pool_cnt, -1);

	while (true) {
		victim = __sync_fetch_and_add(&mgr->evicted, 1);
		victim %= bpt->mgr->pool_max;
		pool = &bpt->mgr->pools[victim];
		idx = (unsigned int)(pool->basenode >> mgr->seg_bits) %
			mgr->tbl_size;

		if (!victim) {
			continue;
		}

		if (!spin_trywrlock(&mgr->pool_tbl_locks[idx])) {
			continue;
		}

		/* Skip this entry if node is pinned or clock bit is set */
		if (pool->pin) {
			__sync_fetch_and_and(&pool->pin, ~CLOCK_BIT);
			spin_wrunlock(&mgr->pool_tbl_locks[idx]);
			continue;
		}

		/* Unlink victim pool node from hash table */
		if ((node = pool->hash_prev)) {
			node->hash_next = pool->hash_next;
		} else if ((node = pool->hash_next)) {
			mgr->pool_tbl[idx] = node->slot;
		} else {
			mgr->pool_tbl[idx] = 0;
		}

		if ((node = pool->hash_next)) {
			node->hash_prev = pool->hash_prev;
		}

		spin_wrunlock(&mgr->pool_tbl_locks[idx]);

		/* Remove old file mapping */
		munmap(pool->map, (mgr->pool_mask + 1) << mgr->node_bits);
		pool->map = NULL;
		__sync_fetch_and_add(&mgr->latchmgr->iostat.pool_unmaps, 1);

		/* Create new pool mapping and link into hash table */
		if (bpt_mapsegment(bpt, pool, node_no)) {
			pool = NULL;
			goto out;
		}

		bpt_linkpool(bpt, pool, node_no, hashv);
		spin_wrunlock(&mgr->pool_tbl_locks[hashv]);

		goto out;
	}

 out:
	return pool;
}

static void bpt_unpinpool(struct bpt_pool *pool)
{
	__sync_fetch_and_add(&pool->pin, -1);
}

static void bpt_locknode(struct bpt_latch *latch, bpt_mode_t mode)
{
	switch (mode) {
	case BPT_LOCK_READ:
		rwlock_rdlock(&latch->rdwr);
		break;
	case BPT_LOCK_WRITE:
		rwlock_wrlock(&latch->rdwr);
		break;
	case BPT_LOCK_ACCESS:
		rwlock_rdlock(&latch->access);
		break;
	case BPT_LOCK_DELETE:
		rwlock_wrlock(&latch->access);
		break;
	case BPT_LOCK_PARENT:
		rwlock_wrlock(&latch->parent);
		break;
	default:
		assert(0);
	}
}

static void bpt_unlocknode(struct bpt_latch *latch, bpt_mode_t mode)
{
	switch (mode) {
	case BPT_LOCK_READ:
		rwlock_rdunlock(&latch->rdwr);
		break;
	case BPT_LOCK_WRITE:
		rwlock_wrunlock(&latch->rdwr);
		break;
	case BPT_LOCK_ACCESS:
		rwlock_rdunlock(&latch->access);
		break;
	case BPT_LOCK_DELETE:
		rwlock_wrunlock(&latch->access);
		break;
	case BPT_LOCK_PARENT:
		rwlock_wrunlock(&latch->parent);
		break;
	default:
		assert(0);
	}
}

void bpt_closemgr(struct bpt_mgr *mgr)
{
	if ((mgr->latches != NULL) &&
	    (mgr->latches != MAP_FAILED)) {
		munmap(mgr->latches,
		       mgr->latchmgr->nr_latch_nodes * mgr->node_size);
	}
	if ((mgr->latchmgr != NULL) &&
	    (mgr->latchmgr != MAP_FAILED)) {
		munmap(mgr->latchmgr, mgr->node_size);
	}
	
	if (mgr->fd && (mgr->fd != -1)) {
		close(mgr->fd);
	}
	if (mgr->pools) {
		sys_free(mgr->pools);
	}
	if (mgr->pool_tbl) {
		sys_free(mgr->pool_tbl);
	}
	if (mgr->pool_tbl_locks) {
		sys_free(mgr->pool_tbl_locks);
	}

	sys_free(mgr);
}

/* b+tree file layout
 * +------------------------+
 * |      Super block       |
 * +------------------------+
 * |      alloc node[0]   --+--+
 * |      alloc node[1]   --+--+--+
 * +------------------------+  |  |
 * |       root node        |  |  |
 * +------------------------+  |  |
 * |       leaf node        |  |  |node free list
 * +------------------------+  |  |
 * |        latches         |  |  |
 * |          ...           |  |  |
 * +------------------------+  |  |
 * |          ...           |<-+--+
 * +------------------------+  |
 *                        ^    |always point to last+1 node
 *                        +----+
 */
struct bpt_mgr *bpt_openmgr(const char *name,
			    unsigned int node_bits,
			    unsigned int pool_max,
			    unsigned int ht_size)
{
	int rc = 0;
	struct bpt_mgr *mgr = NULL;
	struct bpt_latch_mgr *latchmgr = NULL;
	struct bpt_super_block *sb = NULL;
	struct bpt_key *key = NULL;
	struct bpt_slot *sptr = NULL;
	off_t fsize;
	unsigned int node_size;
	unsigned int cache_blk;
	unsigned int last;
	unsigned int latch_per_node;
	unsigned int tbl_size;
	unsigned short nr_latch_nodes = 0;
	int flags;
	bpt_level_t level;
	
	if (node_bits > BPT_MAX_NODE_SHIFT ||
	    node_bits < BPT_MIN_NODE_SHIFT) {
		rc = -1;
		goto out;
	}

	node_size = 1 << node_bits;
	
	if (pool_max == 0) {
		/* Must have buffer pool */
		rc = -1;
		goto out;
	}

	mgr = sys_malloc(sizeof(*mgr));
	if (mgr == NULL) {
		LOG(ERR, "allocate bpt_mgr failed\n");
		rc = -1;
		goto out;
	}

	bzero(mgr, sizeof(*mgr));
	mgr->fd = open(name, O_RDWR|O_CREAT, 0666);
	if (mgr->fd == -1) {
		LOG(ERR, "open %s failed\n", name);
		rc = -1;
		goto out;
	}

	cache_blk = sysconf(_SC_PAGE_SIZE);
	if (cache_blk == -1) {
		LOG(ERR, "sysconf PAGE_SIZE failed\n");
		rc = -1;
		goto out;
	} else if (cache_blk > node_size) {
		LOG(ERR, "PAGE_SIZE too big\n");
		rc = -1;
		goto out;
	}
	
	latchmgr = sys_malloc(BPT_MAX_NODE_SIZE);
	if (latchmgr == NULL) {
		LOG(ERR, "allocate bpt_latch_mgr failed\n");
		rc = -1;
		goto out;
	}
	bzero(latchmgr, BPT_MAX_NODE_SIZE);

	/* Read minimum node size to get super block info */
	if ((fsize = lseek(mgr->fd, 0, SEEK_END)) >= BPT_MIN_NODE_SIZE) {
		sb = (struct bpt_super_block *)sys_malloc(BPT_MIN_NODE_SIZE);
		pread(mgr->fd, sb, BPT_MIN_NODE_SIZE, 0);
		if (strcmp(sb->magic, BPT_MAGIC) != 0) {
			rc = -1;
		} else if ((sb->node_bits < BPT_MIN_NODE_SHIFT) ||
			   (sb->node_bits > BPT_MAX_NODE_SHIFT)) {
			rc = -1;
		} else {
			node_bits = sb->node_bits;
		}

		sys_free(sb);
		if (rc != 0) {
			goto out;
		}
	}

	mgr->node_bits = node_bits;
	mgr->node_size = node_size;

	mgr->pool_max = pool_max;

	if (cache_blk < mgr->node_size) {
		cache_blk = mgr->node_size;
	}

	mgr->pool_mask = (cache_blk >> node_bits) - 1;

	mgr->seg_bits = 0;
	while ((1 << mgr->seg_bits) <= mgr->pool_mask) {
		mgr->seg_bits++;
	}

	mgr->tbl_size = ht_size;

	mgr->pools = calloc(pool_max, sizeof(struct bpt_pool));
	if (mgr->pools == NULL) {
		goto out;
	}
	mgr->pool_tbl = calloc(ht_size, sizeof(unsigned short));
	if (mgr->pool_tbl == NULL) {
		goto out;
	}
	mgr->pool_tbl_locks = calloc(ht_size, sizeof(struct spin_rwlock));
	if (mgr->pool_tbl_locks == NULL) {
		goto out;
	}

	/* Calculate how many nodes we need for latches */
	latch_per_node = mgr->node_size / sizeof(struct bpt_latch);
	nr_latch_nodes = (unsigned short)
		(BPT_LATCH_TABLE / latch_per_node + 1);

	/* File already initialized, map latchmgr and latches directly */
	if (fsize >= mgr->node_size) {
		goto map_latches;
	}

	/* Write super block */
	sb = (struct bpt_super_block *)latchmgr;
	strcpy(sb->magic, BPT_MAGIC);
	sb->major = BPT_MAJOR;
	sb->minor = BPT_MINOR;
	sb->node_bits = node_bits;
	if (write(mgr->fd, sb, mgr->node_size) < mgr->node_size) {
		LOG(ERR, "write sb, %d bytes failed\n", mgr->node_size);
		rc = -1;
		goto out;
	}

	bzero(latchmgr, mgr->node_size);
	latchmgr->nr_latch_nodes = nr_latch_nodes;
	latchmgr->nr_latch_total = (unsigned short)
		(nr_latch_nodes * latch_per_node);
	bpt_putnodeno(latchmgr->alloc->right,
		      NODE_ROOT + MIN_LEVEL + nr_latch_nodes);

	/* Calculate how many hash entries can alloc node holds */
	tbl_size = (unsigned short)((mgr->node_size - sizeof(*latchmgr)) /
				    sizeof(struct latch_hash_bucket));
	if (tbl_size > latchmgr->nr_latch_total) {
		tbl_size = latchmgr->nr_latch_total;
	}

	latchmgr->tbl_size = tbl_size;

	/* Write latchmgr, i.e. 2 alloc node and latchmgr info */
	if (write(mgr->fd, latchmgr, mgr->node_size) < mgr->node_size) {
		LOG(ERR, "write latchmgr, %d bytes failed\n", mgr->node_size);
		rc = -1;
		goto out;
	}

	/* Top to down initialization of empty b+tree with only root
	 * node and leaf node.
	 */
	for (level = MIN_LEVEL; level--; ) {
		sptr = slotptr(latchmgr->alloc, 1);
		sptr->offset = mgr->node_size - STOPPER_KEY_LEN;

		/* For empty b+tree the child node of root is NODE_LEAF,
		 * the child node of NODE_LEAF is 0
		 */
		bpt_putnodeno(sptr->node_no,
			      level ? MIN_LEVEL - level + NODE_ROOT : 0);
		
		/* Create stopper key */
		key = keyptr(latchmgr->alloc, 1);
		key->len = 2;
		key->key[0] = 0xFF;
		key->key[1] = 0xFF;

		latchmgr->alloc->min = mgr->node_size - STOPPER_KEY_LEN;
		latchmgr->alloc->level = level;
		latchmgr->alloc->count = 1;
		latchmgr->alloc->active = 1;

		if (write(mgr->fd, latchmgr, mgr->node_size) < mgr->node_size) {
			LOG(ERR, "write node, level %d failed\n", level);
			rc = -1;
			goto out;
		}
	}

	/* Zero nodes for latches */
	bzero(latchmgr, mgr->node_size);
	last = MIN_LEVEL + NODE_ROOT;
	while (last <= ((MIN_LEVEL + NODE_ROOT + nr_latch_nodes) | mgr->pool_mask)) {
		pwrite(mgr->fd, latchmgr, mgr->node_size, last << mgr->node_bits);
		last++;
	}

 map_latches:

	/* Map latchmgr and latches from db file. These latches
	 * are shared between processes.
	 */
	flags = PROT_READ | PROT_WRITE;
	mgr->latchmgr = mmap(NULL, mgr->node_size, flags, MAP_SHARED,
			     mgr->fd, NODE_ALLOC * mgr->node_size);
	if (mgr->latchmgr == MAP_FAILED) {
		rc = -1;
		goto out;
	}

	mgr->latches = mmap(NULL, mgr->latchmgr->nr_latch_nodes * mgr->node_size,
			    flags, MAP_SHARED, mgr->fd,
			    NODE_LATCH * mgr->node_size);
	if (mgr->latches == MAP_FAILED) {
		rc = -1;
		goto out;
	}

 out:

	if (latchmgr) {
		sys_free(latchmgr);
	}
	if (rc != 0) {
		if (mgr) {
			bpt_closemgr(mgr);
		}
		mgr = NULL;
	}
	return mgr;
}

bptree_t bpt_open(struct bpt_mgr *mgr)
{
	int rc = 0;
	struct bptree *bpt = NULL;

	if (mgr == NULL) {
		rc = -1;
		goto out;
	}

	bpt = sys_malloc(sizeof(*bpt));
	if (bpt == NULL) {
		rc = -1;
		goto out;
	}

	bzero(bpt, sizeof(*bpt));
	bpt->mgr = mgr;

	/* Total 3 in-memory node buffer */
	bpt->mem = sys_malloc(BPT_BUF_NODES * mgr->node_size);
	if (bpt->mem == NULL) {
		rc = -1;
		goto out;
	}

	bzero(bpt->mem, BPT_BUF_NODES * mgr->node_size);
	bpt->frame = (struct bpt_node *)(bpt->mem);
	bpt->cursor = (struct bpt_node *)(bpt->mem + mgr->node_size);
	bpt->zero = (struct bpt_node *)(bpt->mem + 2 * mgr->node_size);

 out:
	if (rc != 0 && bpt) {
		bpt_close(bpt);
		bpt = NULL;
	}

	return bpt;
}

void bpt_close(bptree_t h)
{
	struct bptree *bpt;

	bpt = (struct bptree *)h;
	if (bpt->mem) {
		sys_free(bpt->mem);
	}
	sys_free(bpt);
}

nodeno_t bpt_newnode(struct bptree *bpt, struct bpt_node *node)
{
	struct bpt_mgr *mgr;
	struct bpt_node_set set;
	ssize_t bytes;
	nodeno_t new_node;
	bool reuse;

	mgr = bpt->mgr;
	new_node = 0;
	reuse = false;

	spin_wrlock(&mgr->latchmgr->lock);

	/* Try node free list first
	 * otherwise allocate new empty node
	 */
	if ((new_node = bpt_getnodeno(mgr->latchmgr->alloc[1].right))) {
		if ((set.pool = bpt_pinpool(bpt, new_node))) {
			new_node = 0;
			goto out;
		}

		set.node = bpt_node(bpt, set.pool, new_node);
		bpt_putnodeno(mgr->latchmgr->alloc[1].right,
			      bpt_getnodeno(set.node->right));
		bpt_unpinpool(set.pool);
		reuse = true;
		LOG(DBG, "reuse free node(0x%llx)\n", new_node);
	} else {
		/* Alloc node always point to the tail node. */
		new_node = bpt_getnodeno(mgr->latchmgr->alloc->right);
		bpt_putnodeno(mgr->latchmgr->alloc->right, new_node+1);
		reuse = false;
		LOG(DBG, "allocating new node(0x%llx)\n", new_node);
	}

	bytes = pwrite(mgr->fd, node, mgr->node_size,
		       new_node << mgr->node_bits);
	if (bytes < mgr->node_size) {
		new_node = 0;
		goto out;
	}

	/* If writing first node of cache block, zero last node
	 * in the block
	 */
	if (!reuse &&
	    (mgr->pool_mask > 0) &&
	    ((new_node & mgr->pool_mask) == 0)) {
		/* Use zero buffer to write zeros */
		bytes = pwrite(mgr->fd, bpt->zero, mgr->node_size,
			       (new_node|mgr->pool_mask) << mgr->node_bits);
		if (bytes < mgr->node_size) {
			LOG(ERR, "node(0x%llx) pwrite failed\n", new_node);
			new_node = 0;
			bpt->status = -1;
			goto out;
		}
	}

 out:
	spin_wrunlock(&mgr->latchmgr->lock);

	return new_node;
}

int bpt_freenode(struct bptree *bpt, struct bpt_node_set *set)
{
	spin_wrlock(&bpt->mgr->latchmgr->lock);

	/* Insert the node to be freed into the empty chain
	 * in second alloc node.
	 * alloc[1] -> node_no -> ...  -> free node -> 0
	 */
	bpt_putnodeno(set->node->right,
		      bpt_getnodeno(bpt->mgr->latchmgr->alloc[1].right));
	bpt_putnodeno(bpt->mgr->latchmgr->alloc[1].right, set->node_no);
	set->node->free = 1;

	/* Unlock the node for write and delete */
	bpt_unlocknode(set->latch, BPT_LOCK_WRITE);
	bpt_unlocknode(set->latch, BPT_LOCK_DELETE);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

	spin_wrunlock(&bpt->mgr->latchmgr->lock);

	LOG(DBG, "node(0x%llx) freed\n", set->node_no);

	return bpt->status;
}

unsigned int bpt_findslot(struct bpt_node_set *set,
			  unsigned char *key,
			  unsigned int len)
{
	int slot;
	int low;
	int high;

	low = 1;	// slot index start from 1
	high = set->node->count;

	if (bpt_getnodeno(set->node->right)) {
		/* If next node exists, this node has no stopper
		 * key, so high index should be count+1
		 */
		high++;
	}

	/* Do binary search to find the key */
	while (high > low) {
		slot = low + ((high - low) / 2);
		if (keycmp(keyptr(set->node, slot), key, len) < 0) {
			low = slot + 1;
		} else {
			high = slot;
		}
	}

	return (high > set->node->count) ? 0 : high;
}

unsigned int bpt_loadnode(struct bptree *bpt,
			  struct bpt_node_set *set,
			  unsigned char *key, unsigned int len,
			  bpt_level_t level, bpt_mode_t lock)
{
	nodeno_t node_no;
	nodeno_t prev_node;
	struct bpt_latch *prev_latch;
	struct bpt_pool *prev_pool;
	struct bpt_slot *sptr;
	unsigned int slot;
	bpt_mode_t mode;
	bpt_mode_t prev_mode;
	unsigned char drill;

	node_no = NODE_ROOT;
	prev_node = 0;
	prev_mode = 0;
	drill = 0xFF;

	do {
		/* Determine lock mode of drill level. */
		mode = (drill == level) ? lock : BPT_LOCK_READ;

		set->latch = bpt_pinlatch(bpt, node_no);
		set->node_no = node_no;

		if ((set->pool = bpt_pinpool(bpt, node_no))) {
			set->node = bpt_node(bpt, set->pool, node_no);
		} else {
			goto out;
		}

		if (node_no > NODE_ROOT) {
			bpt_locknode(set->latch, BPT_LOCK_ACCESS);
		}

		if (prev_node) {
			bpt_unlocknode(prev_latch, prev_mode);
			bpt_unpinlatch(prev_latch);
			bpt_unpinpool(prev_pool);
			prev_node = 0;
		}

		bpt_locknode(set->latch, mode);

		if (set->node->free) {
			bpt->status = -1;
			goto out;
		}

		if (node_no > NODE_ROOT) {
			bpt_unlocknode(set->latch, BPT_LOCK_ACCESS);
		}

		/* re-read and re-lock root after determining actual
		 * level of root.
		 */
		if (set->node->level != drill) {
			if (set->node_no != NODE_ROOT) {
				LOG(ERR, "node(0x%llx) illegal lvl(%d), drill(%d)\n",
				    set->node_no, set->node->level, drill);
				bpt->status = -1;
				goto out;
			}

			/* Get the level of root node */
			drill = set->node->level;

			/* If we are updating root node, then we need to
			 * release read lock on root node first and then
			 * re-lock and re-read root node.
			 */
			if ((lock != BPT_LOCK_READ) && (drill == level)) {
				bpt_unlocknode(set->latch, mode);
				bpt_unpinlatch(set->latch);
				bpt_unpinpool(set->pool);
				continue;
			}
		}

		prev_node = set->node_no;
		prev_latch = set->latch;
		prev_pool = set->pool;
		prev_mode = mode;

		/* Find the key on node at this level and descend
		 * to requested level.
		 */
		if (!set->node->kill) {
			if ((slot = bpt_findslot(set, key, len))) {
				/* Skip all dead slots */
				while ((sptr = slotptr(set->node, slot))->dead) {
					if (slot < set->node->count) {
						slot++;
						continue;
					} else {
						goto next_node;
					}
				}

				/* Current level is the requested level,
				 * return slot number
				 */
				if (drill == level) {
					return slot;
				}

				/* Descend to next level */
				node_no = bpt_getnodeno(sptr->node_no);
				drill--;
				continue;
			}
		}

		/* Or slide into next node */
 next_node:
		node_no = bpt_getnodeno(set->node->right);
	} while (node_no);

	LOG(ERR, "Key not found\n");
	bpt->status = -1;
 out:
	return 0;
}

unsigned int bpt_cleannode(struct bptree *bpt,
			   struct bpt_node *node,
			   unsigned int len,
			   unsigned int slot)
{
	struct bpt_key *key;
	unsigned int max;
	unsigned int size;
	unsigned int newslot;
	unsigned int i, count;
	unsigned int next;

	max = node->count;
	newslot = slot;
	size = (max + 1) * sizeof(struct bpt_slot) + sizeof(*node) + len + 1;
	
	/* There is enough space for the key and its slot, just return */
	if (node->min >= size) {
		return slot;
	}
	
	/* Skip cleanup if nothing to reclaim */
	if (!node->dirty) {
		return 0;
	}

	memcpy(bpt->frame, node, bpt->mgr->node_size);
	bzero(node+1, bpt->mgr->node_size - sizeof(*node));
	node->dirty = 0;
	node->active = 0;
	next = bpt->mgr->node_size;

	for (i = 1, count = 0; i <= max; i++) {
		if (i == slot) {
			newslot = count + 1;
		}
		/* Skip all dead keys */
		if (i <= max && slotptr(bpt->frame, i)->dead) {
			continue;
		}

		count++;
		/* Copy key */
		key = keyptr(bpt->frame, i);
		next -= (key->len + 1);
		memcpy(((char *)node) + next, key, key->len + 1);

		/* Copy slot */
		memcpy(slotptr(node, count)->node_no,
		       slotptr(bpt->frame, i)->node_no,
		       NODE_NUM_BYTES);
		if (!(slotptr(node, count)->dead =
		      slotptr(bpt->frame, i)->dead)) {
			node->active++;
		}
		slotptr(node, count)->offset = next;
	}

	node->min = next;
	node->count = count;

	if (node->min >= size) {
		return newslot;
	}
	
	return 0;
}

int bpt_splitroot(struct bptree *bpt, struct bpt_node_set *root,
		  unsigned char *leftkey, nodeno_t node_no2)
{
	nodeno_t left;
	unsigned int next;

	next = bpt->mgr->node_size;

	/* Make a copy of current root node */
	if ((left = bpt_newnode(bpt, root->node)) == 0) {
		goto out;
	}

	bzero(root->node + 1, bpt->mgr->node_size - sizeof(*root->node));

	/* Insert first key on new root node and link old root
	 * node as left child
	 */
	next -= leftkey[0] + 1;
	memcpy(((char *)root->node) + next, leftkey, leftkey[0] + 1);
	bpt_putnodeno(slotptr(root->node, 1)->node_no, left);
	slotptr(root->node, 1)->offset = next;

	/* Insert stopper key and link new node as right child */
	next -= STOPPER_KEY_LEN;
	((unsigned char *)root->node)[next] = 2;
	((unsigned char *)root->node)[next+1] = 0xFF;
	((unsigned char *)root->node)[next+2] = 0xFF;
	bpt_putnodeno(slotptr(root->node, 2)->node_no, node_no2);
	slotptr(root->node, 2)->offset = next;

	bpt_putnodeno(root->node->right, 0);
	root->node->min = next;
	root->node->count = 2;
	root->node->active = 2;
	root->node->level++;

	bpt_unlocknode(root->latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(root->latch);
	bpt_unpinpool(root->pool);

	LOG(DBG, "root splitted, node_no2(0x%llx)\n", node_no2);

 out:
	return bpt->status;
}

int bpt_splitnode(struct bptree *bpt, struct bpt_node_set *set)
{
	struct bpt_mgr *mgr;
	struct bpt_key *key;
	struct bpt_node_set right;
	unsigned int max;
	unsigned int count;
	unsigned int i;
	unsigned int next;
	bpt_level_t level;
	unsigned char fencekey[257];
	unsigned char rightkey[257];

	key = NULL;
	mgr = bpt->mgr;
	level = set->node->level;

	/* Split higher half of keys to bpt->frame */
	bzero(bpt->frame, mgr->node_size);
	max = set->node->count;

	count = 0;
	next = mgr->node_size;
	for (i = max/2 + 1; i <= max; i++) {
		count++;
		key = keyptr(set->node, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy(((char *)bpt->frame) + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(bpt->frame, count)->node_no,
		       slotptr(set->node, i)->node_no,
		       NODE_NUM_BYTES);
		if (!(slotptr(bpt->frame, count)->dead =
		      slotptr(set->node, i)->dead)) {
			bpt->frame->active++;
		}
		slotptr(bpt->frame, count)->offset = next;
	}

	/* Remember fence key for new right node */
	memcpy(rightkey, key, key->len + 1);

	bpt->frame->min = next;
	bpt->frame->count = count;
	bpt->frame->level = level;

	/* Link right node */
	if (set->node_no > NODE_ROOT) {
		memcpy(bpt->frame->right, set->node->right, NODE_NUM_BYTES);
	}

	/* Allocate a new node and write frame to it */
	if ((right.node_no = bpt_newnode(bpt, bpt->frame)) == 0) {
		goto out;
	}

	/* Update lower half in old node */
	memcpy(bpt->frame, set->node, mgr->node_size);
	bzero(set->node + 1, mgr->node_size - sizeof(*set->node));
	set->node->dirty = 0;
	set->node->active = 0;

	count = 0;
	next = mgr->node_size;
	for (i = 1; i <= max/2; i++) {
		count++;
		key = keyptr(bpt->frame, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy((char *)set->node + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(set->node, count)->node_no,
		       slotptr(bpt->frame, i)->node_no,
		       NODE_NUM_BYTES);
		slotptr(set->node, count)->offset = next;
		set->node->active++;
	}

	/* Remember fence key for old node */
	memcpy(fencekey, key, key->len + 1);

	bpt_putnodeno(set->node->right, right.node_no);
	set->node->min = next;
	set->node->count = count;

	/* If current node is root node, split it */
	if (set->node_no == NODE_ROOT) {
		bpt_splitroot(bpt, set, fencekey, right.node_no);
		goto out;
	}

	/* Lock right node */
	right.latch = bpt_pinlatch(bpt, right.node_no);
	bpt_locknode(right.latch, BPT_LOCK_PARENT);

	bpt_locknode(set->latch, BPT_LOCK_PARENT);
	bpt_unlocknode(set->latch, BPT_LOCK_WRITE);

	/* Insert new fence into left block */
	if (bpt_insertkey(bpt, &fencekey[1], fencekey[0], level+1, set->node_no)) {
		goto out;
	}

	if (bpt_insertkey(bpt, &rightkey[1], rightkey[0], level+1, right.node_no)) {
		goto out;
	}

	bpt_unlocknode(set->latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

	bpt_unlocknode(right.latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(right.latch);

	LOG(DBG, "node(0x%llx) splitted, sibling(0x%llx)\n",
	    set->node_no, right.node_no);

 out:
	return bpt->status;
}

int bpt_insertkey(bptree_t h, unsigned char *key,
		  unsigned int len, bpt_level_t level,
		  nodeno_t node_no)
{
	struct bptree *bpt;
	struct bpt_key *ptr;
	struct bpt_node_set set;
	unsigned int slot;
	unsigned int i;

	bpt = (struct bptree *)h;

	while (true) {
		if ((slot = bpt_loadnode(bpt, &set, key, len, level,
					 BPT_LOCK_WRITE))) {
			ptr = keyptr(set.node, slot);
		} else {
			LOG(ERR, "Failed to load node, level(%d), node(0x%llx)\n",
			    level, node_no);
			if (bpt->status == 0) {
				bpt->status = -1;
			}
			goto out;
		}

		/* If key already exists, update node number
		 * and return.
		 */
		if (keycmp(ptr, key, len) == 0) {
			if (slotptr(set.node, slot)->dead) {
				set.node->active++;
			}
			slotptr(set.node, slot)->dead = 0;
			bpt_putnodeno(slotptr(set.node, slot)->node_no, node_no);
			LOG(DBG, "Key updated, level(%d), curr-node(0x%llx), "
			    "node(0x%llx)\n", level, set.node_no, node_no);
			bpt->status = 0;
			goto unlock_node;
		}

		/* Check whether node has enough space to reclaim */
		slot = bpt_cleannode(bpt, set.node, len, slot);
		if (slot) {
			break;
		}

		/* Not enough space for the key, do node split */
		if (bpt_splitnode(bpt, &set)) {
			goto out;
		}
	}

	/* First copy the key into the node */
	set.node->min -= (len + 1);
	((unsigned char *)set.node)[set.node->min] = len;
	memcpy((char *)set.node + set.node->min + 1, key, len);

	/* Then insert new entry into the slot array */
	for (i = slot; i < set.node->count; i++) {
		if (slotptr(set.node, i)->dead) {
			break;
		}
	}

	if (i == set.node->count) {
		i++;
		set.node->count++;	// No dead slot can be reused
	}

	set.node->active++;

	for ( ; i > slot; i--) {
		*slotptr(set.node, i) = *slotptr(set.node, i - 1);
	}

	bpt_putnodeno(slotptr(set.node, slot)->node_no, node_no);
	slotptr(set.node, slot)->offset = set.node->min;
	slotptr(set.node, slot)->dead = 0;

 unlock_node:

	bpt_unlocknode(set.latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

 out:
	return bpt->status;
}

nodeno_t bpt_findkey(bptree_t h, unsigned char *key,
		     unsigned int len)
{
	unsigned int slot;
	struct bptree *bpt;
	struct bpt_key *ptr;
	struct bpt_node_set set;
	nodeno_t node_no;

	bpt = (struct bptree *)h;
	node_no = 0;

	if ((slot = bpt_loadnode(bpt, &set, key, len, 0, BPT_LOCK_READ))) {
		/* If key exists return node number, otherwise return 0. */
		ptr = keyptr(set.node, slot);
		if (keycmp(ptr, key, len) == 0) {
			node_no = bpt_getnodeno(slotptr(set.node, slot)->node_no);
		}
		bpt_unlocknode(set.latch, BPT_LOCK_READ);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
	}

	return node_no;
}

int bpt_fixfence(struct bptree *bpt,
		 struct bpt_node_set *set,
		 bpt_level_t level)
{
	struct bpt_key *ptr;
	nodeno_t node_no;
	unsigned char leftkey[257];
	unsigned char rightkey[257];

	ptr = keyptr(set->node, set->node->count);
	memcpy(rightkey, ptr, ptr->len + 1);

	bzero(slotptr(set->node, set->node->count), sizeof(struct bpt_slot));
	set->node->count--;
	set->node->dirty = 1;

	ptr = keyptr(set->node, set->node->count);
	memcpy(leftkey, ptr, ptr->len + 1);
	node_no = set->node_no;

	bpt_locknode(set->latch, BPT_LOCK_PARENT);
	bpt_unlocknode(set->latch, BPT_LOCK_WRITE);

	if (bpt_insertkey(bpt, &leftkey[1], leftkey[0], level+1, node_no)) {
		goto out;
	}

	if (bpt_deletekey(bpt, &rightkey[1], rightkey[0], level+1)) {
		goto out;
	}

	bpt_unlocknode(set->latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

 out:
	return bpt->status;
}

int bpt_collapseroot(struct bptree *bpt, struct bpt_node_set *root)
{
	struct bpt_node_set child;
	unsigned int i;

	/* Find child entry and promote to new root */
	do {
		for (i = 1; i <= root->node->count; i++) {
			if (!slotptr(root->node, i)->dead) {
				break;
			}
		}

		child.node_no = bpt_getnodeno(slotptr(root->node, i)->node_no);

		child.latch = bpt_pinlatch(bpt, child.node_no);
		/* Lock child for delete and write */
		bpt_locknode(child.latch, BPT_LOCK_DELETE);
		bpt_locknode(child.latch, BPT_LOCK_WRITE);
		
		if ((child.pool = bpt_pinpool(bpt, child.node_no))) {
			child.node = bpt_node(bpt, child.pool, child.node_no);
		} else {
			goto out;
		}

		memcpy(root->node, child.node, bpt->mgr->node_size);

		if (bpt_freenode(bpt, &child)) {
			goto out;
		}
	} while ((root->node->level > 1) && (root->node->active == 1));

	bpt_unlocknode(root->latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(root->latch);
	bpt_unpinpool(root->pool);

	LOG(DBG, "root collapsed, child(0x%llx) freed\n", child.node_no);

 out:
	return bpt->status;
}

int bpt_deletekey(bptree_t h, unsigned char *key,
		  unsigned int len, bpt_level_t level)
{
	struct bptree *bpt;
	struct bpt_key *ptr;
	unsigned int slot;
	unsigned int i;
	struct bpt_node_set right;
	struct bpt_node_set set;
	bool fence = false;
	bool found = false;
	bool dirty = false;
	unsigned char lowerkey[257];
	unsigned char higherkey[257];

	bpt = (struct bptree *)h;
	bpt->status = 0;

	if ((slot = bpt_loadnode(bpt, &set, key, len, level, BPT_LOCK_WRITE))) {
		ptr = keyptr(set.node, slot);
	} else {
		goto out;
	}

	fence = (slot == set.node->count);

	/* If the key was found delete it, otherwise ignore the request */
	if ((found = (keycmp(ptr, key, len) == 0))) {
		if ((found = !slotptr(set.node, slot)->dead)) {
			dirty = true;
			slotptr(set.node, slot)->dead = 1;
			set.node->dirty = 1;
			set.node->active--;

			/* Collapse empty slots */
			while ((i = (set.node->count - 1))) {
				if (slotptr(set.node, i)->dead) {
					*slotptr(set.node, i) =
						*slotptr(set.node, i+1);
					bzero(slotptr(set.node, set.node->count),
					      sizeof(struct bpt_slot));
					set.node->count--;
				} else {
					break;
				}
			}
		}
	}

	if (!found) {
		bpt_unlocknode(set.latch, BPT_LOCK_WRITE);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
		goto foundkey;
	}

	/* Did we delete a fence key in an upper level? */
	if (dirty && level && set.node->active && fence) {
		if (bpt_fixfence(bpt, &set, level)) {
			goto out;
		}
		goto foundkey;
	}

	/* Is this a collapsed root? */
	if ((level > 1) &&
	    (set.node_no == NODE_ROOT) &&
	    (set.node->active == 1)) {
		if (bpt_collapseroot(bpt, &set)) {
			goto out;
		}
		goto foundkey;
	}

	/* Return if node is not empty */
	if (set.node->active) {
		bpt_unlocknode(set.latch, BPT_LOCK_WRITE);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
		goto foundkey;
	}

	/* Cache a copy of fence key in order to find parent */
	ptr = keyptr(set.node, set.node->count);
	memcpy(lowerkey, ptr, ptr->len + 1);

	/* Pull contents of next node into current empty node */
	right.node_no = bpt_getnodeno(set.node->right);
	right.latch = bpt_pinlatch(bpt, right.node_no);
	bpt_locknode(right.latch, BPT_LOCK_WRITE);

	if ((right.pool = bpt_pinpool(bpt, right.node_no))) {
		right.node = bpt_node(bpt, right.pool, right.node_no);
	} else {
		goto out;
	}

	if (right.node->kill) {
		LOG(ERR, "node(0x%llx) killed\n", right.node_no);
		bpt->status = -1;
		goto out;
	}

	memcpy(set.node, right.node, bpt->mgr->node_size);

	ptr = keyptr(right.node, set.node->count);
	memcpy(higherkey, ptr, ptr->len + 1);

	/* Mark right node as deleted */
	bpt_putnodeno(right.node->right, set.node_no);
	right.node->kill = 1;

	bpt_locknode(right.latch, BPT_LOCK_PARENT);
	bpt_unlocknode(right.latch, BPT_LOCK_WRITE);

	bpt_locknode(set.latch, BPT_LOCK_PARENT);
	bpt_unlocknode(set.latch, BPT_LOCK_WRITE);

	/* Insert new higher key to upper level */
	if (bpt_insertkey(bpt, &higherkey[1], higherkey[0],
			  level+1, set.node_no)) {
		goto out;
	}

	/* Delete old lower key from upper level */
	if (bpt_deletekey(bpt, &lowerkey[1], lowerkey[0], level+1)) {
		goto out;
	}

	/* Acquire write and delete lock on deleted node */
	bpt_unlocknode(right.latch, BPT_LOCK_PARENT);
	bpt_locknode(right.latch, BPT_LOCK_DELETE);
	bpt_locknode(right.latch, BPT_LOCK_WRITE);

	/* Free right node */
	bpt_freenode(bpt, &right);

	/* Remove parent modify lock */
	bpt_unlocknode(set.latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

 foundkey:
	bpt->found = found;
 out:
	return bpt->status;
}

struct bpt_key *bpt_key(bptree_t h, unsigned int slot)
{
	struct bptree *bpt;
	
	bpt = (struct bptree *)h;
	
	return keyptr(bpt->cursor, slot);
}

unsigned int bpt_firstkey(bptree_t h, unsigned char *key,
			  unsigned int len)
{
	struct bptree *bpt;
	struct bpt_node_set set;
	unsigned int slot;

	bpt = (struct bptree *)h;
	
	if ((slot = bpt_loadnode(bpt, &set, key, len, 0, BPT_LOCK_READ))) {
		memcpy(bpt->cursor, set.node, bpt->mgr->node_size);
	} else {
		return 0;
	}

	bpt->cursor_node = set.node_no;

	bpt_unlocknode(set.latch, BPT_LOCK_READ);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

	return slot;
}

unsigned int bpt_nextkey(bptree_t h, unsigned int slot)
{
	struct bptree *bpt;
	struct bpt_node_set set;
	nodeno_t right;

	bpt = (struct bptree *)h;
	
	do {
		right = bpt_getnodeno(bpt->cursor->right);

		for (slot++; slot <= bpt->cursor->count; slot++) {
			if (slotptr(bpt->cursor, slot)->dead) {
				continue;
			} else if (right || (slot < bpt->cursor->count)) {
				/* If no next node then the last slot
				 * is stopper key, don't return it.
				 */
				return slot;
			} else {
				break;
			}
		}
		
		/* No next node, just break out */
		if (right == 0) {
			break;
		}
		
		bpt->cursor_node = right;

		if ((set.pool = bpt_pinpool(bpt, right))) {
			set.node = bpt_node(bpt, set.pool, right);
		} else {
			goto out;
		}

		set.latch = bpt_pinlatch(bpt, right);
		bpt_locknode(set.latch, BPT_LOCK_READ);

		memcpy(bpt->cursor, set.node, bpt->mgr->node_size);

		bpt_unlocknode(set.latch, BPT_LOCK_READ);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);

		slot = 0;
	} while (true);

	bpt->status = 0;
 out:
	return 0;
}

void bpt_getiostat(bptree_t h, struct bpt_iostat *iostat)
{
	struct bptree *bpt;
	struct bpt_iostat *iostat_ptr;

	if (h == NULL) {
		return;
	}

	bpt = (struct bptree *)h;
	iostat_ptr = &bpt->mgr->latchmgr->iostat;
	iostat->pool_maps = __sync_fetch_and_add(&iostat_ptr->pool_maps, 0);
	iostat->pool_unmaps = __sync_fetch_and_add(&iostat_ptr->pool_unmaps, 0);
	iostat->latch_hits = __sync_fetch_and_add(&iostat_ptr->latch_hits, 0);
	iostat->latch_evicts = __sync_fetch_and_add(&iostat_ptr->latch_evicts, 0);
}

void dump_key(struct bpt_key *k)
{
	unsigned int i;

	for (i = 0; i < k->len; i++) {
		printf("%c", k->key[i]);
	}

	printf(" ");
}

void dump_keys_in_node(struct bpt_node *node)
{
	int i;
	struct bpt_key *k;
	unsigned char stopper[] = {0xFF, 0xFF};

	for (i = 1; i <= node->count; i++) {
		/* Prepend a '*' before dead keys */
		if (slotptr(node, i)->dead) {
			printf("[*]");
		}

		/* If this is stopper key, just print a ';' */
		k = keyptr(node, i);
		if (keycmp(k, stopper, sizeof(stopper)) == 0) {
			printf(";");
			continue;
		}

		/* Dump the actual key */
		dump_key(k);
	}
	printf("\n");
}

void dump_bpt_node(struct bpt_node *node)
{
	printf("---------- b+tree node info -----------\n"
	       " count  : %d\n"
	       " active : %d\n"
	       " level  : %d\n"
	       " min    : %d\n"
	       " free   : %d\n"
	       " kill   : %d\n"
	       " dirty  : %d\n"
	       " right  : 0x%llx\n"
	       " keys   : ",
	       node->count, node->active, node->level, node->min,
	       node->free, node->kill, node->dirty, bpt_getnodeno(node->right));

	dump_keys_in_node(node);
}

static int dbg_load_node(int fd, struct bpt_node *node,
			 unsigned int node_size,
			 nodeno_t node_no)
{
	int rc = 0;
	off_t offset;

	if (node_no == NODE_SUPER) {
		return -1;
	}

	offset = node_no * node_size;
	if (pread(fd, node, node_size, offset) != node_size) {
		rc = -1;
	}

	return rc;
}

void dump_free_node_list(int fd, struct bpt_node *alloc,
			 unsigned int node_size)
{
	int rc = 0;
	struct bpt_node *node;
	nodeno_t node_no;

	node = sys_malloc(node_size);
	if (node == NULL) {
		printf("Failed to allocate node!\n");
		return;
	}

	printf("-------- b+tree free node list --------\n");

	node_no = bpt_getnodeno(alloc->right);
	while (node_no) {
		printf("0x%llx->", node_no);
		rc = dbg_load_node(fd, node, node_size, node_no);
		if (rc != 0) {
			printf("Failed to load node 0x%llx, error:%d\n",
			       node_no, rc);
			break;
		}
		node_no = bpt_getnodeno(node->right);
	}

	if (rc == 0) {
		printf("nil\n");
	}

	free(node);
}

#ifdef _BPT_UNITTEST

int main(int argc, char *argv[])
{
	int rc = 0;
	int ret = 0;
	bptree_t h = NULL;
	nodeno_t node_no;
	const char *path = "bpt.dat";
	struct bptree *bpt = NULL;
	struct bpt_mgr *mgr = NULL;
	char *key1 = "test1";
	char *key2 = "test2";
	char *key3 = "test3";
	unsigned int key1_len = strlen(key1);
	unsigned int key2_len = strlen(key2);
	unsigned int key3_len = strlen(key3);
	unsigned int slot;
	int i;
	char key[9];
	unsigned int key_len = sizeof(key);

	mgr = bpt_openmgr(path, BPT_MIN_NODE_SHIFT, 128, 13);
	if (mgr == NULL) {
		fprintf(stderr, "Failed to open bpt_mgr!\n");
		goto out;
	}

	h = bpt_open(mgr);
	if (h == NULL) {
		fprintf(stderr, "Failed to open bptree!\n");
		goto out;
	}

	bpt = (struct bptree *)h;
	
	rc = bpt_insertkey(bpt, (unsigned char *)key1, key1_len, 0, 5);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key1);
		goto out;
	}

	rc = bpt_insertkey(bpt, (unsigned char *)key3, key3_len, 0, 7);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key3);
		goto out;
	}

	rc = bpt_insertkey(bpt, (unsigned char *)key2, key2_len, 0, 6);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key2);
		goto out;
	}

	node_no = bpt_findkey(bpt, (unsigned char *)key2, key2_len);
	if (node_no == 0) {
		fprintf(stderr, "Node not found for key: %s\n", key2);
		goto out;
	} else {
		printf("key %s mapped to node 0x%llx\n", key2, node_no);
	}

	rc = bpt_deletekey(bpt, (unsigned char *)key2, key2_len, 0);
	if (rc != 0) {
		fprintf(stderr, "Failed to delete key: %s\n", key2);
		goto out;
	}

	/* Verify key deletion */
	node_no = bpt_findkey(bpt, (unsigned char *)key2, key2_len);
	if (node_no != 0) {
		fprintf(stderr, "Deleted key found: %s->0x%llx\n", key2, node_no);
		goto out;
	}

	rc = bpt_deletekey(bpt, (unsigned char *)key2, key2_len, 0);
	if (rc != 0) {
		fprintf(stderr, "Delete nonexistent key failed!\n");
		goto out;
	} else if (bpt->found != 0) {
		fprintf(stderr, "Nonexistent key found!\n");
		goto out;
	}

	for (i = 0; i < 512; i++) {
		ret = sprintf(key, "%08x", i);
		assert(ret == 8);
		rc = bpt_insertkey(bpt, (unsigned char *)key, key_len, 0, i);
		if (rc != 0) {
			fprintf(stderr, "Failed to insert key: %s\n", key);
			goto out;
		}
	}

	ret = sprintf(key, "%08x", 87);
	node_no = bpt_findkey(bpt, (unsigned char *)key, key_len);
	if (node_no == 0) {
		fprintf(stderr, "Node not found for key: %s\n", key);
		goto out;
	} else {
		printf("key %s mapped to node 0x%llx\n", key, node_no);
	}

	printf("Key iteration test...\n");
	slot = bpt_firstkey(bpt, (unsigned char *)key, key_len);
	if (slot == 0) {
		fprintf(stderr, "Failed to iterate key: %s\n", key);
		goto out;
	}

	printf("Mass deletion test...\n");
	for (i = 511; i >= 0; i--) {
		ret = sprintf(key, "%08x", i);
		rc = bpt_deletekey(bpt, (unsigned char *)key, key_len, 0);
		if (rc != 0) {
			fprintf(stderr, "Failed to delete key: %s\n", key);
			goto out;
		}
	}

	printf("Done\n");

 out:
	if (mgr) {
		bpt_closemgr(mgr);
	}
	if (h) {
		bpt_close(h);
	}
	return rc;
}

#endif	/* _BPT_UNITTEST */
