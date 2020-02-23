#ifndef __BPT_PRIVATE_H__
#define __BPT_PRIVATE_H__

#include "lock.h"

#define NODE_SUPER	0	// node 0 is always reserved for super block
#define NODE_ALLOC	1	// alloc node is the head of free node list
#define NODE_ROOT	2	// root is always located at node 2
#define NODE_LEAF	3	// the first leaf node of level zero is always located at node 2
#define NODE_LATCH	4	// node for latch manager

#define BPT_BUF_NODES	3

#define BPT_LATCH_TABLE	128	// number of latch manager slots

/* maximum addressable space is 6-bytes integer * max-node-size */
#define NODE_NUM_BYTES	6	

/* stopper key is 2 bytes, plus 1 byte for key length, so 3 bytes */
#define STOPPER_KEY_LEN	3

/* minimum level of a new b+tree */
#define MIN_LEVEL	2

struct bpt_super_block {
	char magic[16];
	unsigned int major;
	unsigned int minor;
	unsigned int node_bits;
};

typedef enum {
	BPT_LOCK_ACCESS,
	BPT_LOCK_DELETE,
	BPT_LOCK_READ,
	BPT_LOCK_WRITE,
	BPT_LOCK_PARENT
} bpt_mode_t;

struct bpt_slot {
	unsigned int offset:BPT_MAX_NODE_SHIFT;	// node offset for the key
	unsigned int dead:1;	// set for deleted key
	unsigned int reserved:17;
	unsigned char node_no[NODE_NUM_BYTES]; // child node associated with slot
};

struct bpt_key {
	unsigned char len;
	unsigned char key[0];
};

/* macros to address slot and keys within the node.
 * node slots index beginning from 1.
 */
#define slotptr(node, slot) (((struct bpt_slot *)(node+1)) + (slot-1))
#define keyptr(node, slot) ((struct bpt_key *)((char *)(node) + slotptr(node, slot)->offset))

/* b+tree node latch */
struct bpt_latch {
	struct rwlock rdwr;	// read/write access lock
	struct rwlock parent;	// parent update lock
	struct rwlock access;	// access intent/node delete
	struct spin_rwlock busy;
	volatile unsigned short prev;	// prev entry in hash table chain
	volatile unsigned short next;	// next entry in hash table chain
	volatile unsigned short pin;	// number of outstanding locks
	volatile unsigned short hashv;	// hash value
	volatile nodeno_t node_no;	// latch node number
};

struct latch_hash_bucket {
	struct spin_rwlock lock;
	/* head of the latch hash bucket */
	volatile unsigned short slot;
};

/* b+tree node layout
 * +---------------------+      -
 * |     node header     |      ^
 * |              +------+      |
 * |              |right-+------+--------->next sibling
 * +--------------+------+      |
 * |       slots.offset--+--+   |
 * |       slots.node_no-+--+---+--------->child
 * |       ...           |  |   |
 * +---------------------+  |  node size
 * |     free space      |  |   |
 * +---------------------+  |   |
 * |      bpt keys       |  |   |
 * |       ...           |<-+   v
 * +---------------------+      -
 */
struct bpt_node {
	unsigned int count;	// number of keys in node
	unsigned int active;	// number of active keys
	unsigned int min;	// next key offset
	unsigned char free:1;	// node is on free list
	unsigned char kill:1;	// node is being deleted
	unsigned char dirty:1;	// node is dirty
	unsigned char reserved:5;
	bpt_level_t level;	// node level in the tree
	unsigned char right[NODE_NUM_BYTES]; // Next node number
};

/* node pool */
struct bpt_pool {
	nodeno_t basenode;	// mapped base node number
	char *map;		// mapped memory pointer
	unsigned short slot;
	unsigned short pin;	// mapped node pin counter
	struct bpt_pool *hash_prev;
	struct bpt_pool *hash_next;
};

#define CLOCK_BIT	0x8000	// bit for pool->pin

struct bpt_node_set {
	nodeno_t node_no;
	struct bpt_node *node;  // the b+tree node itself
	struct bpt_pool *pool;	// node pool this node lies on
	struct bpt_latch *latch;
};

/* b+tree latch manager
 * +-----------------------+  -
 * |        alloc[1]       |  ^
 * |        alloc[2]       |  |
 * +-----------------------+ node size
 * |      other fields     |  |
 * +-------+-------+-------+<-+----- latch_tbl
 * | lock  |  ...  | lock  |  |
 * | slot  |       | slot  |  v
 * +-------+-------+-------+  -
 */
struct bpt_latch_mgr {
	struct bpt_node alloc[2];
	struct bpt_iostat iostat;// I/O statistics info
	struct spin_rwlock lock;
	unsigned short latch_deployed;
	unsigned short nr_latch_nodes;
	unsigned short nr_latch_total;
	unsigned short victim;
	unsigned short tbl_size;
	struct latch_hash_bucket latch_tbl[0];
};

struct bpt_mgr {
	unsigned int node_size;
	unsigned int node_bits;
	unsigned int seg_bits;	// segment size in nodes in bits
	int fd;			// index file descriptor

	int pool_cnt;		// current number of node pool
	int pool_max;		// maximum number of node pool
	int pool_mask;		// number of nodes in segments - 1
	int tbl_size;		// size of node segments pool hash table

	/* last evicted pool hash table entry */
	volatile unsigned int evicted;
	unsigned short *pool_tbl;// hash table for node segments pool

	/* locks for pool hash table */
	struct spin_rwlock *pool_tbl_locks;
	
	/* mapped latch node from allocation node */
	struct bpt_latch_mgr *latchmgr;

	/* mapped latches from latch nodes */
	struct bpt_latch *latches;

	struct bpt_pool *pools;	// node segments pool
};

/* b+tree handle */
struct bptree {
	struct bpt_mgr *mgr;	// b+tree manager
	int status;		// status of last operation
	nodeno_t cursor_node;	// current cursor node number
	struct bpt_node *cursor;// cached frame for first/next
	struct bpt_node *frame;	// spare frame for node split
	struct bpt_node *zero;	// zeros frame buffer (never mapped)
	unsigned char *mem;

	/* deletekey returns OK even when the key does not exist.
	 * This is used to indicate whether the key was found in tree.
	 */
	int found;
};

#endif	/* __BPT_PRIVATE_H__ */
