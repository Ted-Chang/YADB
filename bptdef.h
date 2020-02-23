#ifndef __BPTDEF_H__
#define __BPTDEF_H__

/* Minimum node size 512 bytes and max node size 64K */
#define BPT_MAX_NODE_SHIFT	(16)
#define BPT_MIN_NODE_SHIFT	(12)
#define BPT_MAX_NODE_SIZE	(1 << BPT_MAX_NODE_SHIFT)
#define BPT_MIN_NODE_SIZE	(1 << BPT_MIN_NODE_SHIFT)

/* super block info */
#define BPT_MAGIC	"BPLUSTREE"
#define BPT_MAJOR	1
#define BPT_MINOR	0

#endif	/* __BPTDEF_H__ */
