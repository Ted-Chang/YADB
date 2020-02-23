#ifndef __BPTDEF_H__
#define __BPTDEF_H__

/* Minimum page size 512 bytes and max page size 64K */
#define BPT_MAX_PAGE_SHIFT	(16)
#define BPT_MIN_PAGE_SHIFT	(12)
#define BPT_MAX_PAGE_SIZE	(1 << BPT_MAX_PAGE_SHIFT)
#define BPT_MIN_PAGE_SIZE	(1 << BPT_MIN_PAGE_SHIFT)

/* super block info */
#define BPT_MAGIC	"BPLUSTREE"
#define BPT_MAJOR	1
#define BPT_MINOR	0

#endif	/* __BPTDEF_H__ */
