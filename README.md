# YADB
Yet Another DataBase

## Debugging

### Dump b+tree page content with gdb

```
(gdb) p dump_bpt_page(set.page)
---------- b+tree page info -----------
 count  : 2
 active : 2
 level  : 0
 min    : 4087
 free   : 0
 kill   : 0
 dirty  : 0
 right  : 0xb
 keys   : test1 ;
$1 = void
```

### Dump b+tree free page list with gdb
```
(gdb) p dump_free_page_list(mgr->fd, &mgr->latchmgr->alloc[1], mgr->page_size)
-------- b+tree free page list --------
0x1b->0x1a->0x19->0x18->0x17->0x16->0x15->0x14->0x13->0x12->0x11->0x10->0xf->0xe->0xd->0xc->0xb->nil
$1 = void
```
