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

