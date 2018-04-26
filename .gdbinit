define pgdump
    dump binary memory /tmp/tedzhan9-pgdump.bin ($arg0) (($arg0)+($arg1))
    shell ./pgdump < /tmp/tedzhan9-pgdump.bin
end
document pgdump
Dump a page in b+tree with pgdump
Example usage: pgdump ADDRESS LENGTH
end
