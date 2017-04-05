#!/usr/bin/python

import sys 
from pitree import pitree 

# test
def main(args):
    t = pitree()
    t.add(2400, 3290, "one")
    t.add(1250, 2913, "two")
    t.add(2999, 4600, "three")
    t.add(1639, 3007, "four")
    r = t.copy()
    for i in r.search(123, 2400):
        r.update_item(i, i.data + "*")
        print i.begin, " ", i.end, " ", i.data
    print r
    return 0

if __name__ == "__main__":
   main(sys.argv[1:])

