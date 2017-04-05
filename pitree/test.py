#!/usr/bin/python

import sys 
from pitree import pitree 

# test
def main(args):
    t = pitree()
    t.add(2400, 3290, "one")
    t.add(1250, 2913, "two")
    t.add(2999, 4600, "three")
    print t.search(123, 2400)
#    r = t.copy()
#    print r
    return 0

if __name__ == "__main__":
   main(sys.argv[1:])

