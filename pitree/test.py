#!/usr/bin/python

import sys 
from pitree import pitree 

# test
def main(args):
    t = pitree()
    t.add(2400, 3290, "hello")
    r = t.clone()
    print r
    return 0

if __name__ == "__main__":
   main(sys.argv[1:])

