#!/usr/bin/python

import sys
from runner import runner 

class profiler(runner):

    def __init__(self):
        profiler.__init__(self)

    def print_report(self):
        return

# test
def main(args):
     print "opening log file %s" % args[0]
     t = profiler()
     t.run(args[0])
     t.print_report()
     return 0

if __name__ == "__main__":
   main(sys.argv[1:])