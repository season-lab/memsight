#!/usr/bin/python

import sys, collections
from pitree import pitree 
from untree import Untree


class tester:

    countdown = 0

    ttype = collections.namedtuple('ttype', 'pitree untree')

    def __init__(self):
        self.trees = dict()
        self.cnt   = 1

    @classmethod
    def do_test(cls, filename):
        t = tester()
        for op in tester._read_log_file(filename):
            t._do_op(op)

    def _do_op(self, op):
        parms = map(lambda i: int(i), op[1:])
        if   op[0] == 'c': self._do_copy(parms)
        elif op[0] == 'a': self._do_add(parms)
        elif op[0] == 'u': self._do_update(parms)
        elif op[0] == 'n': self._do_new(parms)
        elif op[0] == 's': self._do_search(parms)
        else:              raise ValueError("unknown operation " + str(op[0]))
        self.cnt += 1

    def _do_copy(self, parms):
        print "%d copy %s" % (self.cnt, str(parms))
        assert parms[0] in self.trees
        assert parms[1] not in self.trees
        t = self.trees[parms[0]]
        self.trees[parms[1]] = self.ttype(t.pitree.copy(), t.untree.copy())
        self._check_trees(parms[0])
        self._check_trees(parms[1])

    def _do_add(self, parms):
        print "%d add %s" % (self.cnt, str(parms))
        assert parms[0] in self.trees
        t = self.trees[parms[0]]
        t.pitree.add(parms[1], parms[2], parms[3])
        t.untree.add(parms[1], parms[2], parms[3])
        self._check_trees(parms[0])

    def _do_update(self, parms):
        print "%d update %s" % (self.cnt, str(parms))
        assert parms[0] in self.trees
        t = self.trees[parms[0]]
        i_pitree = None
        for i in t.pitree.search(0, sys.maxint):
            if i.data == parms[1]:
                assert i_pitree == None
                i_pitree = i
        i_untree = None
        for i in t.untree.search(0, sys.maxint):
            if i.data == parms[1]:
                assert i_untree == None
                i_untree = i
        t.pitree.update_item(i_pitree, parms[2])
        t.untree.update_item(i_untree, parms[2])
        self._check_trees(parms[0])

    def _do_new(self, parms):
        print "%d new %s" % (self.cnt, str(parms))
        assert parms[0] not in self.trees
        t = self.ttype(pitree(), Untree())
        self.trees[parms[0]] = t
        self._check_trees(parms[0])

    def _do_search(self, parms):
        print "%d search %s" % (self.cnt, str(parms))
        assert parms[0] in self.trees
        t =  self.trees[parms[0]]
        s_pitree = tester._tree2set(t.pitree, parms[1], parms[2])
        s_untree = tester._tree2set(t.untree, parms[1], parms[2])
        if not tester._check_sets(s_pitree, s_untree, "### search(%d, %d) error: " % (parms[1], parms[2])):
            self._dump_tree(parms[0])
            sys.exit(1)
        self._check_trees(parms[0])

    def _dump_tree(self, tree_id):
        assert tree_id in self.trees
        f = open("dump.log", "w") 
        f.write("n,%d\n" % tree_id)
        t = self.trees[tree_id]
        for i in t.untree.search(0, sys.maxint):
            f.write("a,%d,%d,%d,%d\n" % (tree_id, i.begin, i.end, i.data))
        f.close()

    def _check_trees(self, tree_id):
        t = self.trees[tree_id]
        s_pitree = tester._tree2set(t.pitree)
        s_untree = tester._tree2set(t.untree)
        if not tester._check_sets(s_pitree, s_untree, "### misaligned trees error"):
            self._dump_tree(tree_id)
            sys.exit(1)

    @classmethod
    def _tree2set(cls, t, begin=0, end=sys.maxint):
        s = set()
        for i in t.search(begin, end):
            s.add((i.begin, i.end, i.data))
        return s

    @classmethod
    def _check_sets(cls, s_pitree, s_untree, msg):
        if s_pitree != s_untree:
            print msg
            print "    s_pitree - s_untree = " + str(s_pitree - s_untree)
            print "    s_untree - s_pitree = " + str(s_untree - s_pitree)
            return False
        # tester.countdown += 1
        # if (tester.countdown == 100): return False
        return True

    @classmethod
    def _read_log_file(cls, filename):
        f = open(filename, "r") 
        for line in f:
            yield line.replace("\n","").split(",")

# test
def main(args):
     print "opening log file %s" % args[0]
     tester.do_test(args[0])
     return 0

if __name__ == "__main__":
   main(sys.argv[1:])
