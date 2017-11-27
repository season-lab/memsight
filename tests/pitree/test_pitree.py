import os, sys, traceback
from bcolors import bcolors

currDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(currDir, '../../memory/lib/pitree'))
if rootDir not in sys.path: # add parent dir to paths
    sys.path.append(rootDir)
from pitree import *

def test_1():
    t = pitree()
    t.add(1, 200)
    ris = t.search(20, 25)
    assert len(ris) == 1 and ris.pop() == Interval(1, 200)

def test_2():
    t = pitree()
    t.add(1, 200)
    i = t._pages.root.child.interval
    assert i.begin == 0 and i.end == 2

def test_3():
    t = pitree()
    t.add(1, 20)
    t.add(2, 30)
    t.add(130, 140)
    assert len(t._pages) == 2 and len(t._pages.root.child.interval.data.tree) == 2 and len(t._pages.root.child.right_child.interval.data.tree) == 1

def test_4():
    t = pitree()
    t.add(1, 20)
    tt = t.copy()
    assert t._lazycopy and tt._lazycopy and t._pages == tt._pages

def test_5(): # TODO improvement: check if the tree is actually shared, in some cases copy without actual sharing
              # in this example, if I write in t, i will copy the tree even if it is not necessary, since tt has 
              # copied it already.
    t = pitree()
    t.add(1, 20)
    tt = t.copy()
    tt.add(2, 30)
    assert t._lazycopy and not tt._lazycopy and t._pages != tt._pages

def test_6(): # same problem as before
    t = pitree()
    t.add(1, 20)
    t.add(200, 300)
    tt = t.copy()
    tt.add(2, 30)
    assert t._lazycopy and not tt._lazycopy and t._pages != tt._pages                                                         and \
           t._pages.root.child.right_child.interval.data.tree == tt._pages.root.child.right_child.interval.data.tree          and \
           t._pages.root.child.right_child.interval.data.lazycopy and tt._pages.root.child.right_child.interval.data.lazycopy and \
           t._pages.root.child.interval.data.lazycopy and not tt._pages.root.child.interval.data.lazycopy

def test_7():
    t = pitree()
    t.add(10, 20)
    t.add(30, 35)
    t.add(20, 30)
    t.add(100, 200)
    t.add(200, 300)
    t.add(0, 5)
    t.add(5, 30)
    t.add(129, 130)

    ris = t.search(30, 99)
    expected = set([Interval(20, 30), Interval(5, 30), Interval(30, 35)])
    assert ris == expected

def test_8():
    t = pitree()
    t.add(10, 20)
    t.add(20, 30)
    t.add(90, 100)
    t.add(100, 200)
    t.add(200, 300)
    t.add(0, 5)
    t.add(5, 30)
    t.add(129, 130)

    ris = t.search(31, 100)
    expected = set([Interval(100, 200), Interval(90, 100)])
    assert ris == expected

if __name__=="__main__":
    print "- Test 1"
    try:
        test_1()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 2"
    try:
        test_2()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 3"
    try:
        test_3()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 4"
    try:
        test_4()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 5"
    try:
        test_5()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 6"
    try:
        test_6()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 7"
    try:
        test_7()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 8"
    try:
        test_8()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"