import sys, traceback
sys.path.append('../../memory/lib/pitree')
from node import *
from interval import *
from intervaltree import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def test_1():
    it = IntervalTree()
    it.add(Interval(1,5))
    it.add(Interval(5,10))
    ris = it.search(5)
    assert len(ris) == 2 and ris[0] == Interval(1, 5) and ris[1] == Interval(5, 10)

def test_2():
    it = IntervalTree()
    it.add(Interval(1,5))
    it.add(Interval(6,9))
    ris = it.search(6)
    assert len(ris) == 1 and ris[0] == Interval(6,9)

def test_3(): # left rotation
    it = IntervalTree()
    it.add(Interval(1,5))
    it.add(Interval(2,6))
    it.add(Interval(3,7))
    assert it.root.child.interval == Interval(2,6)

def test_4(): # right + left rotation
    it = IntervalTree()
    it.add(Interval(0,5))
    it.add(Interval(6,9))
    it.add(Interval(2,6))
    r = it.root.child
    assert r.interval == Interval(2,6) and r.left_child.interval == Interval(0,5) and r.right_child.interval == Interval(6,9)

def test_5(): # right rotation
    it = IntervalTree()
    it.add(Interval(3,7))
    it.add(Interval(2,6))
    it.add(Interval(1,5))    
    assert it.root.child.interval == Interval(2,6)

def test_6(): # left + right rotation
    it = IntervalTree()
    it.add(Interval(6,9))
    it.add(Interval(0,5))
    it.add(Interval(2,6))
    r = it.root.child
    assert r.interval == Interval(2,6) and r.left_child.interval == Interval(0,5) and r.right_child.interval == Interval(6,9)

def test_7(): # parent
    it = IntervalTree()
    it.add(Interval(2,6))
    it.add(Interval(0,5))
    it.add(Interval(6,9))
    r = it.root.child
    assert r.parent.interval == "ROOT" and r.left_child.parent.interval == Interval(2,6) and r.right_child.parent.interval == Interval(2,6)

def test_8(): # addi and all the same lower interval
    it = IntervalTree()
    it.addi(2,6)
    it.addi(2,5)
    it.addi(2,3)
    ris = it.search(0,2)
    expected = set([Interval(2,6), Interval(2,5), Interval(2,3)])
    assert len(ris) == 3 and set(ris) == expected

def test_9(): # data
    it = IntervalTree()
    i1 = Interval(0, 5, "one")
    i2 = Interval(3, 7, "two")
    it.add(i1); it.add(i2)
    ris = it.search(0,1)
    assert len(ris) == 1 and ris[0] == i1 and ris[0].data == "one"

def test_10(): # iterator
    it = IntervalTree()
    it.addi(1,2); it.addi(2,3); it.addi(3,4); it.addi(5,6)
    expected = set([Interval(1,2), Interval(2,3), Interval(3,4), Interval(5,6)])
    ris = set()
    for el in it:
        ris.add(el)
    assert ris == expected

def test_11(): # len
    it = IntervalTree()
    it.addi(1,4); it.addi(7,90)
    assert len(it) == 2

def test_12(): # same interval added more than one time
    it = IntervalTree()
    it.addi(1,4); it.addi(1,4)
    ris = []
    for el in it:
        ris.append(el)
    assert len(ris) == 2 and ris[0] == ris[1] and ris[1] == Interval(1,4)

if __name__ == "__main__":
    print "- Test 1"
    try:
        test_1()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 2"
    try:
        test_2()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 3"
    try:
        test_3()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 4"
    try:
        test_4()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 5"
    try:
        test_5()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 6"
    try:
        test_6()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 7"
    try:
        test_7()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 8"
    try:
        test_8()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 9"
    try:
        test_9()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 10"
    try:
        test_10()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 11"
    try:
        test_11()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"

    print "- Test 12"
    try:
        test_12()
    except:
        print bcolors.FAIL + "  Not passed" + bcolors.ENDC
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
    print bcolors.OKGREEN + "  Passed" + bcolors.ENDC + "\n"