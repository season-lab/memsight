## Full writeup on flag 2 found on http://www.ctfhacker.com
## Binary found here: http://csapp.cs.cmu.edu/3e/bomb.tar
import threading
from time import sleep

import angr
import claripy
import logging
from struct import unpack

import sys
import os

import thread

from angr import exploration_techniques

sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from memory import factory

def get_project():
    return angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/bomb", auto_load_libs=False)

def get_state(proj, start, mem_type = 1, remove_options = set()):

    mem_type = int(sys.argv[1]) if len(sys.argv) > 1 else mem_type
    plugins = {}
    if mem_type == 1:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(proj)
        plugins['memory'] = mem_memory

    add_options = None
    #add_options = {angr.options.CACHELESS_SOLVER}

    state = proj.factory.blank_state(addr=start, plugins=plugins, remove_options=remove_options, add_options=add_options)
    if mem_type == 0:
        state.memory.write_strategies.insert(0,
                                                 angr.concretization_strategies.SimConcretizationStrategyRange(
                                                     sys.maxint))
        state.memory.read_strategies.insert(0,
                                                angr.concretization_strategies.SimConcretizationStrategyRange(
                                                    sys.maxint))

    return state

class readline_hook(angr.SimProcedure):
    def run(self):
        pass

class strtol_hook(angr.SimProcedure):
    def run(self, str, end, base):
        return self.state.solver.BVS("flag", 64, explicit_name=True)

def solve_flag_1():

    # shutdown some warning produced by this example
    #logging.getLogger('angr.engines.vex.irsb').setLevel(logging.ERROR)

    proj = get_project()

    start = 0x400ee0
    bomb_explode = 0x40143a
    end = 0x400ef7

    # initial state is at the beginning of phase_one()
    state = get_state(proj, start)

    # a symbolic input string with a length up to 128 bytes
    arg = state.solver.BVS("input_string", 8 * 128)

    # read_line() reads a line from stdin and stores it a this address
    bind_addr = 0x603780

    # bind the symbolic string at this address
    state.memory.store(bind_addr, arg)

    # phase_one reads the string [rdi]
    state.add_constraints(state.regs.rdi == bind_addr)

    # Attempt to find a path to the end of the phase_1 function while avoiding the bomb_explode
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=end, avoid=bomb_explode)

    if simgr.found:
        found = simgr.found[0]
        return found.solver.eval(arg, cast_to=str).rstrip(chr(0)) # remove ending \0
    else:
        raise Exception("angr failed to find a path to the solution :(")

def solve_flag_2():

    proj = get_project()
    bomb_explode = 0x40143a

    # Start analysis at the phase_2 function after the sscanf
    state = get_state(proj, 0x400f0a)

    # Sscanf is looking for '%d %d %d %d %d %d' which ends up dropping 6 ints onto the stack
    # We will create 6 symbolic values onto the stack to mimic this
    for i in xrange(6):
        state.stack_push(state.solver.BVS('int{}'.format(i), 4*8))

    # Attempt to find a path to the end of the phase_2 function while avoiding the bomb_explode
    ex = proj.surveyors.Explorer(start=state, find=(0x400f3c,),
                                 avoid=(bomb_explode,),
                                 enable_veritesting=True)
    ex.run()

    if ex.found:
        found = ex.found[0]

        answer = []

        for _ in xrange(3):
            curr_int = found.solver.eval(found.stack_pop())

            # We are popping off 8 bytes at a time
            # 0x0000000200000001
            # This is just one way to extract the individual numbers from this popped value
            answer.append(str(curr_int & 0xffffffff))
            answer.append(str(curr_int>>32 & 0xffffffff))

        return ' '.join(answer)

def solve_flag_3():

    args = []

    proj = get_project()

    start = 0x400f6a # phase_3 after scanf()
    bomb_explode = 0x40143a
    end = 0x400fc9 # phase_3 before ret

    state = get_state(proj, start)

    # we want to enumerate all solutions... let's have a queue
    queue = [state, ]
    while len(queue) > 0:

        state = queue.pop()
        #print "\nStarting symbolic execution..."

        ex = proj.surveyors.Explorer(start=state, find=(end,),
                                     avoid=(bomb_explode,),
                                     enable_veritesting=True,
                                     max_active=8)
        ex.run()

        #print "Inserting in queue " + str(len(ex.active)) + " paths (not yet finished)"
        for p in ex.active:
            queue.append(p)

        #print "Found states are " + str(len(ex.found))
        #print "Enumerating up to 10 solutions for each found state"

        if ex.found:
            for p in ex.found:
                found = p
                found.stack_pop() # ignore, our args start at offset 0x8

                iter_sol = found.solver.eval_upto(found.stack_pop(), 10) # ask for up to 10 solutions if possible
                for sol in iter_sol:

                    if sol == None:
                        break

                    a = sol & 0xffffffff
                    b = (sol >> 32) & 0xffffffff

                    #print "Solution: " + str(a) + " " + str(b)
                    args.append(str(a) + " " + str(b))

    return args


def solve_flag_4():

    avoid = 0x40143A
    find = 0x401061
    proj = get_project()

    state = get_state(proj, proj.kb.obj.get_symbol('phase_4').rebased_addr, remove_options={angr.options.LAZY_SOLVES})

    state.regs.rdi = 0xABCD

    sm = proj.factory.simulation_manager(state)

    sm.explore(find=find, avoid=avoid)

    found = sm.found[0]

    # stopped on the ret account for the stack
    # that has already been moved
    answer = unpack('II', found.solver.eval(
        found.memory.load(found.regs.rsp - 0x18 + 0x8, 8), cast_to=str))

    return ' '.join(map(str, answer))


def solve_flag_5():

    def is_alnum(state, c):
        # set some constraints on the char, let it
        # be a null char or alphanumeric
        is_num = state.solver.And(c >= ord("0"), c <= ord("9"))
        is_alpha_lower = state.solver.And(c >= ord("a"), c <= ord("z"))
        is_alpha_upper = state.solver.And(c >= ord("A"), c <= ord("Z"))
        is_zero = (c == ord('\x00'))
        isalphanum = state.solver.Or(
            is_num, is_alpha_lower, is_alpha_upper, is_zero)
        return isalphanum

    # getting more lazy, let angr find the functions, and build the CFG
    proj = get_project()

    proj.analyses.CFG()

    start = proj.kb.obj.get_symbol('phase_5').rebased_addr
    avoid = proj.kb.obj.get_symbol('explode_bomb').rebased_addr
    # let's stop at the end of the function
    find = proj.kb.functions.get('phase_5').ret_sites[0].addr

    state = get_state(proj, start,remove_options={angr.options.LAZY_SOLVES})
    # retrofit the input string on the stack
    state.regs.rdi = state.regs.rsp - 0x1000
    string_addr = state.regs.rdi
    sm = proj.factory.simulation_manager(state)
    sm.explore(find=find, avoid=avoid)
    found = sm.found[0]

    mem = found.memory.load(string_addr, 32)
    for i in xrange(32):
        found.add_constraints(is_alnum(found, mem.get_byte(i)))
    return found.solver.eval(mem, cast_to=str).split('\x00')[0]
    # more than one solution could, for example, be returned like this:
    # return map(lambda s: s.split('\x00')[0], found.solver.eval_upto(mem, 10, cast_to=str))


class read_6_ints(angr.SimProcedure):
    answer_ints = []  # class variable
    int_addrs = []

    def run(self, s1_addr, int_addr):
        self.int_addrs.append(int_addr)
        for i in range(6):
            bvs = self.state.solver.BVS("phase6_int_%d" % i, 32)
            self.answer_ints.append(bvs)
            self.state.mem[int_addr].int.array(6)[i] = bvs

        return 6

def solve_flag_6():
    start = 0x4010f4
    read_num = 0x40145c
    find = 0x4011f7
    avoid = 0x40143A
    p = get_project()
    p.hook(read_num, read_6_ints())
    state = get_state(p, start,remove_options={angr.options.LAZY_SOLVES})
    sm = p.factory.simulation_manager(state)
    sm.explore(find=find, avoid=avoid)
    found = sm.found[0]

    answer = [found.solver.eval(x) for x in read_6_ints.answer_ints]
    return ' '.join(map(str, answer))

def solve_secret():
    start = 0x401242
    find = 0x401282
    avoid = (0x40127d, 0x401267,)
    readline = 0x40149e
    strtol = 0x400bd0

    p = get_project()
    p.hook(readline, readline_hook)
    p.hook(strtol, strtol_hook)
    state = get_state(p, start,remove_options={angr.options.LAZY_SOLVES})
    flag = claripy.BVS("flag", 64, explicit_name=True)
    state.add_constraints(flag -1 <= 0x3e8)
    sm = p.factory.simulation_manager(state)
    sm.explore(find=find, avoid=avoid)
    ### flag found
    found = sm.found[0]
    flag = found.solver.BVS("flag", 64, explicit_name="True")
    return str(found.solver.eval(flag))

def main():
    print "Flag    1: " + solve_flag_1()
    print "Flag    2: " + solve_flag_2()
    print "Flag(s) 3: " + str(solve_flag_3())
    print "Flag    4: " + solve_flag_4()
    print "Flag    5: " + solve_flag_5()
    print "Flag    6: " + solve_flag_6()
    print "Secret   : " + solve_secret()

def test():

    assert solve_flag_1() == 'Border relations with Canada have never been better.'
    print "Phase #1 OK"

    assert solve_flag_2() == '1 2 4 8 16 32'
    print "Phase #2 OK"

    args_3 = ["0 207", "1 311", "2 707", "3 256", "4 389", "5 206", "6 682", "7 327"]
    res_3 = solve_flag_3()
    assert len(res_3) == len(args_3)
    for s in args_3:
        assert s in res_3
    print "Phase #3 OK"

    assert solve_flag_4() == '7 0'
    print "Phase #4 OK"

    assert solve_flag_5().lower() == 'ionefg'
    print "Phase #5 OK"

    assert solve_flag_6() == '4 3 2 1 6 5'
    print "Phase #6 OK"

    assert solve_secret() == '22'
    print "Phase #6+ OK"

def travis_keep_alive():
    # travis kills a job if not output is emitted
    while True:
        sleep(60 * 2)
        print "Alive..."

if __name__ == '__main__':

    # logging.basicConfig()
    # logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

    t = threading.Thread(target=travis_keep_alive)
    t.setDaemon(True)
    t.start()

    import time
    start_time = time.time()
    test()
    print "Elapsed time: " + str(time.time() - start_time)
