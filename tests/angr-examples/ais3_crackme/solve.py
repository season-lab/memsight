#!/usr/bin/env python

'''
ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3.

It is an easy crackme challenge. It checks the command line argument.
'''

import angr
import claripy
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from memory import factory

def main(mem_type = 1):
    project = angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/ais3_crackme")

    plugins = {}
    if mem_type == 1:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(project)
        plugins['memory'] = mem_memory

    #create an initial state with a symbolic bit vector as argv1
    argv1 = claripy.BVS("argv1",100*8) #since we do not the length now, we just put 100 bytes
    initial_state = project.factory.entry_state(args=["./crackme1",argv1],
                                                plugins=plugins)

    #create a path group using the created initial state 
    sm = project.factory.simulation_manager(initial_state)

    #symbolically execute the program until we reach the wanted value of the instruction pointer
    sm.explore(find=0x400602) #at this instruction the binary will print the "correct" message

    found = sm.found[0]
    #ask to the symbolic solver to get the value of argv1 in the reached state as a string
    solution = found.solver.eval(argv1, cast_to=str)

    solution = solution[:solution.find("\x00")]
    return solution


def test():
    res = main()
    assert res == "ais3{I_tak3_g00d_n0t3s}"


if __name__ == '__main__':
    import time
    start_time =time.time()
    test()
    print "Elapsed time: " + str(time.time()-start_time)


