#!/usr/bin/env python2

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../../../'))

from memory import factory

FIND_ADDR = 0x08048533 # mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x8048654
AVOID_ADDR = 0x08048554 # mov dword [esp], str.Wrong_ ; [0x804865e:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x804865e


def main(mem_type = 1):
	proj = angr.Project(os.path.dirname(os.path.realpath(__file__)) + '/crackme0x00a', load_options={"auto_load_libs": False})

	plugins = {}
	if mem_type == 1:
		mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(proj)
		plugins['memory'] = mem_memory

	initial_state = proj.factory.entry_state(plugins=plugins)

	sm = proj.factory.simulation_manager(initial_state)
	sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)
	return sm.found[0].posix.dumps(0).split('\0')[0] # stdin

def test():
	assert main() == 'g00dJ0B!'

if __name__ == '__main__':
	import time

	start_time = time.time()
	test()
	print "Elapsed time: " + str(time.time() - start_time)