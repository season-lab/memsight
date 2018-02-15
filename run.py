import sys
import logging

from executor import executor
from memory import factory
from memory import range_fully_symbolic_memory
from utils import parse_args

if __name__ == '__main__':

    #logging.getLogger('angr').setLevel(logging.DEBUG)

    t, file = parse_args(sys.argv)

    explorer = executor.Executor(file)
    angr_project = explorer.project

    if t == 0:
        mem_memory, reg_memory = factory.get_angr_symbolic_memory(angr_project)
    elif t == 1:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(angr_project)

    explorer.run(mem_memory = mem_memory, reg_memory = reg_memory)

    if t == 1 and range_fully_symbolic_memory.profiling_enabled:
        range_fully_symbolic_memory.print_profiling_time_stats()