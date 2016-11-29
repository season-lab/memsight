import executor
import sys
import factory
import utils

if __name__ == '__main__':

    t, file = utils.parse_args(sys.argv)

    explorer = executor.Executor(file)
    angr_project = explorer.project

    if t == 0:
        mem_memory, reg_memory = factory.get_simple_full_symbolic_memory(angr_project)
    elif t == 1:
        mem_memory, reg_memory = factory.get_angr_symbolic_memory(angr_project)

    explorer.explore(mem_memory = mem_memory, reg_memory = reg_memory)