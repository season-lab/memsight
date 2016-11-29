import simple_fully_symbolic_memory
import executor
import sys

if __name__ == '__main__':

    explorer = executor.Executor(sys.argv[1])
    angr_project = explorer.project

    mem_memory = simple_fully_symbolic_memory.FullSymbolicMemory(angr_project.loader.memory, None, 'mem', None, ) # endness=proj.arch.memory_endness
    reg_memory = simple_fully_symbolic_memory.FullSymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)

    explorer.explore(mem_memory = mem_memory, reg_memory = reg_memory)