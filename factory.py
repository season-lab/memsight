import utils
import angr_symbolic_memory
import range_fully_symbolic_memory

def get_angr_symbolic_memory(angr_project):
    mem_memory = None
    reg_memory = None
    #mem_memory = angr_symbolic_memory.SymbolicMemory(angr_project.loader.memory, utils.get_permission_backer(angr_project), 'mem')
    #reg_memory = angr_symbolic_memory.SymbolicMemory(None, None, 'reg', angr_project.arch, endness=angr_project.arch.register_endness)
    return mem_memory, reg_memory

def get_range_fully_symbolic_memory(angr_project):
    mem_memory = range_fully_symbolic_memory.SymbolicMemory(angr_project.loader.memory, utils.get_permission_backer(angr_project), 'mem', None, ) # endness=proj.arch.memory_endness
    return mem_memory, None