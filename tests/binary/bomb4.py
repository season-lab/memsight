from struct import unpack

def start():
    return 0x40100c

def end():
    return [0x401061]

def avoid():
    return [0x40143A]

def hook(state):
    state.memory.store(state.regs.rcx, state.solver.BVS("a1", 32))
    state.memory.store(state.regs.rdx, state.solver.BVS("a2", 32))
    state.regs.rax = 2

def do_start(state):
    state.regs.rdi = 0xABCD
    #state.project.hook(0x401024, hook, length=5)
    params = {}
    return params

def do_end(state, params, pg, verbose=True):

    answer = unpack('II', state.solver.eval(
        state.memory.load(state.regs.rsp - 0x18 + 0x8, 8), cast_to=str))

    print ' '.join(map(str, answer))