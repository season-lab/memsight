import claripy

def start():
    return 0x4004d6

def end():
    return [0x4004ff]

def avoid():
    return []

def do_start(state):
    params = {}
    state.regs.edi = claripy.BVS('edi_i', 32)
    params['edi'] = state.regs.edi
    params['veritesting'] = True
    #params['max_rounds'] = 2
    state.se.add(params['edi'] < 9)
    return params

def do_end(state, params, pg, verbose=True):

    n = state.memory.load(state.regs.rbp - 4, 4).reversed

    o = state.se.Concat(params['edi'], n)
    sol = state.se.eval_upto(o, 10)
    import ctypes
    eax = []
    edi = []
    for k in range(len(sol)):
        edi.append(ctypes.c_int((sol[k] & (0xFFFFFFFF << 32)) >> 32).value)
        eax.append(ctypes.c_int(sol[k] & 0xFFFFFFFF).value)

    assert len(edi) == 9
    assert len(set(eax)) == 8

    if verbose:
        print "I: " + str(edi)
        print "SUM:" + str(eax)
