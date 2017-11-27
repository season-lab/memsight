
def start():
	return 0x804e120

def end():
	return [] #  

def avoid():
	return [0x0, ] # 0x804e3b7, 0x804e3da

def do_start(state):

	import claripy

	state.memory.map_region(0xABCD, 32, claripy.BVV(0x3, 3))

	buf_size = 32
	buf = claripy.BVS('buffer', buf_size * 8)
	buf = claripy.Concat(buf, claripy.BVV(0x0, 8))
	state.memory.store(0xABCD, buf, len(buf) / 8)
	
	state.stack_push(92) # "\"
	state.stack_push(0x0)

	state.stack_push(0x0) # a fake ret addr

	state.stack_push(0x804e120) # a fake ret addr

	state.stack_push(92) # "\"
	state.stack_push(0xABCD)

	state.stack_push(0x804e495) # a fake ret addr

	params = {}
	params['buf'] = buf
	params['veritesting'] = True
	return params

def do_end(state, params, pg):

	import pdb
	pdb.set_trace()

	"""
	o = state.se.Concat(params['edi'], state.regs.eax)
	sol = state.se.eval_upto(o, 10)
	import ctypes
	eax = []
	edi = []
	for k in range(len(sol)):
		edi.append(ctypes.c_int((sol[k] & (0xFFFFFFFF << 32)) >> 32).value)
		eax.append(ctypes.c_int(sol[k] & 0xFFFFFFFF).value)
		assert edi[-1] == eax[-1]

	assert len(edi) == 9
	assert len(eax) == 9
	print "I: " + str(edi)
	print "SUM:" + str(eax)
	"""

	pass