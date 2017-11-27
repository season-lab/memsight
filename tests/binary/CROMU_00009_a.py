
def start():
	return None

def end():
	return [] #[0x804e3a2] 
	
def avoid():
	return []

def do_start(state):

	import claripy

	#buf = [0x1, 0xf5, 0xa]
	buf = [0x40, 0x20, 0xa]
	for i in range(len(buf)):
		c = state.posix.files[0].read_from(1)
		state.se.add(c == buf[i])
	state.posix.files[0].size = len(buf)
	state.posix.files[0].length = len(buf)
	state.posix.files[0].seek(0)
	
	params = {}
	#params['veritesting'] = True
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