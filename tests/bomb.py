def start():
	return 0x401062

def end():
	return [0x4010ee]

def avoid():
	return [0x40143a, 0x4010e9]

def do_start(state):

	arg = None
	for k in range(0, 128):
	    o = state.se.BVS("input_string_" + str(k), 8)
	    state.se.add(state.se.Or(state.se.And(o >= 60, o <= 127), o == 0))

	    if arg == None:
	        arg = o
	    else:
	        arg = state.se.Concat(arg, o)

	# an address where to store my arg
	bind_addr = 0x603780

	# bind the symbolic string at this address
	state.memory.store(bind_addr, arg)

	# phase_5 reads the string [rdi]
	state.regs.rdi = bind_addr

	# make rsi concrete to avoid few uninteresting states
	state.regs.rsi = 0x0

	params = {}
	params['arg'] = arg
	return params

def do_end(state, params):
	print state.se.any_str(params['arg'])
	print state.se.constraints
