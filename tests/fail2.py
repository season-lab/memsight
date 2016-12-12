
def start():
	return 0x400596

def end():
	return [0x4005b3]

def avoid():
	return [0x4005cc]

def do_start(state):
	params = {}
	params['esi'] = state.regs.esi
	params['edi'] = state.regs.edi
	#state.memory.store(0x601040, 0x0, 4)
	#state.memory.store(0x601044, 0x0, 4)
	return params

def do_end(state, params):
	print "EDI: " + str(state.se.any_n_int(params['edi'], 5))
	print "ESI: " + str(state.se.any_n_int(params['esi'], 5))
	print "Constraints:"
	print state.se.constraints
