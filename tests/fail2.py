
def start():
	return 0x400596

def end():
	return [0x4005b3]

def avoid():
	return [0x4005cc]

def do_start(state):
	params = {}
	params['edi'] = state.regs.edi
	return params

def do_end(state, params):
	print "EDI: " + str(state.se.any_n_int(params['edi'], 5))
	print "Constraints:"
	print state.se.constraints
