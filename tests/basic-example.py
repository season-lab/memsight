def start():
	return 0x400576

def end():
	return [0x4005bc]

def avoid():
	return [0x4005d5]

def do_start(state):
	params = {}
	params['edi'] = state.regs.edi
	params['esi'] = state.regs.esi
	return params

def do_end(state, params):
	print state.se.any_int(params['esi'])
	print state.se.any_int(params['edi'])
	print "Constraints:"
	print state.se.constraints
