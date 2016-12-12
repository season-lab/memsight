
def start():
	return 0x400526

def end():
	return [0x400547]

def avoid():
	return [0x400564]

def do_start(state):
	params = {}
	params['esi'] = state.regs.esi
	params['edi'] = state.regs.edi
	return params

def do_end(state, params):
	print "EDI: " + str(state.se.any_n_int(params['edi'], 5))
	print "ESI: " + str(state.se.any_n_int(params['esi'], 5))
	print "Constraints:"
	print state.se.constraints
