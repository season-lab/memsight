
def start():
	return 0x400526

def end():
	return [0x40055d]

def avoid():
	return [0x400576, 0x400577]

def do_start(state):
	params = {}
	params['esi'] = state.regs.esi
	params['edi'] = state.regs.edi
	state.memory.store(0x601040, 0x0, 4)
	state.memory.store(0x601044, 0x0, 4)
	return params

def do_end(state, params):
	print "EDI: " + str(state.se.any_int(params['edi']))
	print "ESI: " + str(state.se.any_int(params['esi']))
	print "Constraints:"
	print state.se.constraints