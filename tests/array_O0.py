
def start():
	return 0x400526

def end():
	return [0x40055d]

def avoid():
	return [0x400576, 0x400577]

def do_start(state):
	return None

def do_end(state, params):
	pass
