import sys
import os

n = int(sys.argv[1])
tests = ['basic-example', 'array_O0', 'fail', 'fail2', 'fail3', 'fail4', 'fail5', 'bomb', 'merge']

print
print "Running tests using memory n=" + str(n)
print

for t in tests:
	print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	print "% TEST: " + t
	print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
	b = os.path.dirname(os.path.realpath(sys.argv[0])) + '/' + t
	os.system('time -p python -u ' + os.path.dirname(os.path.realpath(sys.argv[0])) + '/../run.py ' + str(n) + ' ' + b)
	print
	print

