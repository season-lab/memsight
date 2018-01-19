import angr
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from memory import factory

def main(mem_type = 1):
    p = angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/r100", load_options={'auto_load_libs': False})

    plugins = {}
    if mem_type == 1:
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(p)
        plugins['memory'] = mem_memory

    state = p.factory.entry_state(plugins=plugins)
    ex = p.surveyors.Explorer(start=state, find=(0x400844, ), avoid=(0x400855,))
    ex.run()

    return ex.found[0].posix.dumps(0).strip('\0\n')

def test():
    assert main() == 'Code_Talkers'

if __name__ == '__main__':
    test()
