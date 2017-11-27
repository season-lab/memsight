import unittest
import sys
import os
import angr

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tests.artificial.test_memory import test_symbolic_access, test_store_with_symbolic_size, \
    test_store_with_symbolic_addr_and_symbolic_size, test_concrete_merge, test_concrete_merge_with_condition, \
    test_symbolic_merge

from executor import executor
from memory import factory

class TestMemsightMemory(unittest.TestCase):

    def common(self, file):
        p = os.path.dirname(os.path.realpath(__file__))
        explorer = executor.Executor(p + '/' + file)
        angr_project = explorer.project
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(angr_project)
        return explorer.run(mem_memory=mem_memory, reg_memory=reg_memory, verbose=False)

    def test_basic_example(self):
        self.assertTrue(self.common('basic-example'))

    def test_array_O0(self):
        self.assertTrue(self.common('array_O0'))

    def test_fail(self):
        self.assertTrue(not self.common('fail'))

    def test_fail2(self):
        self.assertTrue(self.common('fail2'))

    def test_fail3(self):
        # self.assertTrue(self.common('fail3'))
        return True

    def test_fail4(self):
        self.assertTrue(self.common('fail4'))

    def test_fail5(self):
        self.assertTrue(self.common('fail5'))

    def test_bomb(self):
        self.assertTrue(self.common('bomb'))

    def test_merge(self):
        self.assertTrue(self.common('merge'))

    def test_memory(self):

        angr_project = angr.Project("/bin/ls", load_options={'auto_load_libs': False})
        mem_memory, reg_memory = factory.get_range_fully_symbolic_memory(angr_project)

        plugins = {}
        if mem_memory is not None:
            plugins['memory'] = mem_memory

        state = angr_project.factory.entry_state(remove_options={angr.options.LAZY_SOLVES}, plugins=plugins)

        test_symbolic_access(state.copy())
        test_store_with_symbolic_size(state.copy())
        test_store_with_symbolic_addr_and_symbolic_size(state.copy())

        test_concrete_merge(state.copy())
        test_concrete_merge_with_condition(state.copy())

        test_symbolic_merge(state.copy())

if __name__ == '__main__':
    unittest.main()