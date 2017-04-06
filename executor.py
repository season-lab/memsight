import resource

import executor_config
import angr
import sys
import simuvex
import pyvex
import pdb
import logging

class Executor(object):

    def __init__(self, binary):

        self.start, self.avoid, self.end, self.config = executor_config.get_target_addrs(binary)

        print
        print "Starting symbolic execution of binary: " + str(binary)
        print "From address: " + str(hex(self.start))
        print "Target addresses: " + ' '.join(map(lambda a: str(hex(a)), self.end))
        print "Avoid addresses: " + ' '.join(map(lambda a: str(hex(a)), self.avoid))
        print

        self.project = angr.Project(binary, load_options={'auto_load_libs' : False})

    def _print_constraints(self, constraints, old_constraints):
        
        print "Path constraints:"
        if old_constraints is None:
            for i in range(len(constraints)):
                print "\t" + str(constraints[i])
            if len(constraints) == 0:
                print "\tNone"
            print
            return None

        else:

            cache = []
            for c in old_constraints:
                cache.append(str(c))

            if len(constraints) == 0 and len(cache) == 0:
                print "\tNone\n"
                return cache

            l = []
            added = []
            removed = []

            for i in range(len(constraints)):
                s = str(constraints[i])
                l.append(s)

            removed = [s for s in cache if s not in l]
            added = [s for s in l if s not in cache]
            cache = l

            if len(removed) > 0:
                print "\tRemoved:"
                for s in removed:
                    print "\t\t" + str(s)

            if len(added) > 0:
                print "\tAdded:"
                for s in added:
                    print "\t\t" + str(s)

            if len(removed) == 0 and len(added) == 0:
                print "\tSame as previous state."

            print       

    def run(self, mem_memory = None, reg_memory = None):

        plugins = {}
        if mem_memory is not None:
            plugins['memory'] = mem_memory
            mem_memory.verbose = False
        if reg_memory is not None:
            plugins['registers'] = reg_memory
            reg_memory.verbose = False

        add_options = {simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}
        state = self.project.factory.blank_state(addr=self.start, remove_options={simuvex.o.LAZY_SOLVES}, add_options=add_options, plugins=plugins)

        data = self.config.do_start(state)

        veritesting = False
        if 'veritesting' in data:
            veritesting = data['veritesting']

        #print "Veritesting: " + str(veritesting)
        pg = self.project.factory.path_group(state, veritesting=veritesting)

        while len(pg.active) > 0:
            print pg

            # step 1 basic block for each active path
            # if veritesting is on: this will step more than one 1 BB!
            pg.explore(avoid=self.avoid, find=self.end, n=1)

            # Bazinga!
            if len(pg.found) > 0:
                print "Reached the target"
                print pg
                state = pg.found[0].state
                self.config.do_end(state, data, pg)
                break

        assert len(pg.found) > 0
        print
        print "Memory footprint: \t" + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"


    def explore(self, mem_memory = None, reg_memory = None):

        plugins = {}
        if mem_memory is not None:
            plugins['memory'] = mem_memory
        if reg_memory is not None:
            plugins['registers'] = reg_memory

        #logging.getLogger('simuvex').setLevel(logging.DEBUG)
        #logging.getLogger('claripy').setLevel(logging.DEBUG)
        #logging.getLogger('angr.analyses.veritesting').setLevel(logging.DEBUG)

        add_options = {simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}
        state = self.project.factory.blank_state(addr=self.start, remove_options={simuvex.o.LAZY_SOLVES}, add_options=add_options, plugins=plugins)

        data = self.config.do_start(state)

        veritesting = False
        if 'veritesting' in data:
            veritesting = data['veritesting']

        print "Veritesting: " + str(veritesting)

        pg = self.project.factory.path_group(state, veritesting=veritesting)

        avoided = []
        found = []
        num_inst=1

        while len(pg.active) > 0 and len(found) == 0:

            parent_state = pg.active[0].history._parent.state if pg.active[0].history._parent is not None else None

            path = pg.active[0]
            state = pg.active[0].state
            addr = state.ip.args[0]
            
            print "\n###################################################"
            print "\nNumber of active states: " + str(len(pg.active))
            print "Executing first active path in the list"
            print "Path is at address: " + str(hex(addr)) 

            code = self.project.factory.block(addr=addr, num_inst=num_inst, backup_state=state)  

            # print original code line
            print "Assembly code: "
            k = 0
            for i, s in enumerate(code.vex.statements): 
                if isinstance(s, pyvex.stmt.IMark):
                    print "\t" + str(code.capstone.insns[k])
                    k += 1

            code.vex.pp()

            # print path constraint
            self._print_constraints(state.se.constraints, parent_state.se.constraints if parent_state is not None else None)

            #pdb.set_trace()    

            print pg

            print "# Start of execution"
            if not veritesting:
                pg.step(opt_level=1, num_inst=num_inst, )  # selector_func = lambda x: x is path
            else:
                pg.step()
            print "# End of execution\n"

            remove = []
            for path in pg.active:
            
                ip = path.state.ip.args[0]
                if ip in self.avoid:
                    avoided.append(path)
                    remove.append(path) 
                    print "\nPath executing " + str(hex(ip)) + " has been moved to avoided paths..."
                
                if ip in self.end:
                    found.append(path)
                    remove.append(path)

            for path in remove:
                pg.active.remove(path)

        if len(pg.active) == 0 and len(found) == 0:
            print "Something went wrong: no active path, but no found path!"
            pdb.set_trace()
            assert False
            sys.exit(1)

        print "One path has reached target instruction: " + str(hex(found[0].state.ip.args[0]))
        state = found[0].state
        self.config.do_end(state, data, pg)
        print "Constraints:"
        self._print_constraints(state.se.constraints, None)
        #pdb.set_trace()

        print
        print "Memory footprint: \t" + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"