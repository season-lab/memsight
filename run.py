import angr, logging
from subprocess import Popen, PIPE
from itertools import product
import struct
import claripy
import resource
import pdb
import simuvex
import sys
import os
import json
import pyvex
from bitstring import Bits
import traceback
import bisect

l = logging.getLogger('fullySymbolicMemory')
l.setLevel(logging.DEBUG)

class MemoryPointer(object):

    def __init__(self, obj, addr, offset, size):
        self.obj = obj
        self.addr = addr
        self.offset = offset
        self.size = size

    def cmp(self, other):
        return cmp(self.addr, other.addr)

    def __repr__(self):
        return "(" + str(self.addr) + ", " + str(self.offset) + ", " + str(self.obj) + ", " + str(self.size) + ")"

class FullSymbolicMemory(simuvex.plugins.plugin.SimStatePlugin):

    def __init__(self, memory_backer=None, 
                permissions_backer=None, 
                kind=None, 
                arch=None, 
                endness=None, 
                check_permissions=None, 
                memory={}):
        simuvex.plugins.plugin.SimStatePlugin.__init__(self)

        self._memory_backer = memory_backer
        self._permissions_backer = permissions_backer
        self._id = kind
        self._arch = arch
        self._endness = "Iend_BE" if endness is None else endness

        self._memory = memory
        self._maximum_symbolic_size = 8 * 1024
        self._maximum_concrete_size = 0x1000000

        self.log("initializing memory...")

    def set_state(self, state):
        self.log("setting current state...")
        self.state = state    

    def memory_op(self, addr, size, data=None):

        reg_name = None
        if self._id == 'reg': 

            if type(addr) in (int, long):
                reg_name = self._reverse_addr_reg(addr)
                self.log("\t" + str(addr) + " => " + str(reg_name))

            if isinstance(addr, basestring):
                reg_name = addr
                addr, size_reg = self._resolve_location_name(addr)
                self.log("\t" + str(addr) + " => " + str(reg_name))

                # a load from a register, derive size from reg size
                if size is None:
                    size = size_reg
                    self.log("\tsize => " + str(size))

                assert size_reg == size

            assert reg_name is not None
            
        # if this is a store then size can be derived from data that needs to be stored
        if size is None and type(data) in (claripy.ast.bv.BV,):
            size = len(data) / 8
            assert type(size) in (int, long)
            self.log("\tsize => " + str(size))

        # convert size to BVV if concrete
        if type(size) in (int, long):
            size = self.state.se.BVV(size, self.state.arch.bits)

        # make size concrete
        if size is not None:
            min_size, max_size = self._resolve_size_range(size)
            size = max_size

        # if addr is constant, make it concrete
        if type(addr) in (claripy.ast.bv.BV,) and not addr.symbolic:
            addr = addr.args[0]

        assert size is not None
        if self._id == 'reg':
            assert type(addr) in (int, long)

        return addr, size, reg_name


    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None, inspect=True):
        self.log("Loading at " + str(addr) + " " + str(size) + " bytes.")

        i_addr = addr
        i_size = size

        assert self._id == 'mem' or self._id == 'reg'

        addr, size, reg_name = self.memory_op(addr, size)        

        # addr is concrete, size is concrete
        if type(addr) in (int, long) and type(size) in (int, long):

            data = None

            addresses = sorted(self._memory.keys()) # ToDo: expensive!
            index = bisect.bisect_left(addresses, addr)

            offset = 0
            missing = 0
            while offset < size:

                mo_addr = addresses[index] if index < len(addresses) else None
                mo = self._memory[addresses[index]] if index < len(addresses) else None

                #self.log("\taddress: " + str(addr + offset))
                #self.log("\tmemory object: " + str(mo))
                #self.log("\tmemory object address: " + str(mo_addr))

                # missing
                if mo_addr == None:
                    #self.log("\tmissing bytes of length " + str(size))
                    data = self.concat_missing_bytes(data, size, reg_name, addr)

                    offset += size
                    break

                assert mo_addr >= (addr + offset)
                
                if mo_addr > (addr + offset):
                    missing = min(mo_addr, addr + size) - (addr + offset)
                    #self.log("\tmissing bytes of length " + str(missing))

                    #self.log("data before: " + str(data))
                    data = self.concat_missing_bytes(data, missing, reg_name, addr + offset)
                    #self.log("data after: " + str(data))

                    offset += missing
                    continue

                # we have an obj at addr
                # how many bytes do we need of it?
                length = 1
                while length < size - offset:
                    if addresses[index + length] == addr + length:
                        mo_next = self._memory[addr + length]
                        if mo_next.obj is mo.obj and mo_next.offset == mo.offset + length:
                            length += 1
                        else:
                            break
                    else:
                        break

                obj, length, used = self.get_obj_bytes(mo.obj, mo.offset, length)
                
                #self.log("\tappending byte: " + str(obj))
                data = obj if data is None else state.se.Concat(data, obj)
                #self.log("\tappending result: " + str(data))

                offset += length
                index += used

            # simplify
            # data = self.state.se.simplify(data)

            # fix endness
            endness = self._endness if endness is None else endness
            if endness == "Iend_LE":
                #self.log("\treversing data: " + str(data))
                data = data.reversed

            # simplify
            # data = self.state.se.simplify(data)

            self.log("\treturning data: " + str(data))
            return data

        elif type(addr) not in (int, long) and addr.symbolic and type(size) in (int, long):

            # get a set of possible write address
            concrete_addresses = self._concretize_addr(addr)

            self.log("\tsymbolic read with " + str(len(concrete_addresses)) + " solutions")

            # build a conditional value
            data = self.load(concrete_addresses[0], size)
            constraint_options = [ addr == concrete_addresses[0] ]

            for a in concrete_addresses[1:]:
                data = self.state.se.If(addr == a, self.load(a, size), data)
                constraint_options.append(addr == a)

            if len(constraint_options) > 1:
                load_constraint = [ self.state.se.Or(*constraint_options) ]
            elif not self.state.se.symbolic(constraint_options[0]):
                load_constraint = [ ]
            else:
                load_constraint = [ constraint_options[0] ]

            if len(load_constraint) > 0:
                self.state.add_constraints(*load_constraint)

            return data

        assert False


    def get_missing_bytes(self, data, missing, reg_name, addr):
        name = "mem_" + str(addr) if self._id == 'mem' else "reg_" + str(reg_name) 
        obj = self._get_unconstrained_bytes(name, missing * 8)
                
        # fix endness
        if self.category == 'reg' and self.state.arch.register_endness == 'Iend_LE':
            #self.log("reversing")
            obj = obj.reversed

        # fix endness
        if self.category != 'reg' and self.state.arch.memory_endness == 'Iend_LE':
            #self.log("reversing")
            obj = obj.reversed

        self.store(addr, obj, missing, ignore_endness=True)
        return (obj, None, None)

    def concat_missing_bytes(self, data, missing, reg_name, addr):
        obj = self.get_missing_bytes(data, missing, reg_name, addr)[0]
        return obj if data is None else state.se.Concat(data, obj)

    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None, inspect=True, priv=None, ignore_endness=False):
        self.log("Storing at " + str(addr) + " " + str(size) + " bytes. Content: " + str(data))

        i_addr = addr
        i_size = size
        i_data = data

        assert self._id == 'mem' or self._id == 'reg'

        addr, size, reg_name = self.memory_op(addr, size, data)

        # convert data to BVV if concrete
        data = self._convert_to_ast(data, size if isinstance(size, (int, long)) else None)

        # simplify
        data = self.state.se.simplify(data)

        # fix endness
        endness = self._endness if endness is None else endness
        if not ignore_endness and endness == "Iend_LE":
            #self.log("\treversing data: " + str(data))
            data = data.reversed

        # simplify
        # data = self.state.se.simplify(data)

        # addr is concrete and size is concrete
        if type(addr) in (int, long) and type(size) in (int, long):

            assert len(data) / 8 == size

            offset = 0
            while offset < size:
                #self.log("\tstoring at " + str(hex(addr + offset)) + ": " + str(data))
                self._memory[addr + offset] = MemoryPointer(data, addr, offset, size)
                offset += 1

            #self.dump_memory()
            return

        # symbolic addr and concrete size
        elif type(addr) not in (int, long) and addr.symbolic and type(size) in (int, long):

            self.log("\tsymbolic write")

            assert len(data) / 8 == size

            # get a set of possible write address
            concrete_addresses = self._concretize_addr(addr)

            self.log("\tsymbolic write with " + str(len(concrete_addresses)) + " solutions")            

            # for each concrete address, do a conditional write            
            for a in concrete_addresses:

                # add condition to our data
                data_c = self.state.se.If(a == addr, data, self.load(a, size))

                offset = 0
                while offset < size:
                    #self.log("\tstoring at " + str(hex(a + offset)) + ": " + str(data_c))
                    self._memory[a + offset] = MemoryPointer(data_c, addr, offset, size)
                    offset += 1

            return

        assert False   


    def get_obj_bytes(self, obj, offset, size):

        # full obj is needed
        if offset == 0 and size * 8 == len(obj):
            return obj, size, size

        size = min(size, (len(obj) / 8) - offset)

        # slice the object
        left = len(obj) - (offset * 8) - 1
        right = left - (size * 8) + 1
        return obj[left:right], size, size

    def dump_memory(self):
        for k in sorted(self._memory.keys()):
            print "[" + str(k) + "]: " + str(self._memory[k]) 

    def _convert_to_ast(self, data_e, size_e=None):
        """
        Make an AST out of concrete @data_e
        """
        if type(data_e) is str:
            # Convert the string into a BVV, *regardless of endness*
            bits = len(data_e) * 8
            data_e = self.state.se.BVV(data_e, bits)
        elif type(data_e) in (int, long):
            data_e = self.state.se.BVV(data_e, size_e*8 if size_e is not None
                                       else self.state.arch.bits)
        else:
            data_e = data_e.to_bv()

        return data_e


    def _resolve_location_name(self, name):

        stn_map = { 'st%d' % n: n for n in xrange(8) }
        tag_map = { 'tag%d' % n: n for n in xrange(8) }

        if self.category == 'reg':
            if self.state.arch.name in ('X86', 'AMD64'):
                if name in stn_map:
                    return (((stn_map[name] + self.load('ftop')) & 7) << 3) + self.state.arch.registers['fpu_regs'][0], 8
                elif name in tag_map:
                    return ((tag_map[name] + self.load('ftop')) & 7) + self.state.arch.registers['fpu_tags'][0], 1

            return self.state.arch.registers[name]
        elif name[0] == '*':
            return self.state.registers.load(name[1:]), None
        else:
            raise simuvex.s_errors.SimMemoryError("Trying to address memory with a register name.")

    def _concretize_addr(self, addr):

        try:
            # concrete
            if isinstance(addr, (int, long)):
                return [ addr ]
            
            # constant
            elif not self.state.se.symbolic(addr):
                return [ self.state.se.any_int(addr) ]

            # symbolic
            N = 2048
            res = self.state.se.any_n_int(addr, N)
            if len(res) >= N:
                self.log("Found " + str(N) + " solutions but more are possible")
                import sys
                sys.exit(0)

            return res

        except Exception as e:
            print "Exception: " + str(e)
            import traceback
            traceback.print_exc()

        assert False
        return []


    def _reverse_addr_reg(self, addr):

        assert self.category == 'reg'
        assert type(addr) in (int, long)

        for name, offset_size in self.state.arch.registers.iteritems():
            offset = offset_size[0]
            size = offset_size[1]
            if addr in range(offset, offset + size):
                return name

        assert False


    def _resolve_size_range(self, size):

        if not self.state.se.symbolic(size):
            i = self.state.se.any_int(size)
            if i > self._maximum_concrete_size:
                raise SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
            return i, i

        max_size = self.state.se.max_int(size)
        min_size = self.state.se.min_int(size)

        if min_size > self._maximum_symbolic_size:
            self.state.log.add_event('memory_limit', message="Symbolic size %d outside of allowable limits" % min_size, size=size)
            assert False
            min_size = self._maximum_symbolic_size

        return min_size, min(max_size, self._maximum_symbolic_size)

    def _get_unconstrained_bytes(self, name, bits, source=None):
        return self.state.se.Unconstrained(name, bits)

    @property
    def category(self):
        if self._id in ('reg', 'mem'):
            return self._id


    def copy(self):
        self.log("Copying memory")
        s = FullSymbolicMemory(memory_backer=self._memory_backer, 
                                permissions_backer=self._permissions_backer, 
                                kind=self._id, 
                                arch=self._arch, 
                                endness=self._endness, 
                                check_permissions=None, 
                                memory=self._memory.copy())

        return s


    @property
    def id(self):
        return self._id


    @property
    def mem(self):

        # In angr, this returns a reference to the (internal) paged memory
        # We do not have (yet) a paged memory. We instead return self
        # that exposes a _preapproved_stack attribute
        # (similarly as done by a paged memory)

        self.log("getting reference to paged memory")
        #traceback.print_stack()
        return self


    @property
    def _preapproved_stack(self):
        pass


    @_preapproved_stack.setter
    def _preapproved_stack(self, value):
        self.log("Boundaries on stack have been set by the caller. Ignored.")
        pass

    def log(self, msg):
        l.debug("[" + self._id + "] " + msg)


def get_target_addrs(fname):

    import imp

    try:
        config = imp.load_source(os.path.basename(fname), fname + ".py")
    except:
        print "config python script related to binary file is missing"
        print "Create " + str(fname) + ".py with the following functions:"
        print "\t        start()    => int"
        print "\t        avoid()    => [int, ...]"
        print "\t          end()    => [int, ...]"
        print "\tdo_start(state)    => o"
        print "\t  do_end(state, o) => None"
        sys.exit(0)

    start = config.start()
    avoid = config.avoid()
    end = config.end()

    return start, avoid, end, config

def print_constraints(constraints, memory, state, cache):
    print "Path constraints:"
    if cache is None:
        for i in range(len(constraints)):
            print "\t" + str(constraints[i])
        if len(constraints) == 0:
            print "\tNone"
        print
        return None

    else:

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
                print "\t\t" + s

        if len(added) > 0:
            print "\tAdded:"
            for s in added:
                print "\t\t" + s

        if len(removed) == 0 and len(added) == 0:
            print "\tSame as previous state."

        print       
        return cache

start, avoid, end, config = get_target_addrs(sys.argv[1])

print
print "Starting symbolic execution of binary: " + str(sys.argv[1])
print "From address: " + str(hex(start))
print "Target addresses: " + ' '.join(map(lambda a: str(hex(a)), end))
print "Avoid addresses: " + ' '.join(map(lambda a: str(hex(a)), avoid))
print

proj = angr.Project(sys.argv[1], load_options={'auto_load_libs':False}, )

fsm_mem = FullSymbolicMemory(proj.loader.memory, None, 'mem', None, ) # endness=proj.arch.memory_endness
fsm_reg = FullSymbolicMemory(None, None, 'reg', proj.arch, endness=proj.arch.register_endness)

plugins = {'memory' : fsm_mem, 'registers' : fsm_reg}
#plugins = {}

#logging.getLogger('simuvex').setLevel(logging.DEBUG)
#logging.getLogger('claripy').setLevel(logging.DEBUG)

state = proj.factory.blank_state(addr=start, remove_options={simuvex.o.LAZY_SOLVES}, plugins=plugins)

data = config.do_start(state)

pg = proj.factory.path_group(state, veritesting=False)

avoided = []
found = []
num_inst=1
constraint_cache = []

while len(pg.active) > 0 and len(found) == 0:

    #print pg.active[0].path_id

    state = pg.active[0].state
    addr = state.ip.args[0]
    
    print "\n###################################################"
    print "\nNumber of active states: " + str(len(pg.active))
    print "Executing first active path in the list"
    print "Path is at address: " + str(hex(addr)) 

    code = proj.factory.block(addr=addr, num_inst=num_inst, backup_state=state)  

    # print original code line
    print "Assembly code: "
    k = 0
    for i, s in enumerate(code.vex.statements): 
        if isinstance(s, pyvex.stmt.IMark):
            print "\t" + str(code.capstone.insns[k])
            k += 1

    code.vex.pp()

    # print path constraint
    constraint_cache = print_constraints(state.se.constraints, fsm_reg, state, constraint_cache)

    #pdb.set_trace()    

    print "# Start of execution"
    pg.step(opt_level=1, num_inst=num_inst) 
    print "# End of execution\n"

    remove = []
    for path in pg.active:
    
        ip = path.state.ip.args[0]
        if ip in avoid:
            avoided.append(path)
            remove.append(path) 
            print "\nPath executing " + str(hex(ip)) + " has been moved to avoided paths..."
        
        if ip in end:
            found.append(path)
            remove.append(path)

    for path in remove:
        pg.active.remove(path)


if len(pg.active) == 0 and len(found) == 0:
    print "Something went wrong: no active path, but not found path!"
    pdb.set_trace() 
    sys.exit(0)

print "One path has reached target instruction: " + str(hex(found[0].state.ip.args[0]))
constraint_cache = print_constraints(found[0].state.se.constraints, fsm_reg, found[0].state, constraint_cache)
state = found[0].state
config.do_end(state, data)
pdb.set_trace()