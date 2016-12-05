import angr 
import logging
import claripy
import pdb
import simuvex
import sys
import os
import pyvex
import traceback
import bisect
import cffi
import utils

l = logging.getLogger('naiveFullySymbolicMemory')
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

class SymbolicMemory(simuvex.plugins.plugin.SimStatePlugin):

    def __init__(self, memory_backer=None, 
                permissions_backer=None, 
                kind=None, 
                arch=None, 
                endness=None, 
                check_permissions=None, 
                concrete_memory={},
                symbolic_memory=[],
                initialized=False):
        simuvex.plugins.plugin.SimStatePlugin.__init__(self)

        self._memory_backer = memory_backer
        self._permissions_backer = permissions_backer
        self._id = kind
        self._arch = arch
        self._endness = "Iend_BE" if endness is None else endness
        
        self._concrete_memory = concrete_memory
        self._symbolic_memory = symbolic_memory

        self._initialized = initialized

        # some threshold
        self._maximum_symbolic_size = 8 * 1024
        self._maximum_concrete_size = 0x1000000

        self.log("symbolic memory has been created")

    def _init_memory(self):

        if self._initialized:
            return

        #return

        # init memory
        if self._memory_backer is not None:

            _ffi = cffi.FFI()

            for addr, backer in self._memory_backer.cbackers:

                data = _ffi.buffer(backer)[:]
                obj = claripy.BVV(data)

                for k in range(len(obj) / 8):
                    self._concrete_memory[k + addr] = utils.get_obj_bytes(obj, k, 1)[0]

                self.log("Initialized memory at " + hex(addr) + " with " + str(len(obj) / 8) + " bytes")

        self._initialized = True

    def set_state(self, state):
        self.log("setting current state...")
        self.state = state    
        self._init_memory()

    def memory_op(self, addr, size, data=None):

        reg_name = None
        if self._id == 'reg': 

            if type(addr) in (int, long):
                reg_name = utils.reverse_addr_reg(self, addr)
                self.log("\t" + str(addr) + " => " + str(reg_name))

            if isinstance(addr, basestring):
                reg_name = addr
                addr, size_reg = utils.resolve_location_name(self, addr)
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


    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None, inspect=True, ignore_endness=False):
        self.log("Loading at " + str(addr) + " " + str(size) + " bytes.")

        i_addr = addr
        i_size = size

        assert self._id == 'mem' or self._id == 'reg'

        addr, size, reg_name = self.memory_op(addr, size)        

        if type(size) in (int, long):

            min_addr = None
            max_addr = None

            # concrete address
            if type(addr) in (int, long):
                min_addr = addr
                max_addr = addr

            # symbolic addr
            else:
                min_addr = self.state.se.min_int(addr)
                max_addr = self.state.se.max_int(addr)
                if min_addr == max_addr:
                    addr = min_addr

            data = None
            for k in range(size):

                obj = utils.get_unconstrained_bytes(self.state, "bottom", 8)

                self.log("\tLoading from: " + str(addr + k))

                # check versus concrete addresses
                for concrete_addr in range(min_addr + k, max_addr + k + 1):

                    if concrete_addr in self._concrete_memory:

                        v = self._concrete_memory[concrete_addr]
                        if max_addr == min_addr:
                            self.log("\tobject is: " + str(v))
                            obj = v
                        else:
                            self.log("\tobject conditional is: " + str(v))
                            obj = self.state.se.If(concrete_addr == addr + k, v, obj)

                    else:
                        self.log("\taddr is not in concrete memory")

                # check versus any symbolic address                
                for o in self._symbolic_memory:

                    e = o[0]
                    v = o[1]

                    if self.intersect(e, addr + k):
                        obj = self.state.se.If(e == addr + k, v, obj)

                self.log("\tappending data: " + str(obj))
                data = self.state.se.Concat(data, obj) if data is not None else obj

            # fix endness
            endness = self._endness if endness is None else endness
            if not ignore_endness and endness == "Iend_LE":
                self.log("\treversing data: " + str(data))
                data = data.reversed

            self.log("\treturning data: " + str(data))
            return data

        assert False


    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None, inspect=True, priv=None, ignore_endness=False, internal=False):
        
        if not internal:
            self.log("Storing at " + str(addr) + " " + str(size) + " bytes. Content: " + str(data))

        i_addr = addr
        i_size = size
        i_data = data

        assert self._id == 'mem' or self._id == 'reg'

        addr, size, reg_name = self.memory_op(addr, size, data)

        # convert data to BVV if concrete
        data = utils.convert_to_ast(self.state, data, size if isinstance(size, (int, long)) else None)

        if type(size) in (int, long):

            assert len(data) / 8 == size

            # simplify
            data = self.state.se.simplify(data)

            # fix endness
            endness = self._endness if endness is None else endness
            if not ignore_endness and endness == "Iend_LE":
                if not internal:
                    self.log("\treversing data: " + str(data))
                data = data.reversed
                self.log("\treversed data: " + str(data))

            min_addr = None
            max_addr = None

            # concrete address
            if type(addr) in (int, long):
                min_addr = addr
                max_addr = addr

            # symbolic addr
            else:
                min_addr = self.state.se.min_int(addr)
                max_addr = self.state.se.max_int(addr)
                if min_addr == max_addr:
                    addr = min_addr

            to_add = []
            to_replace = []
            to_remove = []
            for k in range(size):

                obj = utils.get_obj_bytes(data, k, 1)[0]

                if not internal:
                    self.log("\tSlicing data with offset " + str(k) + " => " + str(obj))

                # concrete addr
                if type(addr) in (int, long):
                    if not internal:
                        self.log("\tAdding to concrete memory as: " + str(addr + k))
                    self._concrete_memory[addr + k] = obj

                flag = False
                count = 0
                for o in self._symbolic_memory:

                    e = o[0]
                    v = o[1]

                    self.log("\tEval: " + str(e) + " with " + str(addr + k))

                    if self.disjoint(e, addr + k):
                        self.log("\tDisjoint")
                        continue

                    elif self.equiv(e, addr + k):
                        self.log("\tEquiv")

                        # if addr was
                        if type(addr + k) in (int, long):
                            to_remove.append(count)
                        else:
                            to_replace.append([e, obj])

                        flag = True

                    else:
                        self.log("\tOther")
                        to_replace.append([e, self.state.se.If(e == addr + k, obj, v)])

                    count += 1

                if not flag and type(addr) not in (int, long):
                    self.log("\tNot inserted. Added later.")
                    to_add.append([addr + k, obj])

            for q in range(len(to_remove)):
                index = to_remove[q]
                self._symbolic_memory.pop(index - q)

            for o in to_replace:
                for oo in self._symbolic_memory:
                    if oo[0] is o[0]:
                        self.log("\tReplacing for " + str(o[0]) + " data: " + str(oo[1]) + " => " + str(o[1]))
                        oo[1] = o[1]

            for o in to_add:
                self.log("\tAdding: " + str(o[0]) + " data: " + str(o[1]))
                self._symbolic_memory.append(o)

            return

        assert False   


    def equiv(self, a, b):
        try:
            return not self.state.se.eval(a != b, 1)[0]
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)


    def intersect(self, a, b):
        try:
            return self.state.se.eval(a == b, 1)[0]
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)


    def disjoint(self, a, b):
        try:
            return not self.state.se.eval(a == b, 1)[0]
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)


    def dump_memory(self):
        pass


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


    @property
    def category(self):
        if self._id in ('reg', 'mem'):
            return self._id


    def copy(self):
        self.log("Copying memory")
        s = SymbolicMemory(memory_backer=self._memory_backer, 
                                permissions_backer=self._permissions_backer, 
                                kind=self._id, 
                                arch=self._arch, 
                                endness=self._endness, 
                                check_permissions=None, 
                                concrete_memory=self._concrete_memory.copy(),
                                symbolic_memory=self._symbolic_memory[:],
                                initialized=self._initialized)

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

    def verbose(self, v):
        if not v:
            l.setLevel(logging.INFO)