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
import resource
import sorted_collection
from pitree import pitree

l = logging.getLogger('naiveFullySymbolicMemory')
l.setLevel(logging.DEBUG)

# profiling vars
time_profile = {}
count_ops = 0
n_ite = 0

def update_counter(elapsed, f):
    
    global time_profile
    global count_ops

    if f not in time_profile:
        time_profile[f] = [1, elapsed]
    else:     
        time_profile[f][0] += 1
        time_profile[f][1] += elapsed
    
    count_ops += 1
    if count_ops > 0 and count_ops % 10000 == 0:
        print
        print "Profiling stats:" # at depth=" + str(depth) + ":"
        for ff in time_profile:
            print "\t" + str(ff) + ": ncall=" + str(time_profile[ff][0]) + " ctime=" + str(time_profile[ff][1])

        print "\tMemory footprint: \t" + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"
        print

def print_profiling_stats(depth, pg):

    global time_profile
    global n_ite

    print
    print "Profiling stats at depth=" + str(depth) + ":"
    print
    for ff in time_profile:
        print "\t" + str(ff) + ": ncall=" + str(time_profile[ff][0]) + " ctime=" + str(time_profile[ff][1])

    print
    print

    count_leaves = 0
    count_bytes = 0
    count_formulas = 0
    for stash in pg.stashes:
        if len(pg.stashes[stash]) <= 0:
            continue
        print "\tStash " + str(stash) + ":"
        for p in pg.stashes[stash]:
            #print "\t\t" + str(len(p.state.memory._concrete_memory)) + ' ' + str(len(p.state.memory._symbolic_memory))
            count_leaves += 1

    print
    print "\tNumber of leaves: \t" + str(count_leaves)
    print "\tLeaves: overall indexed formulas: \t" + str(count_formulas)
    print "\tNumber of states explored: \t" + str(time_profile['__init__'][0]) #angr.path.count_paths)
    print "\tNumber of generated ITE: \t" + str(n_ite)
    print "\tMemory footprint: \t" + str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"
    print

def profile(func):
    def wrap(*args, **kwargs):
        import time
        started_at = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - started_at
        update_counter(elapsed, func.__name__)
        return result
    return wrap

class MemoryObject(object):

    __slots__ = ('obj', 'offset', 'raw_byte')

    def __init__(self, obj, offset):
        self.obj = obj
        self.offset = offset
        self.raw_byte = None

    def __repr__(self):
        return "(" + str(self.obj) + " @ " + str(self.offset) + ")"

    def get_byte(self):

        if self.raw_byte is None:
            self.raw_byte = utils.get_obj_bytes(self.obj, self.offset, 1)[0]
            self.obj = self.raw_byte
            self.offset = 0

        return self.raw_byte

    def compare(self, other):
        if type(other) not in (MemoryObject,):
            raise TypeError("Comparing " + str(type(self)) + " with " + str(type(other)) + " is not supported.")

        if self.obj is not None and other.obj is not None:
            if id(self.obj) == id(other.obj) and self.offset == other.offset:
                return True
            else:
                return False
        else:
            if id(self.raw_byte) == id(other.raw_byte) or self.get_byte() == other.get_byte():
                return True
            else:
                return False

class SymbolicItem(object):

    __slots__ = ('addr', 'obj', 't', 'guard')

    def __init__(self, addr, obj, t, guard):
        self.addr = addr
        self.obj = obj
        self.t = t
        self.guard = guard

    def __eq__(self, other):
        if id(self) == id(other):
            return True

        return False

    def __repr__(self):
        return "[" + str(self.addr) + ", " + str(self.obj) + ", " + str(self.t) + ", " + str(self.guard) + "]"


class MappedRegion(object):

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

    def __init__(self, addr, length, permissions):
        self.addr = addr
        self.length = length
        self.permissions = permissions


    def __repr__(self):
        rwx_s  = "r" if self.is_readable() else ''
        rwx_s += "w" if self.is_writable() else ''
        rwx_s += "x" if self.is_executable() else ''
        return "(" + str(hex(self.addr)) + ", " + str(hex(self.addr + self.length)) + ") [" + rwx_s +"]"


    def is_readable(self):
        return self.permissions.args[0] & MappedRegion.PROT_READ


    def is_writable(self):
        return self.permissions.args[0] & MappedRegion.PROT_WRITE    


    def is_executable(self):
        return self.permissions.args[0] & MappedRegion.PROT_EXEC


class SymbolicMemory(simuvex.plugins.plugin.SimStatePlugin):

    @profile
    def __init__(self, memory_backer=None, 
                permissions_backer=None, 
                kind=None, 
                arch=None, 
                endness=None, 
                check_permissions=None, 
                symbolic_memory=None,
                stack_range=None,
                mapped_regions=[],
                verbose=False,
                timestamp=0,
                initializable=None,
                initialized=False,
                timestamp_implicit=0):

        simuvex.plugins.plugin.SimStatePlugin.__init__(self)

        self._memory_backer = memory_backer
        self._permissions_backer = permissions_backer
        self._id = kind
        self._arch = arch
        self._endness = "Iend_BE" if endness is None else endness
        
        self._symbolic_memory = Untree() if symbolic_memory is None else symbolic_memory
        self.timestamp = timestamp
        self.timestamp_implicit = timestamp_implicit

        # some threshold
        self._maximum_symbolic_size = 8 * 1024
        self._maximum_concrete_size = 0x1000000

        self._abstract_backer = None

        # stack range
        self._stack_range = stack_range

        # mapped regions
        self._mapped_regions = mapped_regions

        self.verbose = verbose
        if self.verbose: self.log("symbolic memory has been created")

        self._initializable = initializable if initializable is not None else sorted_collection.SortedCollection(key=lambda x: x[0])
        self._initialized = initialized

    @profile
    def _init_memory(self):

        if self._initialized:
            return

        # init mapped regions
        for start, end in self._permissions_backer[1]:

            perms = self._permissions_backer[1][(start, end)]
            self.map_region(start, end-start, perms)

        # init memory
        if self._memory_backer is not None:

            _ffi = cffi.FFI()
            for addr, backer in self._memory_backer.cbackers:

                data = _ffi.buffer(backer)[:]
                obj = claripy.BVV(data)

                page_size = 0x1000
                size = len(obj) / 8
                data_offset = 0
                page_index = int(addr / page_size)
                page_offset = addr % page_size

                while size > 0:

                    mo = [page_index, obj, data_offset, page_offset, min(size, page_size)]
                    if self.verbose: self.log("Adding initializable area: page_index=" + str(mo[0]) + " size=" + str(mo[4]) + " data_offset=" + str(mo[2]))
                    self._initializable.insert(mo)
                    page_index += 1
                    size -= page_size - page_offset
                    data_offset += page_size - page_offset
                    page_offset = 0

        """
        # force load initialized bytes at the startup
        indexes = set(self._initializable._keys)
        for index in indexes:
            self._load_init_data(index * 0x1000, 1)

        print self._initializable._keys
        assert len(self._initializable._keys) == 0
        """

        self._initialized = True

    @profile
    def set_state(self, state):
        if self.verbose: self.log("setting current state...")
        self.state = state
        self._init_memory()

    @profile
    def _load_init_data(self, addr, size):

        page_size = 0x1000
        page_index = int(addr / page_size)
        page_end = int((addr + size) / page_size)
        k = bisect.bisect_left(self._initializable._keys, page_index)

        if self.verbose: self.log("Checking initializable: page index " + str(page_index) + " k=" + str(k) + " max_k=" + str(len(self._initializable)) + " end_k=" + str(page_end))

        to_remove = []
        while k < len(self._initializable) and self._initializable[k][0] <= page_end:

            data = self._initializable[k] # [page_index, data, data_offset, page_offset, min(size, page_size]
            if self.verbose: self.log("\tLoading initialized data at " + str(data[0]))
            for j in range(data[4]):

                #self.timestamp += 1
                e = (data[0] * 0x1000) + data[3] + j
                v = MemoryObject(data[1], data[2] + j)
                self._symbolic_memory.add(e, e + 1, SymbolicItem(e, v, 0, None))

            to_remove.append(data)
            k += 1

        for e in to_remove:
            self._initializable.remove(e)

        if len(to_remove):
            if self.verbose: self.log("\tRemaining items in initializable: " + str(len(self._initializable)))

    @profile
    def _raw_ast(self, a):
        if type(a) is simuvex.s_action_object.SimActionObject:
            return a.ast
        elif type(a) is dict:
            return { k:self._raw_ast(a[k]) for k in a }
        elif type(a) in (tuple, list, set, frozenset):
            return type(a)((self._raw_ast(b) for b in a))
        else:
            return a

    @profile
    def memory_op(self, addr, size, data=None):

        addr = self._raw_ast(addr)
        size = self._raw_ast(size)
        data = self._raw_ast(data)

        reg_name = None
        if self._id == 'reg': 

            if type(addr) in (int, long):
                reg_name = utils.reverse_addr_reg(self, addr)
                if self.verbose: self.log("\t" + str(addr) + " => " + str(reg_name))

            if isinstance(addr, basestring):
                reg_name = addr
                addr, size_reg = utils.resolve_location_name(self, addr)
                if self.verbose: self.log("\t" + str(addr) + " => " + str(reg_name))

                # a load from a register, derive size from reg size
                if size is None:
                    size = size_reg
                    if self.verbose: self.log("\tsize => " + str(size))

                assert size_reg == size

            assert reg_name is not None
            
        # if this is a store then size can be derived from data that needs to be stored
        if size is None and type(data) in (claripy.ast.bv.BV,):
            size = len(data) / 8
            assert type(size) in (int, long)
            if self.verbose: self.log("\tsize => " + str(size))

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

    @profile
    def build_ite(self, addr, cases, v, obj):

        assert len(cases) > 0

        if len(cases) == 1:
            cond = addr == cases[0].data.addr
        else:
            cond = self.state.se.And(addr >= cases[0].data.addr, addr <= cases[-1].data.addr)

        cond = claripy.And(cond, cases[0].data.guard) if cases[0].data.guard is not None else cond

        global n_ite
        n_ite += 1

        return self.state.se.If(cond, v, obj)

    @profile
    def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None, inspect=True, ignore_endness=False, disable_actions=False):

        global n_ite

        try:

            if self.verbose: self.log("Loading at " + str(addr) + " " + str(size) + " bytes.")

            i_addr = addr
            i_size = size

            assert self._id == 'mem' or self._id == 'reg'

            addr, size, reg_name = self.memory_op(addr, size)        

            if type(size) in (int, long):

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

                # check permissions
                self.check_sigsegv_and_refine(addr, min_addr, max_addr, False)

                # check if binary data should be loaded into address space
                self._load_init_data(min_addr, (max_addr - min_addr) + size)

                data = None
                for k in range(size):

                    if self.verbose: self.log("\tLoading from: " + str(hex(addr + k) if type(addr) in (long, int) else (addr + k)))

                    P = self._symbolic_memory.search(min_addr + k, max_addr + k + 1)
                    P = sorted(list(P), key = lambda x : (x.data.t, (x.data.addr if type(x.data.addr) in (int, long) else 0)))

                    if self.verbose: self.log("\tMatching formulas:" + str(len(P)))
                    #if self.verbose: self.log("\tMatching formulas:" + str(P))

                    if min_addr == max_addr and len(P) == 1 and type(P[0].data.addr) in (long, int) and P[0].data.guard is None:
                        obj = P[0].data.obj.get_byte()

                    else:

                        obj = utils.get_unconstrained_bytes(self.state, "bottom", 8, memory=self)

                        if(self.category == 'mem' and
                                    simuvex.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY not in self.state.options):

                            # implicit store...
                            self.timestamp_implicit -= 1
                            self._symbolic_memory.add(min_addr + k, max_addr + k + 1, SymbolicItem(addr + k, MemoryObject(obj, 0), self.timestamp_implicit, None))

                        if self.verbose: self.log("\tAdding ite cases: " + str(len(P)))
                        obj = self.build_merged_ite(addr + k, P, obj)

                    # concat single-byte objs
                    if self.verbose: self.log("\tappending data") #: " + str(obj))
                    data = self.state.se.Concat(data, obj) if data is not None else obj

                # fix endness
                endness = self._endness if endness is None else endness
                if not ignore_endness and endness == "Iend_LE":
                    #if self.verbose: self.log("\treversing data: " + str(data))
                    data = data.reversed

                if not disable_actions:
                    if simuvex.o.AST_DEPS in self.state.options and self.category == 'reg':
                        r = simuvex.SimActionObject(data, reg_deps=frozenset((addr,)))

                    if simuvex.o.AUTO_REFS in self.state.options and action is None:
                        ref_size = size if size is not None else (data.size() / 8)
                        region_type = self.category
                        if region_type == 'file':
                            # Special handling for files to keep compatibility
                            # We may use some refactoring later
                            region_type = self.id
                        action = simuvex.SimActionData(self.state, region_type, 'read', addr=addr, data=data, size=ref_size,
                                               condition=condition, fallback=fallback)
                        self.state.log.add_action(action)

                #if self.verbose: self.log("\treturning data: " + str(data))
                return data

            assert False

        except Exception as e:

            if type(e) in (simuvex.s_errors.SimSegfaultError,):
                raise e

            print str(e)
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def build_merged_ite(self, addr, P, obj):

        N = len(P)
        merged_p = []
        for i in range(N):

            p = P[i]
            v = p.data.obj.get_byte()

            # lookahead for merging
            is_good_candidate = type(p.data.addr) in (int, long) and p.data.guard is None
            mergeable = False
            if len(merged_p) > 0 and is_good_candidate \
                    and p.data.addr == merged_p[-1].data.addr + 1:

                prev_v = merged_p[-1].data.obj.get_byte()
                if v.op == 'BVV':

                    # both constant and equal
                    if prev_v.op == 'BVV' and v.args[0] == prev_v.args[0]:
                        # if self.verbose: self.log("\tmerging ite with same constant and consecutive address")
                        mergeable = True

                # same symbolic object
                elif v is prev_v:
                    # if self.verbose: self.log("\tmerging ite with same sym and consecutive address")
                    mergeable = True

            if not mergeable:

                if len(merged_p) > 0:
                    if self.verbose:
                        self.log("\tbuilding ite with " + str(len(merged_p)) + " case(s)")  # " + str(addrs))
                    obj = self.build_ite(addr, merged_p, merged_p[-1].data.obj.get_byte(), obj)
                    merged_p = []

                if is_good_candidate:
                    merged_p.append(p)
                else:
                    if self.verbose:
                        self.log("\tbuilding ite with " + str(1) + " case(s)")  # " + str(addrs))
                    obj = self.build_ite(addr, [p], v, obj)

            else:
                merged_p.append(p)

        if len(merged_p) > 0:
            if self.verbose: self.log("\tbuilding ite with " + str(len(merged_p)) + " case(s)")  #: "+ str(v))
            obj = self.build_ite(addr, merged_p, v, obj)

        return obj

    @profile
    def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None, inspect=True, priv=None, ignore_endness=False, internal=False, disable_actions=False):

        global n_ite

        try:

            if not internal:
                if self.verbose: self.log("Storing at " + str(addr) + " " + str(size) + " bytes.") # Content: " + str(data))
                pass

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
                        #if self.verbose: self.log("\treversing data: " + str(data))
                        pass
                    data = data.reversed
                    #if self.verbose: self.log("\treversed data: " + str(data))

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

                # check permissions
                self.check_sigsegv_and_refine(addr, min_addr, max_addr, True)

                self.timestamp += 1

                for k in range(size):

                    obj = MemoryObject(data, k)

                    if not internal:
                        if self.verbose: self.log("\tSlicing data with offset " + str(k))# + " => " + str(obj))

                    P = self._symbolic_memory.search(min_addr + k, max_addr + k + 1)
                    if self.verbose: self.log("\tConflicting forumulas: " + str(len(P)))
                    replaced = False
                    constant_addr = min_addr == max_addr
                    for p in P:
                        if (constant_addr and type(p.data.addr) in (int, long) and (min_addr + k) == p.data.addr) or (id(p.data.addr) == id(addr + k)):
                            if self.verbose: self.log("\tUpdating node...")
                            self._symbolic_memory.update_item(p, SymbolicItem(addr + k, obj, self.timestamp, None))
                            replaced = True
                            break

                    if not replaced:
                        if self.verbose: self.log("\tAdding node...")
                        self._symbolic_memory.add(min_addr + k, max_addr + k + 1, SymbolicItem(addr + k, obj, self.timestamp, None))

                if not disable_actions:
                    if simuvex.o.AUTO_REFS in self.state.options and action is None and not self._abstract_backer:

                        ref_size = size if size is not None else (data.size() / 8)
                        region_type = self.category
                        if region_type == 'file':
                            # Special handling for files to keep compatibility
                            # We may use some refactoring later
                            region_type = self.id
                        action = simuvex.SimActionData(self.state, region_type, 'write', addr=addr, data=data,
                                               size=ref_size,
                                               condition=condition
                                               )
                        self.state.log.add_action(action)

                        if action is not None:
                            action.actual_value = action._make_object(data)  # TODO

                return

            assert False   

        except Exception as e:

            if type(e) in (simuvex.s_errors.SimSegfaultError,):
                raise e

            import traceback
            print str(e)
            traceback.print_exc()
            sys.exit(1)

    @profile
    def same(self, a, b, range_a=None, range_b=None):

        # true if the two formulas can cover exactly one address
        # I don't know if there could be other scenarios where this
        # can be true...

        if id(a) == id(b):
            return True
        assert range_a is not None and range_b is not None
        if range_a is not None and range_b is not None and range_a[0] == range_b[0] and range_a[1] == range_b[1] and range_a[1] - range_b[0] == 1:
            return True

        try:
            cond = a != b
            return not self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def intersect(self, a, b, range_a=None, range_b=None):
        if id(a) == id(b):
            return True
        assert range_a is not None and range_b is not None
        if range_a is not None and range_b is not None and (range_a[1] < range_b[0] or range_b[1] < range_a[0]):
            return False

        try:
            cond = a == b
            return self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def disjoint(self, a, b, range_a=None, range_b=None):
        if id(a) == id(b):
            return False
        assert range_a is not None and range_b is not None 
        if range_a is not None and range_b is not None and (range_a[1] < range_b[0] or range_b[1] < range_a[0]):
            return True
        
        try:
            cond = a == b
            return not self.state.se.satisfiable(extra_constraints=(cond,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

    @profile
    def dump_memory(self):
        pass

    @profile
    def _resolve_size_range(self, size):

        if not self.state.se.symbolic(size):
            i = self.state.se.any_int(size)
            if i > self._maximum_concrete_size:
                raise simuvex.SimMemoryLimitError("Concrete size %d outside of allowable limits" % i)
            return i, i

        max_size = self.state.se.max_int(size)
        min_size = self.state.se.min_int(size)

        # we do not support symbolic size yet...
        if min_size != max_size:
            #print "addr " + str(self.state.ip)
            #print utils.full_stack()
            #assert min_size == max_size
            l.warning("Concretizing symbolic length. Much sad; think about implementing.")
            self.state.add_constraints(size == max_size, action=True)

        if min_size > self._maximum_symbolic_size:
            assert False
            min_size = self._maximum_symbolic_size

        return min_size, min(max_size, self._maximum_symbolic_size)

    @property
    def category(self):
        if self._id in ('reg', 'mem'):
            return self._id

    @profile
    def copy(self):
        if self.verbose: self.log("Copying memory")
        s = SymbolicMemory(memory_backer=self._memory_backer, 
                                permissions_backer=self._permissions_backer, 
                                kind=self._id, 
                                arch=self._arch, 
                                endness=self._endness, 
                                check_permissions=None, 
                                symbolic_memory=self._symbolic_memory.copy(),
                                stack_range=self._stack_range,
                                mapped_regions=self._mapped_regions[:],
                                verbose=self.verbose,
                                timestamp=self.timestamp,
                                initializable=self._initializable.copy(),
                                initialized=self._initialized,
                                timestamp_implicit=self.timestamp_implicit)

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

        if self.verbose: self.log("getting reference to paged memory")
        #traceback.print_stack()
        return self

    @property
    def _preapproved_stack(self):
        return self._stack_range

    @_preapproved_stack.setter
    def _preapproved_stack(self, value):
        if self.verbose: self.log("Boundaries on stack have been set by the caller: (" + str(hex(value.start)) + ", " + str(hex(value.end)) + ")")
        
        if self._stack_range is not None:
            if self.verbose: self.log("\tUnnmapping old stack...")
            for k in range(len(self._mapped_regions)):
                region = self._mapped_regions[k]
                if region.addr == self._stack_range.start:
                    del self._mapped_regions[k]
                    if self.verbose: self.log("\tDone.")
                    break

        self._stack_range = value
        self.map_region(value.start, value.end - value.start, MappedRegion.PROT_READ | MappedRegion.PROT_WRITE)

    @profile
    def log(self, msg, verbose=True):
        if verbose:
            print("[" + self._id + "] " + msg)
            #l.debug("[" + self._id + "] " + msg)

    @profile
    def error(self, msg):
        l.error("[" + self._id + "] " + msg)

    @profile
    def is_verbose(self, v):
        self.verbose = v
        if not v:
            l.setLevel(logging.INFO)

    @profile
    def map_region(self, addr, length, permissions):

        if self.verbose: self.log("Required mapping of length " + str(length) + " at " + str(hex(addr if type(addr) in (long, int) else addr.args[0])) + ".")

        if self.state.se.symbolic(addr) or self.state.se.symbolic(length):
            assert False

        # make if concrete
        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        # make perms a bitvector to easily check them
        if isinstance(permissions, (int, long)):
            permissions = claripy.BVV(permissions, 3)

        # keep track of this region
        self._mapped_regions.append(MappedRegion(addr, length, permissions))

        if self.verbose: self.log("\t" + str(self._mapped_regions[-1]))

        # sort mapped regions 
        self._mapped_regions = sorted(self._mapped_regions, key=lambda x: x.addr)

    @profile
    def unmap_region(self, addr, length):
        assert False

    @profile
    def permissions(self, addr):

        # return permissions of the addr's region

        if self.state.se.symbolic(addr):
            assert False

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.any_int(addr)

        for region in self._mapped_regions:
            if addr >= region.addr and addr <= region.addr + region.length:
                return region.permissions

        # Unmapped region?
        assert False

    @profile
    def check_sigsegv_and_refine(self, addr, min_addr, max_addr, write_access):

        if simuvex.o.STRICT_PAGE_ACCESS not in self.state.options:
            return

        # (min_addr, max_addr) is our range addr

        try:

            access_type = "write" if write_access else "read"

            if len(self._mapped_regions) == 0:
                raise simuvex.s_errors.SimSegfaultError(min_addr, "Invalid " + access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            last_covered_addr = min_addr - 1
            for region in self._mapped_regions:

                # region is after our range addr
                if max_addr < region.addr:
                    break

                # region is before our range addr
                if last_covered_addr + 1 > region.addr + region.length:
                    continue

                # there is one addr in our range that could be not covered by any region
                if last_covered_addr + 1 < region.addr:

                    # check with the solver: is there a solution for addr?
                    if self.state.se.satisfiable(extra_constraints=(addr >= last_covered_addr + 1, addr < region.addr,)):
                        raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                # last_covered_addr + 1 is inside this region
                # let's check for permissions

                upper_addr = min(region.addr + region.length, max_addr)
                if access_type == 'write':
                    if not region.is_writable() and self.state.se.satisfiable(extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                elif access_type == 'read':
                    if not region.is_readable() and self.state.se.satisfiable(extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                if max_addr > region.addr + region.length:
                    last_covered_addr = region.addr + region.length
                else:
                    last_covered_addr = max_addr

            # last region could not cover up to max_addr
            if last_covered_addr < max_addr:

                # we do not need to check with the solver since max_addr is already a valid solution for addr
                raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

        except Exception as e:

            if type(e) in (simuvex.s_errors.SimSegfaultError,):
                raise e

            print utils.full_stack()

    @profile
    def merge(self, others, merge_conditions, common_ancestor=None):

        if self.verbose: self.log("Merging memories of " + str(len(others) + 1) + " states")
        assert len(merge_conditions) == 1 + len(others)
        assert len(others) == 1  # ToDo

        self._merge(others[0], merge_conditions, common_ancestor)

        return 1

    @profile
    def _merge(self, other, merge_conditions, common_ancestor, verbose=False):

        try:

            assert self._stack_range == other._stack_range

            missing_self = set(self._initializable._keys) - set(other._initializable._keys)
            for index in missing_self:
                self._load_init_data(index * 0x1000, 1)

            assert len(set(self._initializable._keys) - set(other._initializable._keys)) == 0

            missing_other = set(other._initializable._keys) - set(self._initializable._keys)
            for index in missing_other:
                other._load_init_data(index * 0x1000, 1)

            assert len(set(other._initializable._keys) - set(self._initializable._keys)) == 0

            ancestor_timestamp = common_ancestor.timestamp
            ancestor_timestamp_implicit = common_ancestor.timestamp_implicit

            P = self._symbolic_memory.search(0, sys.maxint)
            for p in P:
                assert p.data.t >= 0
                if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (p.data.t < 0 and p.data.t < ancestor_timestamp_implicit):
                    guard = claripy.And(p.data.guard, merge_conditions[0]) if p.data.guard is not None else merge_conditions[0]
                    i = SymbolicItem(p.data.addr, p.data.obj, p.data.t, guard)
                    self._symbolic_memory.update_item(p, i)

            P = other._symbolic_memory.search(0, sys.maxint)
            for p in P:
                assert p.data.t >= 0
                if (p.data.t > 0 and p.data.t >= ancestor_timestamp) or (p.data.t < 0 and p.data.t < ancestor_timestamp_implicit):
                    guard = claripy.And(p.data.guard, merge_conditions[1]) if p.data.guard is not None else merge_conditions[1]
                    i = SymbolicItem(p.data.addr, p.data.obj, p.data.t, guard)
                    self._symbolic_memory.add(p.begin, p.end, i)

            self.timestamp = max(self.timestamp, other.timestamp)
            self.timestamp_implicit = min(self.timestamp_implicit, other.timestamp_implicit)

        except Exception as e:
            pdb.set_trace()

class Untree(object):

    def __init__(self, items=[]):
        self._list = items
        self._log = log

    def search(self, a, b):
        b -= 1
        res = []
        for e in self._list:
            if self._intersect(a, b, e.begin, e.end):
                res.append(e)
        return res

    def update_item(self, e, data):
        new_e = UntreeItem(e.begin, e.end, data, e.index)
        self._list[e.index] = new_e
        self._log.append(['u', id(self), id(e.data), id(data)])

    def copy(self):
        return Untree(self._list[:])

    def add(self, begin, end, data):
        end -= 1
        e = UntreeItem(begin, end, data, len(self._list))
        self._list.append(e)

    def _intersect(self, a_min, a_max, b_min, b_max):

        if b_min <= a_min <= b_max:
            return True

        if a_min <= b_min <= a_max:
            return True

        if b_min <= a_max <= b_max:
            return True

        if a_min <= b_max <= a_max:
            return True

        return False

class UntreeItem(object):
    __slots__ = ('begin', 'end', 'data', 'index')

    def __init__(self, begin, end, data, index):
        self.begin = begin
        self.end = end
        self.data = data
        self.index = index