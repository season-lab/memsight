import bisect

import simuvex
import utils

class PagedMemory(object):

    PAGE_SIZE = 0x1000

    ACCESS_EXECUTE  = 0x1
    ACCESS_WRITE    = 0x2
    ACCESS_READ     = 0x4

    def __init__(self, memory, pages=dict()):
        self._pages = pages
        self._cowed = set()
        self.memory = memory

    def _get_index_offset(self, addr):
        index = addr / self.PAGE_SIZE
        offset = addr % self.PAGE_SIZE
        return index, offset

    def __getitem__(self, addr):

        #self._check_access(addr, self.ACCESS_READ)

        index, offset = self._get_index_offset(addr)

        if index not in self._pages:
            return None

        page = self._pages[index]

        if offset not in page:
            return None

        return page[offset]

    def __setitem__(self, addr, value):

        #self._check_access(addr, self.ACCESS_WRITE)
        #print "Storing at " + str(addr) + " data: " + str(value)

        index, offset = self._get_index_offset(addr)

        #print "storing at index= " + str(index) + " offset=" + str(offset)

        if index not in self._pages:
            page = dict()
            self._cowed.add(index)
            self._pages[index] = page
        else:
            page = self._pages[index]
            if index not in self._cowed:
                page = dict(page)
                self._pages[index] = page
                self._cowed.add(index)

        page[offset] = value

    def __len__(self):
        count = 0
        for p in self._pages:
            count += len(self._pages[p])
        return count

    def _check_access(self, addr, min_addr, max_addr, access_type):

        if simuvex.o.STRICT_PAGE_ACCESS not in self.state.options:
            return

        s_access_type = None
        if access_type == self.ACCESS_READ: s_access_type = "read"
        elif access_type == self.ACCESS_WRITE: s_access_type = "write"
        elif access_type == self.ACCESS_EXECUTE: s_access_type = "execute"

        # (min_addr, max_addr) is our range addr

        try:

            if len(self.memory._mapped_regions) == 0:
                raise simuvex.s_errors.SimSegfaultError(addr, "Invalid " + s_access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

            last_covered_addr = min_addr - 1
            for region in self.memory._mapped_regions:

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

                if access_type == self.ACCESS_WRITE:
                    if not region.is_writable() and self.state.se.satisfiable(extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + s_access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                elif access_type == self.ACCESS_READ:
                    if not region.is_readable() and self.state.se.satisfiable(extra_constraints=(addr >= last_covered_addr + 1, addr <= upper_addr,)):
                        raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + s_access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

                if max_addr > region.addr + region.length:
                    last_covered_addr = region.addr + region.length
                else:
                    last_covered_addr = max_addr

            # last region could not cover up to max_addr
            if last_covered_addr < max_addr:

                # we do not need to check with the solver since max_addr is already a valid solution for addr
                raise simuvex.s_errors.SimSegfaultError(last_covered_addr + 1, "Invalid " + s_access_type + " access: [" + str(hex(min_addr)) + ", " + str(hex(max_addr)) + "]")

        except Exception as e:

            if type(e) in (simuvex.s_errors.SimSegfaultError,):
                raise e

            print utils.full_stack()

    def find(self, start, end):

        #self._check_access(None, start, end, self.ACCESS_READ)
        values = {}

        range_len = end - start
        if range_len >= 1024:

            #print "Large range... pages are " + str(len(self._pages))

            indexes = sorted(self._pages.keys())
            min_index = int(start / self.PAGE_SIZE)
            max_index = int(end / self.PAGE_SIZE)
            offset = start % self.PAGE_SIZE

            #print "min_index=" + str(min_index) + " max_index=" + str(max_index)
            print indexes

            pos = bisect.bisect_left(indexes, min_index)

            while pos < len(indexes) and indexes[pos] <= max_index:

                index = indexes[pos]
                if index in self._pages:
                    #print "Looking at page index=" + str(index) + " offset=" + str(offset)
                    page = self._pages[index]
                    while offset < self.PAGE_SIZE:
                        if offset in page:
                            values[index * self.PAGE_SIZE + offset] = page[offset]
                        offset += 1
                        if index * self.PAGE_SIZE + offset > end:
                            return values
                offset = 0
                pos += 1

        else:

            addr = start
            index, offset = self._get_index_offset(addr)
            while addr <= end:

                #print "reading from index=" + str(index) + " offset=" + str(offset)

                if index not in self._pages:
                    addr += self.PAGE_SIZE - offset
                    offset = 0
                    index += 1
                    continue

                if offset in self._pages[index]:
                    values[addr] = self._pages[index][offset]
                #else: print "address is empty"

                addr += 1
                offset += 1
                if offset >= self.PAGE_SIZE:
                    offset = 0
                    index += 1

        return values

    def copy(self, memory):
        return PagedMemory(pages=dict(self._pages), memory=memory)

