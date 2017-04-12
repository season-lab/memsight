#!/usr/bin/python

"""
pitree: cloneable paged interval tree

Copyright 2017 Camil Demetrescu 
-- based on modified version of chaimleib's IntervalTree

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import collections
from cintervaltree import Interval, IntervalTree # use custom interval tree
    

# ----------------------------------------------------------------------
# page
# ----------------------------------------------------------------------
class page:

    def __init__(self, begin, end):
        """
        Page constructor
        """
        self.begin    = begin
        self.end      = end
        self.lazycopy = False
        self.lookup   = dict()
        self.tree     = IntervalTree()

    def copy(self):
        """
        Lazy copy of the page - O(1)
        :rtype: page
        """
        self.lazycopy = True
        p = page(self.begin, self.end)
        p.lazycopy = True
        p.tree     = self.tree
        p.lookup   = self.lookup
        return p

    def add(self, begin, end, item=None):
        """
        Insert new interval with key [begin, end] and value item.
        :param begin: interval begin point (key)
        :param end: interval end point (key)
        :param item: value associated with key
        """
        self._copy_on_write()
        i = Interval(begin, end, item)
        self.tree.add(i)
        self.lookup[i] = i

    def update_item(self, i, new_item):
        """
        Update item field of interval in the tree
        :param i: object of type Interval previously returned by search
        :param new_item: new value for interval
        """
        self._copy_on_write()
        i = self.lookup[i]
        i.data = new_item
        return i

    def _copy_on_write(self):
        if (self.lazycopy):
            self.lazycopy = False
            self.tree = self.tree.copy() # this clones Interval objects in the tree
            self.lookup.clear()
            for i in self.tree: 
                self.lookup[i] = i
        
    def __repr__(self):
        return "[begin="     + str(self.begin)      + \
               ", end="      + str(self.end)        + \
               ", lazycopy=" + str(self.lazycopy)   + \
               ", tree="     + str(self.tree) + "]"

    __str__ = __repr__


# ----------------------------------------------------------------------
# pitree
# ----------------------------------------------------------------------
class pitree:

    stats = collections.namedtuple('stats', 'num_pages num_intervals num_1_intervals')

    def __init__(self, page_size = 128):
        self.__pages       = IntervalTree()
        self.__lookup      = dict()
        self.__lazycopy    = False
        self.__page_size   = page_size
        self.__num_inter   = 0
        self.__num_1_inter = 0

    def __repr__(self):
        return "---\npages="  + str(self.__pages)       + "\n\n"  + \
               "lookup="      + str(self.__lookup)      + "\n\n"  + \
               "lazycopy="    + str(self.__lazycopy)    + "\n"    + \
               "page_size="   + str(self.__page_size)   + "\n"    + \
               "num inter="   + str(self.__num_inter)   + "\n---" + \
               "num 1-inter=" + str(self.__num_1_inter) + "\n---"

    __str__ = __repr__

    def get_stats(self):
        return pitree.stats(num_pages       = len(self.__lookup),  \
                            num_intervals   = self.__num_inter,    \
                            num_1_intervals = self.__num_1_inter)

    @classmethod
    def print_stats(cls, stats_list):
        max_pages       = 0
        max_intervals   = 0
        max_1_intervals = 0
        tot_pages       = 0
        tot_intervals   = 0
        tot_1_intervals = 0
        n               = len(stats_list)
        for s in stats_list:
            tot_pages       += s.num_pages
            tot_intervals   += s.num_intervals
            tot_1_intervals += s.num_1_intervals
            if (s.num_pages       > max_pages):       max_pages       = s.num_pages
            if (s.num_intervals   > max_intervals):   max_intervals   = s.num_intervals
            if (s.num_1_intervals > max_1_intervals): max_1_intervals = s.num_1_intervals
        print "[pitree] num pitrees="         + str(n)                 + \
                     ", max num pages="       + str(max_pages)         + \
                     ", max ints per tree="   + str(max_intervals)     + \
                     ", max 1-ints per tree=" + str(max_1_intervals)   + \
                     ", avg num pages="       + str(tot_pages/n)       + \
                     ", avg ints per tree="   + str(tot_intervals/n)   + \
                     ", avg 1-ints per tree=" + str(tot_1_intervals/n)

    def copy(self):
        """
        Lazy copy of the tree - O(1)
        :rtype: pitree
        """
        self.__lazycopy = True
        cloned = pitree(self.__page_size)
        cloned.__lazycopy    = True
        cloned.__pages       = self.__pages
        cloned.__lookup      = self.__lookup
        cloned.__num_inter   = self.__num_inter
        cloned.__num_1_inter = self.__num_1_inter
        return cloned

    def add(self, begin, end, item=None):
        """
        Insert new interval with key [begin, end) and value item.
        :param begin: interval begin point (key)
        :param end: interval end point (key)
        :param item: value associated with key
        """
        assert begin < end
        begin_p = begin / self.__page_size
        end_p   = end   / self.__page_size + 1
        self._copy_on_write()
        try:
            p = self.__lookup[(begin_p, end_p)]
            #print "adding to page " + str(p)
        except KeyError:
            p = page(begin_p, end_p)
            self.__lookup[(begin_p, end_p)] = p
            self.__pages.addi(p.begin, p.end, p)
        p.add(begin, end, item)
        self.__num_inter = self.__num_inter + 1
        if (begin + 1 == end):
            self.__num_1_inter = self.__num_1_inter + 1

    def search(self, begin, end):
        """
        Get all intervals overlapping with the interval [begin, end)
        :param begin: interval begin point (key)
        :param end: interval end point (key)
        :rtype: set of objects of type Interval (fields: begin, end, data)
        """
        assert begin < end
        begin_p = begin / self.__page_size
        end_p   = end   / self.__page_size + 1
        res = set()
        for i in self.__pages.search(begin_p, end_p):
            res.update(i.data.tree.search(begin, end))
        return res

    def update_item(self, i, new_item):
        """
        Update item field of interval in the tree
        :param i: object of type Interval previously returned by search
        :param new_item: new value for interval
        """
        self._copy_on_write()
        begin_p = i.begin / self.__page_size
        end_p   = i.end   / self.__page_size + 1
        p = self.__lookup[(begin_p, end_p)]
        return p.update_item(i, new_item)

    def _copy_on_write(self):
        """
        Clone pages and lookup data structures
        """
        if (self.__lazycopy):
            self.__lazycopy = False
            pages  = IntervalTree()
            lookup = dict()
            for p in self.__lookup.values():
                n = p.copy()
                lookup[(p.begin, p.end)] = n
                pages.addi(n.begin, n.end, n)
            self.__pages  = pages
            self.__lookup = lookup
