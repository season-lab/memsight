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

from cintervaltree import IntervalTree # use custom interval tree
    

# ----------------------------------------------------------------------
# page
# ----------------------------------------------------------------------
class page:

    def __init__(self, begin, end, tree=None, lazycopy=False):
        """
        Page constructor. Intervals [begin, end] are assumed to be closed
        """
        self.begin    = begin
        self.end      = end
        self.lazycopy = lazycopy
        if tree is None:
            self.tree  = IntervalTree()
        else: 
            self.tree = tree

    def _copy_on_write(self):
        if (self.lazycopy):
            self.lazycopy = False
            self.tree = self.tree.copy() # this clones Interval objects in the tree
        
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

    def __init__(self, page_size = 1024):
        self.__pages     = IntervalTree()
        self.__lookup    = dict()
        self.__page_size = page_size

    def __repr__(self):
        return str(self.__pages) + "\n\n" + str(self.__lookup) + "\n\n" + str(self.__page_size)

    def copy(self):
        """
        Lazy copy of the tree
        :rtype: pitree
        """
        cloned = pitree(self.__page_size)
        for p in self.__lookup.values():
            n = page(p.begin, p.end, p.tree, True)
            cloned.__lookup[(p.begin, p.end+1)] = n
            cloned.__pages.addi(n.begin, n.end+1, n)
        return cloned

    def add(self, begin, end, item=None):
        """
        Insert new interval with key [begin, end] and value item.
        :param begin: interval begin point (key)
        :param end: interval end point (key)
        :param item: value associated with key
        """
        assert begin <= end
        begin_p = begin / self.__page_size
        end_p   = end   / self.__page_size
        try:
            p = self.__lookup[(begin_p, end_p+1)]
        except KeyError:
            p = page(begin_p, end_p)
            self.__lookup[(begin_p, end_p+1)] = p
            self.__pages.addi(p.begin, p.end+1, p)
        p._copy_on_write()
        p.tree.addi(begin, end+1, item)

    def search(self, begin, end):
        """
        Get all intervals overlapping with the closed interval [begin, end]
        :param begin: interval begin point (key)
        :param end: interval end point (key)
        :rtype: set of objects of type Interval (fields: begin, end+1, data)
        """
        assert begin <= end
        begin_p = begin / self.__page_size
        end_p   = end   / self.__page_size
        res = set()
        for i in self.__pages.search(begin_p, end_p+1):
            res.update(i.data.tree.search(begin, end+1))
        return res

    def update_item(self, i, new_item):
        """
        Update item field of interval in the tree
        :param i: object of type Interval previously returned by search
        :param new_item: new value for interval
        """
        i.data = new_item
        begin_p = i.begin / self.__page_size
        end_p   = i.end   / self.__page_size
        p = self.__lookup[(begin_p, end_p+1)]
        p._copy_on_write()

    __str__ = __repr__
