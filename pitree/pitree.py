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
    def __init__(self, start, end, tree=None, lazycopy=False):
        self.start    = start
        self.end      = end
        self.lazycopy = lazycopy
        if tree is None:
            self.tree  = IntervalTree()
        else: 
            self.tree = tree
    def __str__(self):
        return "start="      + str(self.start)    + \
               ", end="      + str(self.end)      + \
               ", lazycopy=" + str(self.lazycopy) + \
               ", tree="     + str(self.tree)


# ----------------------------------------------------------------------
# pitree
# ----------------------------------------------------------------------
class pitree:

    def __init__(self, page_size = 1024):
        self.__pages     = IntervalTree()
        self.__lookup    = dict()
        self.__page_size = page_size

    def __str__(self):
        return str(self.__pages) + " " + str(self.__page_size)

    def copy(self):
        """
        Copy tree
        :rtype: pitree
        """
        cloned = pitree(self.__page_size)
        for p in self.__lookup.values():
            n = page(p.start, p.end, p.tree, True)
            cloned.__pages.addi(n.start, n.end+1, n)
        return cloned

    def add(self, start, end, item=None):
        """
        Insert new item with key [start, end].
        :param start: interval start point (key)
        :param end: interval end point (key)
        :param item: value associated with key
        """
        assert start <= end
        start_p = start / self.__page_size
        end_p   = end   / self.__page_size
        try:
            p = self.__lookup[(start_p, end_p+1)]
        except KeyError:
            p = page(start_p, end_p)
            self.__lookup[(start_p, end_p+1)] = p
            self.__pages.addi(p.start, p.end+1, p)
        if (p.lazycopy):
            p.lazycopy = False
            p.tree = p.tree.copy() # *** DEEP COPY HERE! <=================
        p.tree.addi(start, end, item)
        print p

    def search(self, start, end):
        """
        Get all items overlapping with the interval [start, end]
        :param start: interval start point (key)
        :param end: interval end point (key)
        :rtype: set of items
        """
        assert start <= end
        start_p = start / self.__page_size
        end_p   = end   / self.__page_size
        res = set()
        for i in self.__pages.search(start_p, end_p+1):
            res.update(i.data.tree.search(start, end+1))
        return res
