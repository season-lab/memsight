#!/usr/bin/python

"""
pitree: cloneable paged interval tree

Copyright 2017 Camil Demetrescu 
-- based on slightly modified version of chaimleib's IntervalTree

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
    def __init__(self):
        self.dirty = False
        self.max   = 0


# ----------------------------------------------------------------------
# pitree
# ----------------------------------------------------------------------
class pitree:

    def __init__(self, page_size = 1024):
        self.__pages     = IntervalTree()
        self.__page_size = page_size

    def __str__(self):
        return str(self.__pages) + " " + str(self.__page_size)

    def clone(self):
        """
        Clone tree
        :rtype: pitree
        """
        cloned = pitree(self.__page_size)
        cloned.__pages     = self.__pages.copy()
        for x in cloned.__pages:
            x.dirty = False
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

    # get iterator for all items in the interval [start, end]
    def slice(self, start, end):
        return None

