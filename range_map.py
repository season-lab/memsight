import bisect
import math


class RangeMap(object):

    PAGE_SIZE = 4096
    CUTOFF_RANGE_SIZE = 3

    def __init__(self, large_ranges=[], ranges={}):
        self._large_ranges = large_ranges
        self._ranges = ranges
        self._cowed = set()

    def add(self, start, end, obj):

        begin = int(start / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(end / RangeMap.PAGE_SIZE))

        if end - begin >= RangeMap.CUTOFF_RANGE_SIZE:
            self._large_ranges.append((start, end, obj))

        else:

            index = begin
            t = (start, end, obj)
            while index <= finish:

                if index not in self._ranges:
                    page = [t, ]
                    self._ranges[index] = page
                    self._cowed.add(index)

                else:

                    if index not in self._cowed:
                        self._ranges[index] = list(self._ranges[index])
                        self._cowed.add(index)

                    self._ranges[index].append(t)

                index += 1

    def query(self, start, end):

        result = set()

        for r in self._large_ranges:
            if self._intersect(start, end, r[0], r[1]):
                result.add(r)


        begin = int(start / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(end / RangeMap.PAGE_SIZE))

        if end - begin < self.CUTOFF_RANGE_SIZE:

            index = begin
            while index <= finish:

                if index in self._ranges:
                    for r in self._ranges[index]:
                        if self._intersect(start, end, r[0], r[1]):
                            result.add(r)

                index += 1

        else:

            indexes = sorted(self._ranges.keys())
            k = bisect.bisect_left(indexes, begin)

            while k < len(indexes) and indexes[k] <= finish:

                index = indexes[k]
                for r in self._ranges[index]:
                    if self._intersect(start, end, r[0], r[1]):
                        result.add(r)

                k += 1

        return result

    def remove(self, r):

        # r must be returned by query()

        if r in self._large_ranges:
            self._large_ranges.remove(r)
            return

        begin = int(r[0] / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(r[1] / RangeMap.PAGE_SIZE))

        index = begin
        while index <= finish:

            if index in self._ranges:
                if r in self._ranges[index]:
                    self._ranges[index].remove(r)

            index += 1

    def replace(self, old, new):

        # old must be returned by query()
        assert old[0] == new[0] and old[1] == new[1]

        if old in self._large_ranges:
            self._large_ranges.remove(old)
            self._large_ranges.append(new)
            return

        begin = int(new[0] / RangeMap.PAGE_SIZE)
        finish = int(math.ceil(new[1] / RangeMap.PAGE_SIZE))

        index = begin
        while index <= finish:

            if index in self._ranges:
                if old in self._ranges[index]:
                    self._ranges[index].remove(old)
                    self._ranges[index].append(new)

            index += 1


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

    def copy(self):
        rm = RangeMap(list(self._large_ranges), dict(self._ranges))
        return rm

    def merge(self, others, merge_conditions):

        for o in others:
            self._large_ranges |= o._large_ranges

        assert False # ToDo


