untree_next_id = 1

class Untree(object):

    def __init__(self, items=[], log=None, trace=True):
        self._list = items
        self._log = log

        global untree_next_id
        self._id = untree_next_id
        untree_next_id += 1

        if self._log and trace:
            self._log.append(['n', str(self._id)])

    def search(self, a, b):

        if self._log:
            self._log.append(['s', str(self._id), str(a), str(b)])

        res = []
        for e in self._list:
            if self._intersect(a, b, e.begin, e.end):
                res.append(e)
        return res

    def update_item(self, e, data):

        if self._log:
            self._log.append(['u', str(self._id), str(id(e.data)), str(id(data))])

        new_e = UntreeItem(e.begin, e.end, data, e.index)
        self._list[e.index] = new_e

    def copy(self):

        r = Untree(self._list[:], log=(self._log[:] if self._log else None), trace=False)

        if self._log:
            self._log.append(['c', str(self._id), str(r._id)])
            r._log.append(['c', str(self._id), str(r._id)])

        return r

    def add(self, begin, end, data):

        if self._log:
            self._log.append(['a', str(self._id), str(begin), str(end), str(id(data))])

        e = UntreeItem(begin, end, data, len(self._list))
        self._list.append(e)

    def _intersect(self, a_min, a_max, b_min, b_max):
        return min(a_max, b_max) - max(a_min, b_min) > 0


class UntreeItem(object):
    __slots__ = ('begin', 'end', 'data', 'index')

    def __init__(self, begin, end, data, index):
        self.begin = begin
        self.end = end
        self.data = data
        self.index = index