untree_next_id = 1

class Untree(object):

    __round = 0
    __log = None

    def __init__(self, items=[], log=None, trace=True):
        self._list = items
        self._log = log

        global untree_next_id
        self._id = untree_next_id
        untree_next_id += 1

        self._log(['n', str(self._id)])

    @classmethod
    def set_log(cls, log):
        assert Untree.__log is None
        Untree.__log = log

    @classmethod
    def new_round(cls):
        Untree.__round += 1
        if Untree.__log is not None:
            Untree.__log.append(['r', _round])

    def _log(self, item):
        log = self.__log if self.__log is not None else Untree.__log if Untree.__log is not None else None
        if log is not None:
            log.append(item)

    def search(self, a, b):

        self._log(['s', str(self._id), str(a), str(b)])

        res = []
        for e in self._list:
            if self._intersect(a, b, e.begin, e.end):
                res.append(e)

        return set(res)

    def update_item(self, e, data):

        self._log(['u', str(self._id), str(id(e.data)), str(id(data))])

        new_e = UntreeItem(e.begin, e.end, data, e.index)
        self._list[e.index] = new_e

    def copy(self):

        r = Untree(self._list[:], log=(self._log[:] if self._log is not None else None), trace=False)

        self._log(['c', str(self._id), str(r._id)])
        if Untree.__log is None: r._log(['c', str(self._id), str(r._id)])

        return r

    def add(self, begin, end, data):

        self._log(['a', str(self._id), str(begin), str(end), str(id(data))])

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