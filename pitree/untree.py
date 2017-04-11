class Untree(object):

    def __init__(self, items=[]):
        self._list = items

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
