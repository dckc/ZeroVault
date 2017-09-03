'''io_pola -- IO guided by the Principle of Least Authority

The standard Path.open() appeals to ambient authority to open files
based on string pathnames. Here we use explicit authority.

'''

from os import O_RDONLY, O_WRONLY, O_CREAT
from posixpath import join as pathjoin


class FdPath(object):
    '''pathlib style file API using dir_fd's

    >>> io = MockIO()

    >>> d1 = FdPath(0, 'subdir1', io.ops())
    >>> f1 = d1 / 'f1'
    >>> f1.exists()
    True
    >>> f1.open().read()
    'blah blah'

    '''
    def __init__(self, dir_fd, path, ops):
        '''
        @param ops: (os.fdopen, os.open, os.stat) or work-alikes
        '''
        fdopen, os_open, stat = ops
        self.label = '%d:%s' % (dir_fd, path)
        self.pathjoin = lambda other: FdPath(
            dir_fd, pathjoin(path, other), ops)

        def exists():
            try:
                stat(path, dir_fd=dir_fd)
                return True
            except OSError:
                return False
        self.exists = exists

        self.open = lambda mode='r': fdopen(
            os_open(path, mode_flags(mode), dir_fd=dir_fd), mode=mode)

    def __str__(self):
        return '%s(%s)' % (self.__class__.__name__, self.label)

    def __truediv__(self, other):
        return self.pathjoin(other)


def mode_flags(mode):
    # hmm... binary on Windows?
    return ((O_WRONLY | O_CREAT) if 'w' in mode else
            O_RDONLY if 'r' in mode else 0)


class MockIO(object):
    example = {(0, 'subdir1/f1'): 'blah blah'}

    def __init__(self, stdin=b'', content=None):
        from io import BytesIO
        self.stdin = BytesIO(stdin)
        self.stdout = BytesIO()
        self.content = self.example if content is None else content
        self._fd = {}
        self._start = None

    def ops(self):
        from io import BytesIO, StringIO

        def stat(p, dir_fd):
            if (dir_fd, p) in self.content:
                return None  # TODO: stat struct, esp. mtime
            else:
                raise OSError

        def fdopen(fd, mode):
            k = self._fd[fd]
            if 'w' in mode:
                self.content[k] = ''
            txt = self.content[k]
            bs = txt.encode('utf-8')
            return BytesIO(bs) if 'b' in mode else StringIO(txt)

        def os_open(path, flags, dir_fd):
            fd = 100 + len(self._fd)
            self._fd[fd] = (dir_fd, path)
            return fd

        return fdopen, os_open, stat

