#!/usr/local/bin/python3
'''

>>> io = MockIO(stdin=b'password=sekret')
>>> environ = {'HTTPS': '1', 'REQUEST_METHOD': 'POST',
...            'wsgi.input': io.stdin}
>>> templates = FdPath(3, 'templates', io.ops())
>>> revocationdir = FdPath(4, 'revoked', io.ops())

>>> app = mk_app(templates, revocationdir, io.now)
>>> body = app(environ, io.start_response)

>>> print(io._start)
... # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
('200 OK', [('Content-type', 'text/html'),
            ['Set-Cookie', 'rumpelroot=...']])

>>> print(''.join(body))
... # doctest: +ELLIPSIS
blah blah KEM...

Note: #! line follows FreeBSD convention of putting python in /usr/local/bin
'''
from datetime import timedelta
from http import cookies
from os import O_RDONLY, O_WRONLY, O_CREAT
from posixpath import join as pathjoin
from socketserver import BaseServer
from sys import stderr, exc_info
import base64
import cgi
import hashlib
import hmac
import json
import logging

from jinja2 import Environment, BaseLoader, TemplateNotFound

import platform_stub
platform_stub.monkey_patch_platform(platform_stub)
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler

log = logging.getLogger(__name__)

# CHANGE THIS SALT WHEN INSTALLED ON YOUR PERSONAL SERVER!
serversalt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP"

CT_HTML = ('Content-type', 'text/html')
CT_PLAIN = ('Content-type', 'text/plain')


def main(argdata, argdirs, now):
    log.debug('main(argdata=%s)', argdata)
    if 'SCRIPT_NAME' in {}:  # TODO: environ
        raise NotImplementedError
        cgi_main(stdin, stdout, environ, cwd, now)

    app = mk_app(argdirs / 'templates', argdirs / 'revoked', now)

    with Server(argdata['socket'], app) as httpd:
        log.info('Serving on %s', httpd.socket.getsockname())
        httpd.serve_forever()


def mk_app(templates, revocationdir, now,
           DEBUGGING=True):
    get_template = Environment(
        autoescape=False,
        loader=FdPathLoader(templates),
        trim_blocks=False).get_template

    def app(environ, start_response):
        log.debug('handling request. environ keys: %s', environ.keys())
        if "HTTPS" not in environ and not DEBUGGING:
            start_response('403 Forbidden', [CT_PLAIN])
            return [err_unencrypted(environ.get('SERVERNAME'))]

        # TODO: address LC_TYPE issue
        form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
        log.debug('form keys: %s', form.keys())
        if "HTTP_COOKIE" not in environ:
            if "password" not in form:
                start_response('200 OK', [CT_HTML])
                context = {}
                html = get_template('passwordform.html').render(context)
            else:
                set_cookie, context = set_password(form["password"].value, now())
                start_response('200 OK', [CT_HTML, set_cookie.split(': ', 1)])
                html = get_template('rumpeltree.html').render(context)
        else:
            start_response('200 OK', [CT_HTML])
            context = vault_context(environ["HTTP_COOKIE"],
                                    revocationdir,
                                    form.getfirst("revocationkey"))
            html = get_template('rumpeltree.html').render(context)
        return [html]

    return app


def set_password(password, t0):
    '''Build cookie header, template context for a new password.

    >>> header, ctx = set_password('sekret', MockIO().now())
    >>> header
    ... # doctest: +ELLIPSIS
    'Set-Cookie: rumpelroot=KEM...; Domain=pass...; expires=...2020...; Path=/'
    >>> ctx
    {'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA'}
    '''
    rumpelroot = base64.b32encode(hmac.new(
        serversalt.encode('utf-8'),
        msg=password.encode('utf-8'),
        digestmod=hashlib.sha256).digest()).decode('us-ascii').strip("=")
    cookie = cookies.SimpleCookie()
    cookie["rumpelroot"] = rumpelroot
    cookie["rumpelroot"]["domain"] = "password.capibara.com"
    cookie["rumpelroot"]["path"] = "/"
    expiration = t0 + timedelta(days=365 * 20)
    cookie["rumpelroot"]["expires"] = expiration.strftime(
        "%a, %d-%b-%Y %H:%M:%S GMT")
    context = {
      'rumpelroot': rumpelroot
    }
    return cookie.output(), context


def vault_context(http_cookie, revocationdir, revocationkey):
    '''Recover root from cookie and handle revocation.

    Suppose our visitor has set a password:

    >>> io = MockIO()
    >>> http_cookie, _ctx = set_password('sekret', MockIO().now())
    >>> http_cookie = http_cookie.split(': ')[1]
    >>> _d = lambda d: sorted(d.items())

    Ordinary case:

    >>> _d(vault_context(http_cookie, FdPath(0, 'r', io.ops()), None))
    ... # doctest: +NORMALIZE_WHITESPACE
    [('revocationlist', []),
     ('rumpelroot', 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA')]
    >>> sorted(io.content.keys())
    [(3, 'templates/rumpeltree.html')]

    Incident response:

    >>> key = '12345678901234567890123456789012'
    >>> _d(vault_context(http_cookie, FdPath(0, 'r', io.ops()), key))
    ... # doctest: +NORMALIZE_WHITESPACE
    [('revocationlist', ['12345678901234567890123456789012']),
     ('rumpelroot', 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA')]
    >>> sorted(io.content.keys())
    ... # doctest: +NORMALIZE_WHITESPACE
    [(0, 'r/YUKL3QIGJ3HAGAPERA2NYK32M6QZYZI2IBRTNQTTVLMOKD7WX6DA.json'),
     (3, 'templates/rumpeltree.html')]


    '''
    cookie = cookies.SimpleCookie(http_cookie)
    rumpelroot = cookie["rumpelroot"].value
    rumpelsub = base64.b32encode(hmac.new(
        serversalt.encode('utf-8'),
        rumpelroot.encode('utf-8'),
        digestmod=hashlib.sha256).digest()).decode('utf-8').strip("=")
    revocationjsonfile = revocationdir / (rumpelsub + ".json")
    revocationlist = []
    if (revocationjsonfile.exists()):
        with revocationjsonfile.open(mode='r') as data_file:
            revocationlist = json.load(data_file)
    if revocationkey is not None:
        if len(revocationkey) == 32:
            revocationlist.append(revocationkey)
            with revocationjsonfile.open(mode='w') as outfile:
                json.dump(revocationlist, outfile)
    context = {
        'rumpelroot': rumpelroot,
        'revocationlist': revocationlist
    }
    return context


def err_unencrypted(servername):
    if servername:
        html = ("<H2>OOPS</H2><b>YOU SHOULD NEVER</b> access ZeroVault "
                "over a <b>UNENCRYPTED</b> connection!<br>"
                "Please visit the <A HREF=\"https://" +
                servername + "/\">HTTPS site</A>!")
    else:
        html = "<H2>OOPS</H2>Broken server setup. No SERVER_NAME set."
    return html.encode('utf-8')


class FdPathLoader(BaseLoader):
    def __init__(self, tpl_dir):
        self._path = lambda tpl: tpl_dir / tpl

    def get_source(self, environment, template):
        log.debug('get_source(%s)', template)
        path = self._path(template)
        if not path.exists():
            raise TemplateNotFound(template)
        # mtime = path.stat().mtime
        uptodate = lambda: False  # TODO: path.stat
        with path.open(mode='rb') as f:
            source = f.read().decode('utf-8')
        return source, str(path), uptodate


class FdPath(object):
    '''pathlib style file API using dir_fd's

    ref https://pypi.python.org/pypi/pathlib2/
    '''
    def __init__(self, dir_fd, path, ops):
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
        return '%s(%s)'% (self.__class__.__name__, self.label)

    def __truediv__(self, other):
        return self.pathjoin(other)


class ArgDataPath(object):
    def __init__(self, argdata, ops):
        self.pathjoin = lambda other: FdPath(argdata[other], '.', ops)

    def __truediv__(self, other):
        return self.pathjoin(other)


def mode_flags(mode):
    # hmm... binary on Windows?
    return ((O_WRONLY | O_CREAT) if 'w' in mode else
            O_RDONLY if 'r' in mode else 0)


class Server(WSGIServer):
    # TODO: move this out of _script()
    # once we
    def __init__(self, socket, app):
        log.debug('Server.__init__(%s, %s)', socket, app.__name__)
        BaseServer.__init__(self, None, WSGIRequestHandler)
        self.socket = socket
        self.application = app

    def get_request(self):
        log.debug('get_request...')
        out = self.socket.accept()
        log.debug('got: %s', out)
        self.server_address = self.socket.getsockname()
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port
        self.setup_environ()
        return out

    def handle_error(self, request, client_address):
        log.error('OOPS!', exc_info=exc_info())


class MockIO(object):
    example = {(3, 'templates/rumpeltree.html'):
               'blah blah {{rumpelroot}}'}

    def __init__(self, stdin=b'', content=None):
        from io import BytesIO
        self.stdin = BytesIO(stdin)
        self.stdout = BytesIO()
        self.content = self.example if content is None else content
        self._fd = {}
        self._start = None

    def ops(self):
        from posixpath import join as pathjoin
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

    def now(self):
        import datetime
        return datetime.datetime(2001, 1, 1)

    def start_response(self, status, response_headers, exc_info=None):
        self._start = (status, response_headers)
        return self.stdout.write


if __name__ == '__main__':
    def _script():
        '''Access to ambient authority derives
        from invocation as a script.
        '''
        from datetime import datetime
        from os import fdopen, open as os_open, stat
        from sys import argdata
        # TODO: CGI: from os import environ
        # TODO: CGI: from sys import stdin, stdout

        logging.basicConfig(level=logging.DEBUG, stream=stderr)
        log.debug('Logging configured.')

        argdirs = ArgDataPath(argdata, (fdopen, os_open, stat))
        main(argdata, argdirs, datetime.now)

    _script()
