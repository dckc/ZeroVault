#!/usr/local/bin/python3
'''

>>> io = MockIO(stdin=b'password=sekret')
>>> environ = {'HTTPS': '1', 'REQUEST_METHOD': 'POST',
...            'wsgi.input': io.stdin}
>>> cwd = Path('.', io.ops())

>>> app = mk_app(cwd, io.now, io.FileSystemLoader)
>>> body = app(environ, io.start_response)

>>> print(io._start)
... # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
('200 OK', [('Content-type', 'text/html'),
            ['Set-Cookie', 'rumpelroot=...']])

>>> print(''.join(body))
... # doctest: +ELLIPSIS
:: render rumpeltree.html with {'rumpelroot': 'KEM...'}

Note: #! line follows FreeBSD convention of putting python in /usr/local/bin
'''
from datetime import timedelta
from sys import stderr
from http import cookies
import base64
import cgi
import hashlib
import hmac
import json

from jinja2 import Environment

# CHANGE THIS SALT WHEN INSTALLED ON YOUR PERSONAL SERVER!
serversalt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP"

CT_HTML = ('Content-type', 'text/html')
CT_PLAIN = ('Content-type', 'text/plain')


def main(stdin, stdout, cwd, now, FileSystemLoader):
    raise NotImplementedError
    # if 'SCRIPT_NAME' in environ: ...
    cgi_main(stdin, stdout, environ, cwd, now, FileSystemLoader)


def mk_app(cwd, now, FileSystemLoader):
    def app(environ, start_response):
        if "HTTPS" not in environ:
            start_response('403', [CT_PLAIN])
            return [err_unencrypted(environ.get('SERVERNAME'))]

        templates = (cwd / __file__).resolve().parent / 'templates'
        get_template = Environment(
            autoescape=False,
            loader=FileSystemLoader(str(templates)),
            trim_blocks=False).get_template

        form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ)
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
                                    cwd.resolve().parent / "revoked",
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

    Ordinary case:

    >>> vault_context(http_cookie, Path('/r', io.ops()), None)
    ... # doctest: +NORMALIZE_WHITESPACE
    {'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA',
     'revocationlist': []}
    >>> list(io.existing.keys())
    []

    Incident response:

    >>> key = '12345678901234567890123456789012'
    >>> vault_context(http_cookie, Path('/r', io.ops()), key)
    ... # doctest: +NORMALIZE_WHITESPACE
    {'rumpelroot': 'KEM23BBQKBRTKNKY4KVEQ465DKYI26FWEDY3HZGCFXOXBJCSYSNA',
     'revocationlist': ['12345678901234567890123456789012']}
    >>> list(io.existing.keys())
    ['/r/YUKL3QIGJ3HAGAPERA2NYK32M6QZYZI2IBRTNQTTVLMOKD7WX6DA.json']

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
    return html


class Path(object):
    '''pathlib style file API

    ref https://pypi.python.org/pypi/pathlib2/
    '''
    def __init__(self, path, ops):
        self._path = path
        abspath, dirname, pathjoin, exists, io_open = ops
        self.resolve = lambda: Path(abspath(path), ops)
        self.pathjoin = lambda other: Path(pathjoin(path, other), ops)
        self._parent = lambda: Path(dirname(path), ops)
        self.exists = lambda: exists(path)
        self.open = lambda mode='r': io_open(path, mode=mode)

    @property
    def parent(self):
        return self._parent()

    def __str__(self):
        return self._path

    def __truediv__(self, other):
        return self.pathjoin(other)


class MockIO(object):
    def __init__(self, stdin=b''):
        from io import BytesIO
        self.stdin = BytesIO(stdin)
        self.stdout = BytesIO()
        self.existing = {}
        self._tpl = None
        self._start = None

    def ops(self):
        from posixpath import abspath, dirname, join as pathjoin
        from io import BytesIO, StringIO

        def exists(p):
            return p in self.existing

        def io_open(p, mode):
            if 'w' in mode:
                self.existing[p] = True
            return BytesIO() if 'b' in mode else StringIO()
        return abspath, dirname, pathjoin, exists, io_open

    def now(self):
        import datetime
        return datetime.datetime(2001, 1, 1)

    def FileSystemLoader(self, path):
        # kludge
        return self

    def get_source(self, env, tpl):
        self._tpl = tpl
        return 'ARBITRARY SOURCE', '<template>', lambda: True

    def load(self, env, tpl, context):
        self._tpl = tpl
        return self

    def render(self, context):
        return ':: render %s with %s' % (self._tpl, context)

    def start_response(self, status, response_headers, exc_info=None):
        self._start = (status, response_headers)
        return self.stdout.write


if __name__ == '__main__':
    def _script():
        '''Access to ambient authority derives
        from invocation as a script.
        '''
        from datetime import datetime
        from io import open as io_open
        from os.path import abspath, dirname, join as pathjoin, exists
        # TODO: CGI: from os import environ
        # TODO: CGI: from sys import stdin, stdout

        from jinja2 import FileSystemLoader

        cwd = Path('.', (abspath, dirname, pathjoin, exists, io_open))
        main(cwd, datetime.now, FileSystemLoader)

    _script()
