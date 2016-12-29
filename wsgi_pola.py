'''wsgi_fd -- WSGI guided by Principle of Least Authority

Python's standard WSGIServer inherits from TCPServer, which appeals to
ambient authority to allocate a new socket in its constructor. We get
more natural composition when we explicitly pass all necessary authority.

'''

from socketserver import BaseServer
from sys import exc_info
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler
import logging

log = logging.getLogger(__name__)


class Server(WSGIServer):
    def __init__(self, socket, app):
        log.debug('Server.__init__(%s, %s)', socket, app.__name__)
        # Bypass TCPServer.__init__()
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
        log.error('WSGI app failed.', exc_info=exc_info())
