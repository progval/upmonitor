import os
import sys
import time
import hmac
import socket
import base64
import xmlrpc
import logging
import asyncore
import traceback

from . import networking

if sys.version_info < (3, 3, 0):
    ConnectionRefusedError = socket.gaierror

PROTOCOL_VERSION = 1

class Handler(networking.Handler):

    _instances = {}
    """Dictionnary of client handler which successfully authenticated the
    client."""

    def __init__(self, conf, my_hostname,  other_hostname=None, sock=None):
        super(Handler, self).__init__(sock)
        self._my_hostname = my_hostname
        self._other_hostname = other_hostname
        self._conf = conf
        self._authenticated = False
        """Whether or not the remote host successfully signed the token."""
        self._token = base64.b64encode(os.urandom(64))
        """Random token used as salt for this session."""

    def handle_connect(self):
        logging.info('Sending handshake to %s.' % self._other_hostname)
        self.call.handshake(version=PROTOCOL_VERSION, token=self._token,
                hostname=self._my_hostname)

    def on_handshake(self, version, token, hostname):
        """Should be the first function called by any of the peers."""
        logging.info('Received handshake.')
        assert version == PROTOCOL_VERSION
        if self._other_hostname:
            assert hostname == self._other_hostname
        else:
            self._other_hostname = hostname
        logging.info('Handshake is from %s.' % hostname)
        m = hmac.new(self._conf['secret'].encode())
        m.update(token.encode())
        m.update(self._my_hostname.encode())
        self.call.validate_handshake(signed_token=m.hexdigest())

    def on_validate_handshake(self, signed_token):
        m = hmac.new(self._conf['secret'].encode())
        m.update(self._token)
        m.update(self._other_hostname.encode())
        assert m.hexdigest() == signed_token
        self._authenticated = True
        self._instances[self._other_hostname] = self
        logging.info('%s authenticated.' % self._other_hostname)

class Server(Handler):
    """Handles connection with a client."""
    def __init__(self, sock, addr, driver, *args, **kwargs):
        super(Server, self).__init__(*args, sock=sock, **kwargs)


class Client(Handler):
    """Handles connection to a server."""
    def __init__(self, host, port, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))

    def handle_connect_event(self):
        try:
            super(Client, self).handle_connect_event()
        except (ConnectionRefusedError, socket.error):
            logging.error('Connection refused by %s' % self._other_hostname)

class ServerDriver(asyncore.dispatcher_with_send):
    """Factory of ClientHandler objects."""
    def __init__(self, host, port, *args, **kwargs):
        super(ServerDriver, self).__init__()
        self._setup_network(host, port)
        self._args = args
        self._kwargs = kwargs

    def _setup_network(self, host, port):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        (sock, addr) = self.accept()
        Server(sock, addr, self, *self._args, **self._kwargs)

    def handle_error(self):
        traceback.print_exc()

