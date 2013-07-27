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

__all__ = ['PROTOCOL_VERSION', 'Handler', 'Client', 'Server', 'ServerDriver']

if sys.version_info < (3, 3, 0):
    ConnectionRefusedError = socket.gaierror

PROTOCOL_VERSION = 1

def check_auth(f):
    """Utility decorator to check the remote host has already been
    authenticated before calling the decorated method."""
    def newf(self, *args, **kwargs):
        if self._authenticated:
            return f(self, *args, **kwargs)
        else:
            logging.warning(('Host %s using command %s without '
                    'being authenticated.') %
                    (self._other_hostname or '<unknown>',
                     f.__name__[3:]))
    return newf

class Handler(networking.Handler):

    _instances = {}
    """Dictionnary of client handler which successfully authenticated the
    client."""

    def __init__(self, conf, database, plugins,
            my_hostname, other_hostname=None, sock=None):
        super(Handler, self).__init__(sock, plugins)
        self._my_hostname = my_hostname
        self._other_hostname = other_hostname
        self._conf = conf
        self._database = database
        self._authenticated = False
        """Whether or not the remote host successfully signed the token."""
        self._token = base64.b64encode(os.urandom(64))
        """Random token used as salt for this session."""

    @classmethod
    def propagate_local_database_update(cls, old_state, updated,
            my_hostname, slave_hostname=None):
        """Sends an 'update_state' to all connected hosts about a database
        update made locally (ie. not from network).

        :param updated: dictionnary of updated values if `slave_hostname`
            is set, and dictionnary of dictionnaries of updated values if
            it is not.
        :param slave_hostname: Hostname of the slave whose associated state
            has been updated."""
        for handler in cls._instances.values():
            if handler._authenticated:
                handler.call.update_state(new_state=updated,
                        monitor_hostname=my_hostname,
                        slave_hostname=slave_hostname)

    def handle_connect(self):
        """Sends a handshake to the host."""
        logging.info('Sending handshake to %s.' % 
                (self._other_hostname or '<unknown>'))
        self.call.handshake(version=PROTOCOL_VERSION, token=self._token,
                hostname=self._my_hostname)

    def on_handshake(self, version, token, hostname):
        """Should be the first function called by any of the peers.
        
        :param version: Protocol version
        :param token: Random token string
        :param hostname: Hostname of the peer calling 'handshake'."""
        logging.info('Received handshake.')
        assert version == PROTOCOL_VERSION
        if self._other_hostname:
            assert hostname == self._other_hostname
        else:
            self._other_hostname = hostname
        self._db_connection = self._database[self._my_hostname][hostname]
        logging.info('Handshake is from %s.' % hostname)
        m = hmac.new(self._conf['secret'].encode())
        m.update(token.encode())
        m.update(self._my_hostname.encode())
        self.call.validate_handshake(signed_token=m.hexdigest())
        self._db_connection.update_one(time.time(), 'connected', True)

    def on_validate_handshake(self, signed_token):
        """Reply to a 'handshake' command.
        
        :param signed_token: hexadecimal digest of an hmap token created
            with the secret key + token given in 'handshake' + hostname
            of the peer signing the token."""
        m = hmac.new(self._conf['secret'].encode())
        m.update(self._token)
        m.update(self._other_hostname.encode())
        if m.hexdigest() == signed_token:
            self.call.validate_handshake_reply(ok=True)
        else:
            self.call.validate_handshake_reply(ok=False)
            return
        self._authenticated = True
        self._instances[self._other_hostname] = self
        logging.info('%s authenticated.' % self._other_hostname)

    def on_validate_handshake_reply(self, ok):
        """Reply to a 'validate_handshake' command.

        :param ok: Whether or not the validation succeeded."""
        assert ok
        self.call.request_state()

    @check_auth
    def on_request_state(self, monitor_hostname=None, slave_hostname=None):
        """Request whole or part of the database.

        :param monitor_hostname: If given, will send the state of all
            connections monitored by on host (designated by
            monitor_hostname) instead of the whole database.
        :param slave_hostname: Can only be given if `monitor_hostname`
            is given. If given, will send the state of a connection
            (the one used by `monitor_hostname` to monitor
            `slave_hostname) instead of all host's connections."""
        logging.info('State request from %s.' % self._other_hostname)
        state = self._database.get_from_hostnames(
                monitor_hostname=monitor_hostname,
                slave_hostname=slave_hostname)
        self.call.update_state(monitor_hostname=monitor_hostname,
                slave_hostname=slave_hostname,
                new_state=state.to_dict())

    @check_auth
    def on_update_state(self, new_state,
            monitor_hostname=None, slave_hostname=None):
        """Updates values whose timestamp is greater than the one
        currently registered for this value. Also creates the value
        if it did not already exist.
        Also has the side-effect of sending `update_state` with the
        *actually* updated values (ie. those newer than the ones already
        registered) to all connected hosts.
        
        :param new_state: A dictionnary representing the values to update.
        :param monitor_hostname: See `on_request_state`. 
        :param slave_hostname: See `on_request_state`.
        """
        logging.info('State received from %s.' % self._other_hostname)
        state = self._database.get_from_hostnames(
                monitor_hostname=monitor_hostname,
                slave_hostname=slave_hostname)
        (old_state, new_state) = state.update_from_dict(new_state)
        kwargs = {'monitor_hostname': monitor_hostname,
                'slave_hostname': slave_hostname,
                'new_state': new_state,
                }
        if new_state:
            for instance in self._instances.values():
                if instance is not self:
                    instance.call.update_state(
                        monitor_hostname=monitor_hostname,
                        slave_hostname=slave_hostname,
                        new_state=new_state)
        self.call_plugins_post_callback('update_state', {
            'monitor_hostname': monitor_hostname,
            'slave_hostname': slave_hostname,
            'new_state': new_state,
            'old_state': old_state
            })


    def handle_close(self):
        super(Handler, self).handle_close()
        if hasattr(self, '_db_connection') and \
                self._db_connection['connected']:
            self._db_connection.update_one(time.time(), 'connected', False)


class Server(Handler):
    """Handles connection with a client."""
    def __init__(self, sock, addr, driver, *args, **kwargs):
        super(Server, self).__init__(*args, sock=sock, **kwargs)
        self.handle_connect()


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

