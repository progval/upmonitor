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

from . import utils
from . import plugins
from . import networking

__all__ = ['PROTOCOL_VERSION', 'Handler', 'Client', 'Server', 'ServerDriver']

if sys.version_info < (3, 3, 0):
    ConnectionRefusedError = socket.gaierror

PROTOCOL_VERSION = 1

class INTENT:
    ID = 0
    CREATOR = 1
    APPROVALS = 2
    PERFORMED = 3
    EXTRA = 4

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
    newf.__doc__ = f.__doc__
    newf.__repr__ = f.__repr__
    return newf

def host_precedence(host1, host2):
    """Returns -1 if host1 has precedence, 0 if both hosts are equal, and
    1 if host2 has precedence."""
    # We use alphabetical order to determine precedance.
    # This *MUST* be consistant over ALL connected hosts or intent handling
    # will be inconsistent.
    if host1 > host2:
        return -1
    elif host1 == host2:
        return 0
    else:
        return 1

class Handler(networking.Handler):

    _instances = {}
    """Dictionnary of client handler which successfully authenticated the
    client."""
    _intents = {}
    """Dictionnary of
    {plugin: [(id, creator, approvals, performed, data), ...], ...}
    where the tuple represents an intent."""

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

    @classmethod
    def create_intent(cls, plugin, id, extra=None):
        """Creates an intent, ie. notify the network a plugin wants to do
        something, and make sure no other host will do the same thing (and
        if any of them wants to, the network will determine precedence
        between it and us).

        :param plugin: The name of the plugin creating this intent.
        :param id: An ID determined by the plugin. It has to be unique to
            this action, but has to be chosen in such a way that any other
            host that would do the same action would chose the same ID.
            (eg. Do not use local timestamps. However, if this is as a
            reaction to a database change of *one* host, it might be fine
            to use the timestamp declared by this host.)
            Can be any serializable type.
        :param extra: Any extra data that will be sent to the plugin
            callback if it is decided that we will perform this intent.
            It won't be sent over network so it is ok if it is not
            serializable."""
        if plugin not in cls._intents:
            cls._intents[plugin] = []
        logging.debug('Creating intent. Plugin: %s, id: %s' %
                (plugin, id))
        for handler in cls._instances.values():
            if handler._authenticated:
                handler.call.new_intent(
                        creator=handler._my_hostname,
                        approvals=[handler._my_hostname],
                        plugin=plugin,
                        id=id)
        # FIXME: We should not use handler._my_hostname here.
        cls._intents[plugin].append([id, handler._my_hostname,
                set([handler._my_hostname]), False, extra])

    #################################################################
    # Connection and handshake

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
        self._db_connection.update_one(time.time(), 'connected', True)
        logging.info('%s authenticated.' % self._other_hostname)

    def on_validate_handshake_reply(self, ok):
        """Reply to a 'validate_handshake' command.

        :param ok: Whether or not the validation succeeded."""
        assert ok
        self.call.request_state()
        self.call.request_intents()

    #################################################################
    # Database

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
                if instance is not self and instance._authenticated:
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
        self.perform_approved_intents()

    def perform_approved_intents(self):
        graph = utils.NetworkGraph(self._database)
        for (plugin, intents) in self._intents.items():
            for intent in intents:
                (id, creator, approvals, performed, extra) = intent
                if creator == self._my_hostname and \
                        approvals >= graph.get_reachable(self._my_hostname):
                    if performed:
                        continue
                    self.perform_intent(plugin, intent)

    #################################################################
    # Intents

    @check_auth
    def on_request_intents(self):
        self.call.new_intents(intents={plugin:
            [(id, creator, list(approvals))
             for (id, creator, approvals, performed, extra) in intents
             if not performed]
            for (plugin, intents) in self._intents.items()})

    @check_auth
    def on_new_intents(self, intents):
        for (plugin, plugin_intents) in intents.items():
            for (id, creator, approvals) in plugin_intents:
                self.on_new_intent(plugin, id, creator, approvals)

    @check_auth
    def on_new_intent(self, plugin, id, creator, approvals):
        """Asks us to approve an intent.

        :param plugin: The plugin in charge of this intent.
        :param id: An unique identifier for this intent.
        :param creator: The host which created this intent.
        :param approvals: List of hosts that approve this intent, ie.
                that *will* not create another intent doing the same
                task.
        """
        if plugin not in self._intents:
            self._intents[plugin] = []
        approvals = set(approvals)
        for intent in self._intents[plugin]:
            (id2, creator2, approvals2, performed2, extra2) = intent
            if id2 == id:
                graph = utils.NetworkGraph(self._database)
                if creator == self._my_hostname and \
                        approvals >= graph.get_reachable(self._my_hostname):
                    if performed2:
                        return
                    self.perform_intent(plugin, intent)
                else:
                    self.merge_intents(plugin, intent,
                            [id, creator, approvals, False, None])
                break
        else:
            self.add_intent_to_list(plugin,
                    [id, creator, approvals, False, None])
            return

    def add_intent_to_list(self, plugin, intent):
        """Called when we are told about a new intent that we did not see before.
        Archives and relays it."""
        (id, creator, approvals, performed, extra) = intent
        logging.debug('New intent received. Plugin: %s, ID: %s, creator: %s.' %
                (plugin, id, creator))
        approvals = set(approvals) | set([self._my_hostname])
        self._intents[plugin].append([id, creator, approvals, False, None])
        for instance in self._instances.values():
            if instance._authenticated:
                instance.call.new_intent(
                        plugin=plugin,
                        id=id,
                        creator=creator,
                        approvals=approvals)

    def perform_intent(self, plugin, intent):
        """Called when an intent has been created by us, and is approved
        by all connected hosts.
        Performs the intent and let other hosts know."""
        (id, creator, approvals, performed, extra) = intent
        logging.debug(('Performing intent. Plugin: %s, ID: %s, '
                       'creator: %s, approvals: %s.') %
                (plugin, id, creator, approvals))
        # TODO: Find a way to remove intents from the list or it will
        # take more and more memory (not a big deal in much cases, but
        # not for systems with little memory and/or with huge uptime).
        intent[INTENT.PERFORMED] = True
        for instance in self._instances.values():
            if instance._authenticated:
                instance.call.delete_intent(
                        plugin=plugin,
                        id=id)
        plugins.Plugin.dispatch_approved_intent(plugin, id,
                intent[INTENT.EXTRA])

    def merge_intents(self, plugin, old_intent, new_intent):
        """Called when we receive an intent with a (plugin, id)
        couple that is already in our intents list.
        We will determine precedence of creators, merge approvals,
        and relay it."""
        (id, creator, approvals, performed, extra) = old_intent
        (id, creator2, approvals2, foo, foo) = new_intent
        logging.debug(('Intent update. Plugin: %s, ID: %s. '
                       'Old creator: %s, old approvals: %s; '
                       'new creator: %s, new_approvals: %s.') %
                (plugin, id, creator, approvals, creator2, approvals2))
        if old_intent[INTENT.PERFORMED]:
            # Already performed
            return
        if old_intent[INTENT.CREATOR] == new_intent[INTENT.CREATOR] and \
                old_intent[INTENT.ID] == new_intent[INTENT.ID]:
            return
        # So now we have two similar but different intents, and have
        # to determine precedance.
        if host_precedence(old_intent[INTENT.CREATOR],
                new_intent[INTENT.CREATOR]) <= 0:
            prio_intent = old_intent
        else:
            prio_intent = new_intent
        # We update the old one because it is already in the intents list
        # and has the extra values, if any.
        old_intent[INTENT.CREATOR] = prio_intent[INTENT.CREATOR]
        old_intent[INTENT.APPROVALS] = (old_intent[INTENT.APPROVALS] |
                                    new_intent[INTENT.APPROVALS])
        for instance in self._instances.values():
            if instance._authenticated:
                instance.call.new_intent(
                        plugin=plugin,
                        id=id,
                        creator=old_intent[INTENT.CREATOR],
                        approvals=old_intent[INTENT.APPROVALS])

    @check_auth
    def on_delete_intent(self, plugin, id):
        """Mark an intent as performed and relay it.

        :param plugin: The plugin that created the intent
        :param id: The intent ID."""
        if plugin not in self._intents:
            return
        for intent in self._intents[plugin]:
            (id2, creator, approvals, performed, extra) = intent
            if id2 == id:
                break
        else:
            return
        if intent[INTENT.PERFORMED]:
            return
        intent[INTENT.PERFORMED] = True
        for instance in self._instances.values():
            if instance is not self and instance._authenticated:
                instance.call.delete_intent(
                        plugin=plugin,
                        id=id)

    #################################################################
    # Connection closed

    def handle_close(self):
        super(Handler, self).handle_close()
        logging.error('Connection closed by %s' % self._other_hostname)
        if hasattr(self, '_db_connection') and \
                self._db_connection['connected']:
            self._db_connection.update_one(time.time(), 'connected', False)
            self.perform_approved_intents()


class Server(Handler):
    """Handles connection with a client."""
    def __init__(self, sock, addr, driver, *args, **kwargs):
        super(Server, self).__init__(*args, sock=sock, **kwargs)
        self.handle_connect()

    def handle_close(self):
        super(Server, self).handle_close()
        if self._other_hostname in Client._clients:
            utils.scheduler.enter(self._conf['hosts'][self._my_hostname]\
                        ['monitor'][self._other_hostname]['reconnect_delay'],
                    1,
                    Client._clients[self._other_hostname].initialize_connection,
                    argument=[])


class Client(Handler):
    """Handles connection to a server."""

    _clients = {}
    def __init__(self, host, port, *args, **kwargs):
        self.__host = host
        self.__port = port
        super(Client, self).__init__(*args, **kwargs)
        self._clients[self._my_hostname] = self
        self.initialize_connection()

    def initialize_connection(self):
        self._next_initialization_scheduled = False
        if not self.connected and not self.connecting and \
                self._other_hostname not in self._instances:
            logging.info('Connecting to %s' % self._other_hostname)
            self.connecting = True
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connect((self.__host, self.__port))

    def handle_connect_event(self):
        self.connecting = False
        try:
            super(Client, self).handle_connect_event()
        except (ConnectionRefusedError, socket.error):
            logging.error('Connection refused by %s' % self._other_hostname)
            if hasattr(self, '_db_connection') and \
                    self._db_connection['connected']:
                self._db_connection.update_one(time.time(), 'connected', False)
                self.perform_approved_intents()
            utils.scheduler.enter(self._conf['hosts'][self._my_hostname]\
                        ['monitor'][self._other_hostname]['connect_delay'],
                    1, self.initialize_connection, argument=[])
            self._next_initialization_scheduled = True

    def handle_close(self):
        super(Client, self).handle_close()
        if not self._next_initialization_scheduled:
            logging.error('Connection closed by %s' % self._other_hostname)
            utils.scheduler.enter(self._conf['hosts'][self._my_hostname]\
                        ['monitor'][self._other_hostname]['reconnect_delay'],
                    1, self.initialize_connection, argument=[])

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

