import os
import sys
import time
import hmac
import socket
import base64
import xmlrpc
import logging
import asyncore
import threading
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

class PING:
    TARGET = 0
    PLUGIN = 1
    LOCAL_TIMESTAMP = 2
    EXTRA = 3


def check_auth(read_only):
    """Utility decorator to check the remote host has already been
    authenticated before calling the decorated method."""
    def decorator(f):
        def newf(self, *args, **kwargs):
            if self._authenticated:
                if read_only or not self._read_only:
                    return f(self, *args, **kwargs)
                else:
                    logging.warning(('Host %s using command %s without '
                            'write access.') %
                            (self._other_hostname or '<unknown>',
                             f.__name__[3:]))
            else:
                logging.warning(('Host %s using command %s without '
                        'being authenticated.') %
                        (self._other_hostname or '<unknown>',
                         f.__name__[3:]))
        newf.__doc__ = f.__doc__
        newf.__repr__ = f.__repr__
        return newf
    return decorator

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

_last_uid = 0
_uid_lock = threading.Lock()
def uid():
    """Return an unique ID (obtained with thread-safe incrementation)."""
    global _last_uid, _uid_lock
    with _uid_lock:
        _last_uid += 1
        return _last_uid

class Handler(networking.Handler):

    __slots__ = ('_my_hostname', '_other_hostname', '_conf',
            '_database', '_authenticated', '_token')

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
        self._read_only = True
        """Whether or not the remote host can write database, create intents,
        or create ping requests."""
        self._token = base64.b64encode(os.urandom(64))
        """Random token used as salt for this session."""

    #################################################################
    # Connection and handshake

    def handle_connect(self):
        """Sends a handshake to the host."""
        logging.info('Sending handshake to %s.' %
                (self._other_hostname or '<unknown>'))
        self.call.handshake(version=PROTOCOL_VERSION, token=self._token,
                hostname=self._my_hostname, read_only=False)

    def on_handshake(self, version, token, hostname, read_only):
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
        if read_only:
            secret = self._conf['secrets']['readonly']
        else:
            secret = self._conf['secrets']['readwrite']
        self._read_only = read_only
        m = hmac.new(secret.encode())
        m.update(token.encode())
        m.update(self._my_hostname.encode())
        self.call.validate_handshake(signed_token=m.hexdigest())

    def on_validate_handshake(self, signed_token):
        """Reply to a 'handshake' command.

        :param signed_token: hexadecimal digest of an hmap token created
            with the secret key + token given in 'handshake' + hostname
            of the peer signing the token."""
        m = hmac.new(self._conf['secrets']['readwrite'].encode())
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

    @check_auth(read_only=True)
    def on_request_state(self, monitor_hostname=None, slave_hostname=None):
        """Request whole or part of the database.

        :param monitor_hostname: If given, will send the state of all
            connections monitored by on host (designated by
            monitor_hostname) instead of the whole database.
        :param slave_hostname: Can only be given if `monitor_hostname`
            is given. If given, will send the state of a connection
            (the one used by `monitor_hostname` to monitor
            `slave_hostname` instead of all host's connections."""
        logging.info('State request from %s.' % self._other_hostname)
        state = self._database.get_from_hostnames(
                monitor_hostname=monitor_hostname,
                slave_hostname=slave_hostname)
        self.call.update_state(monitor_hostname=monitor_hostname,
                slave_hostname=slave_hostname,
                new_state=state.to_dict())

    @check_auth(read_only=False)
    def on_update_state(self, new_state,
            monitor_hostname=None, slave_hostname=None):
        """Updates values whose timestamp is greater than the one
        currently registered for this value. Also creates the value
        if it did not already exist.
        Also has the side-effect of sending `update_state` with the
        *actually* updated values (ie. those newer than the ones already
        registered) to all connected hosts.

        :param new_state: A dictionnary representing the values to update.
        :param monitor_hostname: See :py:meth:`.Handler.on_request_state`.
        :param slave_hostname: See :py:meth:`.Handler.on_request_state`.
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
        """Called when an host disconnects. Performs all intents
        that were only waiting for this host to approve."""
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

    _intents = {}
    """Dictionnary of
    {plugin: [(id, creator, approvals, performed, extra), ...], ...}
    where the tuple represents an intent."""

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
        cls._intents[plugin].append([id, cls._my_hostname,
                set([cls._my_hostname]), False, extra])

    @check_auth(read_only=True)
    def on_request_intents(self):
        """Reply with a 'new_intents' command. Usually called on
        connection."""
        self.call.new_intents(intents={plugin:
            [(id, creator, list(approvals))
             for (id, creator, approvals, performed, extra) in intents
             if not performed]
            for (plugin, intents) in self._intents.items()})

    @check_auth(read_only=False)
    def on_new_intents(self, intents):
        """Notify about multiple intent creation. Usually in reply
        of the 'request_intents' command.

        :param intents: Dictionnary of `{plugin: (id, creator, approvals)}`"""
        for (plugin, plugin_intents) in intents.items():
            for (id, creator, approvals) in plugin_intents:
                self.on_new_intent(plugin, id, creator, approvals)

    @check_auth(read_only=False)
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
        Archives and relays it.

        :param plugin: The plugin which should be used to perform the ping.
        :param intent: An intent tuple."""
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
        Performs the intent and let other hosts know.

        :param plugin: The plugin which should be used to perform the ping.
        :param intent: An intent tuple."""
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
        and relay it.

        :param plugin: The plugin which created the intent.
        :param old_intent: A tuple containing the already registered intent
        :param new_intent: A tuple containing the intent just received
            over network."""
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

    @check_auth(read_only=False)
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
    # Ping

    _pings = {}
    """Dictionnary of {(creator, id): (target, plugin, local_timestamp, extra)}
    where the local_timestamp is the timestamp of *this* host when the ping
    request has actually been sent."""
    _pongs = {}
    """Dict of {(creator, id): {pinged_by}}."""

    @classmethod
    def request_ping(cls, plugin, target=None, standard_ping=True,
            data=None, extra=None, direct_ping=True):
        """Request all hosts of the network to ping something (usually
        a given host).

        :param plugin: The plugin requesting this ping.
        :param target: The target host (if this is a standard ping).
        :param standard_ping: Determines whether the ping will be done
            using the 'ping' command of the protocol or if we will ask
            the plugin (on the remote host) to perform a custom ping.
        :param data: If `standard_ping` is True, this data will be
            provided to the plugin when pinging. It has to be
            serializable.
        :param extra: Data that will be given to the plugin every time
            it is notified of a pong. Does not have to be serializable as
            it will not be sent over network.
        :param direct_ping: Determines whether or not this host will
            make a ping too."""
        assert not standard_ping or data is None
        id = uid()
        key = (cls._my_hostname, id)
        assert key not in cls._pings
        cls._pings[key] = \
                [target, plugin, None, extra]
        ping_plugin = None if standard_ping else plugin # Plugin used for pinging
        for handler in cls._instances.values():
            if handler._authenticated:
                if target == handler._other_hostname:
                    handler.make_ping(cls._my_hostname, id, ping_plugin, data)
                else:
                    handler.call.request_ping(
                        creator=cls._my_hostname,
                        id=id,
                        target=target,
                        plugin=ping_plugin,
                        data=data)
        if direct_ping and target == cls._my_hostname:
            if standard_ping:
                key = (cls._my_hostname, id)
                plugins.Plugin.dispatch_pong_notification(plugin,
                        cls._my_hostname, cls._my_hostname, None, 0, extra)
            else:
                def callback(status, latency):
                    plugins.Plugin.dispatch_pong_notification(plugin,
                            cls._my_hostname, cls._my_hostname,
                            status, latency, extra)
                plugins.Plugin.dispatch_ping_request(plugin, target, data,
                        callback)

    @check_auth(read_only=False)
    def on_request_ping(self, creator, id, target, plugin, data=None):
        """Asks us to perform a ping.

        :param creator: The creator of this ping request.
        :param id: An ID for this ping request (it has to be defined
            in such a way that the (creator, id) tuple is unique.
        :param target: The target of the ping.
        :param plugin: The plugin that should be use to make
            the ping request. If None, the native 'ping' command
            of the protocol will be used.
        :param data: Any data the plugin needs to perform its ping."""
        key = (creator, id)
        if key in self._pings:
            return
        assert creator != self._my_hostname
        self._pings[key] = [target, plugin, None, None]
        if target == self._my_hostname:
            assert creator != self._my_hostname
            if plugin is None:
                self.call.pong_notification(
                        creator=creator,
                        id=id,
                        pinged_by=self._my_hostname,
                        status=None,
                        latency=0)
            else:
                def callback(status, latency):
                    self.call.pong_notification(
                            creator=creator,
                            id=id,
                            pinged_by=self._my_hostname,
                            status=status,
                            latency=latency)
                plugins.Plugin.dispatch_ping_request(plugin, target, data,
                        callback)
        elif target == self._other_hostname:
            self.make_ping(creator, id, plugin, data)
        else:
            for handler in self._instances.values():
                if handler is not self and handler._authenticated:
                    handler.call.request_ping(
                        creator=creator,
                        id=id,
                        target=target,
                        plugin=plugin,
                        data=data)

    def make_ping(self, creator, id, plugin, data):
        """Perform a ping (if this is a standard ping) or relay it to the
        target (if it is a custom ping).

        :param creator: The hostname of the creator of this ping request.
        :param id: The ID of this ping.
        :param plugin: The plugin used to perform this ping (or None
            if this is a standard ping).
        :param data: Any data used by the plugin to perform this ping."""
        if plugin is None:
            assert self._pings[(creator, id)][PING.LOCAL_TIMESTAMP] is None
            self._pings[(creator, id)][PING.LOCAL_TIMESTAMP] = time.time()
            self.call.ping(token=(creator, id))
        else:
            self.call.request_ping(
                creator=creator,
                id=id,
                target=self._other_hostname,
                plugin=plugin,
                data=data)

    def on_ping(self, token):
        """Reply with a pong.

        :param token: A token that will be sent with the 'pong'."""
        self.call.pong(token=token)

    @check_auth(read_only=False)
    def on_pong(self, token):
        """Reply to a 'ping'.

        :param token: The token we sent in the 'ping' request.
        """
        assert isinstance(token, list)
        assert len(token) == 2
        token = tuple(token)
        assert token in self._pings
        if token not in self._pongs:
            self._pongs[token] = set()
        assert self._my_hostname not in self._pongs[token]
        self._pongs[token] |= {self._my_hostname}
        latency = time.time()-self._pings[token][PING.LOCAL_TIMESTAMP]
        (creator, id) = token

        if creator == self._my_hostname:
            self.handle_pong(id, self._my_hostname, None, latency)
        else:
            for handler in self._instances.values():
                if handler._authenticated:
                    handler.call.pong_notification(
                            creator=creator,
                            id=id,
                            pinged_by=self._my_hostname,
                            status=None,
                            latency=latency)

    @check_auth(read_only=False)
    def on_pong_notification(self, creator, id, pinged_by, status, latency):
        """Called when another host received a pong. Handle it if we are the
        author of the ping; relay it if we are not.

        :param creator: The creator of the ping request
        :param id: Ping id.
        :param pinged_by: The host which sent the ping (and received the pong)
        :param status: Status of the request, if applicable.
        :param latency: The delta between the moment the ping was sent
            and the moment the pong was received."""
        key = (creator, id)
        if key not in self._pongs:
            self._pongs[key] = set()
        if pinged_by in self._pongs[key]:
            return
        self._pongs[key] |= {pinged_by}
        if creator == self._my_hostname:
            self.handle_pong(id, pinged_by, status, latency)
        else:
            for handler in self._instances.values():
                if handler._authenticated:
                    handler.call.pong_notification(
                            creator=creator,
                            id=id,
                            pinged_by=pinged_by,
                            status=status,
                            latency=latency)

    def handle_pong(self, id, pinged_by, status, latency):
        """Called after any pong or pong_notification in reply of one of
        the ping requests *we* made.

        :param id: The ID of the ping request
        :param pinged_by: The hostname of the host which actually pinged
            the host.
        :param status: Status of the request, if applicable
        :param latency: The delta between the moment the ping was sent
            and the moment the pong was received."""
        key = (self._my_hostname, id)
        assert key in self._pings
        (target, plugin, local_timestamp, extra) = self._pings[key]
        assert plugin is not None
        plugins.Plugin.dispatch_pong_notification(plugin, pinged_by, target,
                status, latency, extra)



    #################################################################
    # Connection closed

    def handle_close(self):
        """Called when the connection is closed or refused."""
        super(Handler, self).handle_close()
        if hasattr(self, '_db_connection') and \
                self._db_connection['connected']:
            logging.error('Connection closed by %s' % self._other_hostname)
            self._db_connection.update_one(time.time(), 'connected', False)
            self.perform_approved_intents()


class Server(Handler):
    """Handles connection with a client."""
    def __init__(self, sock, addr, driver, *args, **kwargs):
        super(Server, self).__init__(*args, sock=sock, **kwargs)
        self.handle_connect()

    def handle_close(self):
        """Called when the connection is closed."""
        super(Server, self).handle_close()
        if self._other_hostname in Client._clients:
            utils.scheduler.enter(self._conf['hosts'][self._my_hostname]\
                        ['monitor'][self._other_hostname]['reconnect_delay'],
                    1,
                    Client._clients[self._other_hostname].initialize_connection,
                    argument=[])


class Client(Handler):
    """Handles connection to a server."""

    __slots__ = ('_next_initialization_scheduled',)

    _clients = {}
    def __init__(self, host, port, *args, **kwargs):
        self.__host = host
        self.__port = port
        super(Client, self).__init__(*args, **kwargs)
        self._clients[self._my_hostname] = self
        self.initialize_connection()

    def initialize_connection(self):
        """Called by the constructor or by the scheduler to (re)connect
        to the server."""
        self._next_initialization_scheduled = False
        if not self.connected and not self.connecting and \
                self._other_hostname not in self._instances:
            logging.info('Connecting to %s' % self._other_hostname)
            self.connecting = True
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connect((self.__host, self.__port))

    def handle_connect_event(self):
        """Called just after the connection, whether or not it succeeded."""
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
        """Called when the connection is closed or refused."""
        super(Client, self).handle_close()
        if not self._next_initialization_scheduled:
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
        """Open the port and listen."""
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        """Spawns a new :py:class:`.Server` instance."""
        (sock, addr) = self.accept()
        Server(sock, addr, self, *self._args, **self._kwargs)

    def handle_error(self):
        traceback.print_exc()

