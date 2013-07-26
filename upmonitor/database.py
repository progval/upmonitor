"""
Database is a wrapper around a dictionnary of Host instances.
A Database is immutable.

Host is a wrapper around a dictionnary of Connection instances.
An Host is immutable.

Connection is a wrapper around a dictionnary used as state of a
connection.
A Connection can be updated in two ways:
    * from the network, with the update_from_dict method. Only
      keys with a last-update-timestamp greater than the one
      recorded are updated.
    * from the host monitoring this connection. The host gives
      a timestamp at which this change has been made, that should
      (obviously) be greater than the timestamp of the latest
      recorded change.
Time does not have to be synced between hosts since a timestamp may
only be compared with another timestamp from the same host.
"""

import bisect
import operator

class Database:
    """Distributed database storing up status of all hosts."""

    def __init__(self, hostnames):
        self._hosts = {hostname: Host(hostname, hostnames)
                       for hostname in hostnames}

    def __getitem__(self, hostname):
        return self._hosts[hostname]

    def get_from_hostnames(self, monitor_hostname=None, slave_hostname=None):
        """Get itself or an Host instance or a Connection instance matching
        the given monitor_hostname and slave_hostname.
        slave_hostname may only be provided if monitor_hostname is."""
        assert monitor_hostname is not None or slave_hostname is None
        obj = self
        if monitor_hostname is not None:
            obj = obj[monitor_hostname]
            if slave_hostname is not None:
                obj = obj[slave_hostname]
        return obj

    def to_dict(self):
        """Returns a dictionnary to be sent over network and loaded with
        update_from_dict."""
        return {key: host.to_dict() for (key, host) in self._hosts.items()}

    def update_from_dict(self, dict_):
        """Update state from network from a dictionnary created with to_dict.
        Returns a dict of dict of dict of updated values."""
        updated = {}
        for (key, value) in dict_.items():
            updates = self[key].update_from_dict(value)
            if updates:
                updated[key] = updates
        return updated

class Host:
    """Represents a host in the network."""

    def __init__(self, my_hostname, hostnames):
        self._my_hostname = my_hostname
        self._callbacks = []
        self._connections = {other_hostname:
                                Connection(other_hostname, self._callbacks)
                             for other_hostname in hostnames
                             if other_hostname != my_hostname}

    def __getitem__(self, hostname):
        return self._connections[hostname]

    def add_callback(self, cb):
        """Register a function to be called every time a connection of this
        host has one (or more) of its keys updated."""
        # Since all connections share the same callbacks list, this will
        # will update the callback list of all connections.
        self._callbacks.append(cb)

    def to_dict(self):
        """Returns a dictionnary to be sent over network and loaded with
        update_from_dict."""
        return {key: conn.to_dict()
                for (key, conn) in self._connections.items()}

    def update_from_dict(self, dict_):
        """Update state from network from a dictionnary created with to_dict.
        Returns a dict of dict of updated values."""
        updated = {}
        for (key, value) in dict_.items():
            updates = self[key].update_from_dict(value)
            if updates:
                updated[key] = updates
        return updated

class Connection:
    """Keeps an history of connection states between two hosts."""

    def __init__(self, hostname, callbacks, state=None):
        self._hostname = hostname
        self._callbacks = callbacks
        if state is None:
            state = {}
        self._state = state.copy()

    def __getitem__(self, name):
        return self._state[name][1]

    def update(self, timestamp, **kwargs):
        """Update multiple items from a given timestamp. Supposed to be used
        only by the monitor of this connection."""
        update = {key: (timestamp, value) for (key, value) in kwargs.items()}
        self._state.update(update)
        for cb in self._callbacks:
            cb(update)

    def update_one(self, timestamp, name, value):
        """Update one item. Supposed to be used only by the monitor of this
        connection."""
        assert name not in self._state or timestamp >= self._state[name][0]
        self._state[name] = (timestamp, value)
        for cb in self._callbacks:
            cb({name: (timestamp, value)}, self._hostname)

    def to_dict(self):
        """Returns a dictionnary to be sent over network and loaded with
        update_from_dict."""
        return self._state.copy()

    def update_from_dict(self, dict_):
        """Update state from network from a dictionnary created with to_dict.
        Returns a dict of updated values."""
        updated = {}
        for (key, value) in dict_.items():
            assert isinstance(value, list) or isinstance(value, tuple)
            assert len(value) == 2
            assert isinstance(value[0], float) or isinstance(value[0], int)
            if key not in self._state or value[0] > self._state[key][0]:
                self._state[key] = value
                updated[key] = value
        return updated
