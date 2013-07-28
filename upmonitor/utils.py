import time
import sched
import asyncore
import functools

__all__ = ['NetworkGraph', 'scheduler']

class NetworkGraph:
    """Utility for manipulating network graphs. All links are reciprocal.

    :param database: The database that will be used to build the graph.
    :param is_connected: A function that takes a `database.Connection`
            object and returns a boolean telling if the two hosts are
            connected. Defaults to
            `lambda x:'connected' in state and state['connected'])`"""
    class Node:
        """Represents an host of the network."""
        def __init__(self, hostname):
            self.hostname = hostname
            self.connections = {}
        def connect(self, host):
            """Add another node as connected with this one."""
            self.connections[host.hostname] = host
    def __init__(self, database, is_connected=None):
        if not is_connected:
            def is_connected(state):
                return 'connected' in state and state['connected']
        self.nodes = {}
        for monitor_hostname in database.keys():
            self.nodes[monitor_hostname] = self.Node(monitor_hostname)
        for (monitor_hostname, monitor) in database.items():
            for (slave_hostname, state) in monitor.items():
                if (is_connected(database[slave_hostname][monitor_hostname]) and
                        is_connected(state)):
                    self.nodes[monitor_hostname].connect(
                            self.nodes[slave_hostname])

    def get_reachable(self, hostname):
        """Return hostnames of all hosts this host can reach."""
        browsed = set()
        reachable = set([hostname])
        while browsed != reachable:
            this_round = reachable - browsed
            for hostname in this_round:
                reachable |= self.nodes[hostname].connections.keys()
            browsed |= this_round
        return reachable

scheduler = sched.scheduler(timefunc=time.time,
        delayfunc=functools.partial(asyncore.loop, count=1))
