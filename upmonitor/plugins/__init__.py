import os
import imp
import logging
import traceback

from upmonitor.database import get_absolute_dict as absdict

__all__ = ['Plugin']

class Plugin:
    _instances = {}
    def __init__(self, my_hostname, plugin_conf, conf, database):
        assert self.__class__ is not Plugin
        self.name = self.__class__.__name__
        self._instances[self.name] = self
        self.log = logging.getLogger(self.name)
        self.log.debug('Loading plugin %s' % self.name)
        self.my_hostname = my_hostname
        self.plugin_conf = plugin_conf
        self.conf = conf
        self.database = database

    @staticmethod
    def load_plugin(path, my_hostname, plugin_conf, conf, database):
        """Tries to load a plugin and display an error in the log if
        it failed."""
        try:
            name = os.path.splitext(os.path.split(path)[1])[0]
            module = imp.load_source(name, path)
            plugin = module.Plugin(my_hostname, plugin_conf, conf, database)
        except Exception:
            logging.error('Cannot import plugin %s:\n%s' % 
                    (name, traceback.format_exc()))
            return None
        else:
            return plugin

    @classmethod
    def on_local_database_update(cls, old_state, new_state,
            my_hostname, slave_hostname=None):
        """Sends an 'update_state' to all plugins which implement
        `on_key_update` about a database update made locally (ie. not
        from network).

        :param updated: dictionnary of updated values if `slave_hostname`
            is set, and dictionnary of dictionnaries of updated values if
            it is not.
        :param slave_hostname: Hostname of the slave whose associated state
            has been updated."""
        for plugin in cls._instances.values():
            if not hasattr(plugin, 'on_key_update'):
                continue
            for (key, new_value) in new_state.items():
                assert key in old_state
                old_value = old_state[key] or (None, None)
                plugin.on_key_update(my_hostname, slave_hostname, key,
                        old_value[0], old_value[1],
                        new_value[0], new_value[1])

    @classmethod
    def dispatch_approved_intent(cls, plugin, id, extra=None):
        """Call the `on_approved_intent` method of the appropriate plugin."""
        assert plugin in cls._instances
        assert hasattr(cls._instances[plugin], 'on_approved_intent')
        cls._instances[plugin].on_approved_intent(id, extra)
    def create_intent(self, id, extra=None):
        """Create an intent and notify network handlers."""
        from upmonitor import handlers
        handlers.Handler.create_intent(self.name, id, extra)

    def request_ping(self, *args, **kwargs):
        """Ask all connection :py:class:`upmonitor.handlers.Handler`s to
        request a ping. All arguments are passed to
        :py:meth:handlers.Handler.request_ping, with the plugin name preprended
        to the list of arguments."""
        from upmonitor import handlers
        handlers.Handler.request_ping(self.name, *args, **kwargs)
    @classmethod
    def dispatch_ping_request(cls, plugin, target, data, callback):
        assert plugin in cls._instances
        assert hasattr(cls._instances[plugin], 'on_ping_request'), plugin
        cls._instances[plugin].on_ping_request(target, data, callback)
    @classmethod
    def dispatch_pong_notification(cls, plugin, pinged_by, target,
            status, latency, extra):
        assert plugin in cls._instances
        assert hasattr(cls._instances[plugin], 'on_pong_notification'), plugin
        cls._instances[plugin].on_pong_notification(pinged_by, target,
                status, latency, extra)


    def post_update_state(self, old_state, new_state,
            monitor_hostname, slave_hostname):
        if not hasattr(self, 'on_key_update'):
            return
        old_state = absdict(old_state, monitor_hostname, slave_hostname)
        new_state = absdict(new_state, monitor_hostname, slave_hostname)
        for (monitor_hostname, monitor) in new_state.items():
            for (slave_hostname, slave) in monitor.items():
                for (key, new_value) in slave.items():
                    old_value = old_state[monitor_hostname][slave_hostname] \
                            [key] or (None, None)
                    self.on_key_update(monitor_hostname, slave_hostname, key,
                            old_value[0], old_value[1],
                            new_value[0], new_value[1])

