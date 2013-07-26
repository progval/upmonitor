import os
import imp
import logging
import traceback

from upmonitor.database import get_absolute_dict as absdict

class Plugin:
    _instances = []
    def __init__(self, database):
        self._instances.append(self)
        self.log = logging.getLogger(self.__class__.__name__)
        self.database = database

    @staticmethod
    def load_plugin(path, plugin_conf, database):
        try:
            name = os.path.splitext(os.path.split(path)[1])[0]
            module = imp.load_source(name, path)
            plugin = module.Plugin(database)
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
        for plugin in cls._instances:
            if not hasattr(plugin, 'on_key_update'):
                continue
            for (key, new_value) in new_state.items():
                assert key in old_state
                old_value = old_state[key] or (None, None)
                plugin.on_key_update(my_hostname, slave_hostname, key,
                        old_value[0], old_value[1],
                        new_value[0], new_value[1])

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
