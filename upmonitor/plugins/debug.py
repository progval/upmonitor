from upmonitor.plugins import Plugin

class Debug(Plugin):
    def on_key_update(self, monitor_hostname, slave_hostname,
            key, old_timestamp, old_value, new_timestamp, new_value):
        assert old_timestamp is None or new_timestamp > old_timestamp
        self.log.debug('%s -> %s: %s going from %r to %r' %
                (monitor_hostname, slave_hostname, key, old_value, new_value))


Plugin = Debug
