import upmonitor.utils as utils
from upmonitor.plugins import Plugin

class Latency(Plugin):
    __slots__ = tuple()

    def __init__(self, *args, **kwargs):
        super(Latency, self).__init__(*args, **kwargs)
        self.schedule()
    def schedule(self):
        self.log.debug("Schedule")
        utils.scheduler.enter(self.plugin_conf['interval'], 10,
                self.scheduler_callback, argument=[])

    def scheduler_callback(self):
        self.log.debug("Scheduler callback")
        self.schedule()
        for target in self.plugin_conf['targets']:
            self.request_ping(target=target)

    def on_pong_notification(self, pinged_by, target, status, latency, extra):
        self.log.info('Pong notif for %s -> %s: %f' %
                (pinged_by, target, latency))

Plugin = Latency
