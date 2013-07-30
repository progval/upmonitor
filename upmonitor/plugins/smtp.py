import time
import socket
import asyncore
import threading

import upmonitor.utils as utils
import upmonitor.plugins as plugins

class STATUS:
    CONNECTION_REFUSED = 0
    DOES_NOT_REPLY = 1
    OK = 2

class Smtp(plugins.Plugin, asyncore.dispatcher):
    __slots__ = ('_requests_lock', '_request_time', '_requests')

    def __init__(self, *args, **kwargs):
        plugins.Plugin.__init__(self, *args, **kwargs)
        asyncore.dispatcher.__init__(self)
        self.schedule()
        self._requests_lock = threading.Lock()
        self._request_time = None
        self._requests = set()
    def schedule(self):
        self.log.debug("Schedule")
        utils.scheduler.enter(self.plugin_conf['interval'], 10,
                self.scheduler_callback, argument=[])

    def scheduler_callback(self):
        self.log.debug("Scheduler callback")
        self.schedule()
        for target in self.plugin_conf['targets']:
            self.request_ping(target=target, standard_ping=False)

    def on_ping_request(self, target, data, callback):
        assert target == self.my_hostname
        with self._requests_lock:
            should_ping = not bool(self._requests)
            self._requests |= {callback}
        if should_ping:
            self.initialize_connection()

    def initialize_connection(self):
        self.log.info('Connecting to SMTP server.')
        assert self._request_time is None
        self._request_time = time.time()
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect(('localhost', 25))

    def handle_connect_event(self):
        try:
            super(Smtp, self).handle_connect_event()
        except (ConnectionRefusedError, socket.error):
            self.send_pong_notification(STATUS.CONNECTION_REFUSED)
        else:
            self.send_pong_notification(STATUS.OK)
            self.close()

    def send_pong_notification(self, status):
        with self._requests_lock:
            for cb in self._requests:
                cb(status=status, latency=time.time()-self._request_time)
            self._requests = set()
            self._request_time = None
        

    def on_pong_notification(self, pinged_by, target, status, latency, extra):
        self.log.info('SMTP server is %s on %s, latency: %f' %
                ('up' if status == STATUS.OK else 'down', target, latency))
    

Plugin = Smtp
