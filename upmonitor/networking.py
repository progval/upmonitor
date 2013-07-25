import time
import logging
import msgpack
import asyncore
import traceback

class CannotConnect(Exception):
    pass
class ConnectionRefused(Exception):
    pass
class NoDataReceived(Exception):
    pass

class _MethodCaller:
    def __init__(self, handler):
        self._handler = handler
    def __getattr__(self, name):
        def method(**kwargs):
            kwargs['command'] = name
            self._handler.send(msgpack.packb(kwargs))
        return method


class Handler(asyncore.dispatcher_with_send):
    """Abstract class for managing a connection an events."""
    def __init__(self, sock=None, ui=None):
        super(Handler, self).__init__(sock)
        self._unpacker = msgpack.Unpacker(use_list=True, encoding='utf8')
        self.call = _MethodCaller(self)

    def readable(self):
        return True

    def writeable(self):
        return True

    def handle_read(self):
        data = self.recv(4096)
        self._unpacker.feed(data)
        while self._read_object():
            pass

    def _read_object(self):
        """Read an object and dispatch it according to the `command` entry."""
        try:
            obj = self._unpacker.unpack()
        except msgpack.exceptions.OutOfData:
            return False
        if obj is None:
            return False
        assert isinstance(obj, dict), obj
        assert 'command' in obj, obj
        assert isinstance(obj['command'], str), obj['command']
        method_name = 'on_' + obj.pop('command')
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            parsed = method(**obj)
        else:
            logging.info('Unknown command received: %s' % obj['command'])
        return True

    def on_ping(self, token):
        assert isinstance(token, str)
        self.call.pong(token=token)

    def handle_error(self):
        traceback.print_exc()


def run():
    """Run the network drivers."""
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print('Received Ctrl-C. Exiting.')
        return
