#!/usr/bin/env python3
import sys
import json
import socket
import logging

from upmonitor.networking import run
from upmonitor.database import Database
from upmonitor.handlers import Client, ServerDriver, Handler

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Syntax: upmonitor.py settings.json')
        exit()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    conf = json.load(open(sys.argv[1]))
    my_hostname = socket.gethostname()
    if my_hostname not in conf['hosts']:
        print('Error: Not in hosts list.', file=sys.stderr)

    database = Database(conf['hosts'].keys())
    database[my_hostname].add_callback(
            Handler.propagate_local_database_update)

    server = None
    my_host_conf = conf['hosts'][my_hostname]
    for (hostname, host_conf) in my_host_conf['monitor'].items():
        assert hostname != my_hostname
        if 'port' in host_conf:
            port = host_conf['port'] 
        else:
            port = conf['hosts'][hostname]['daemon']['port']
        try:
            monitor = Client(host_conf['address'], port,
                    conf, database, my_hostname, hostname)
        except (ConnectionRefusedError, socket.error) as e:
            logging.error('Could not connect to %s: %r' % (hostname, e))

    server = ServerDriver(my_host_conf['daemon']['address'],
            my_host_conf['daemon']['port'],
            conf, database, my_hostname)
    try:
        run()
    except KeyboardInterrupt:
        logging.critical('Got Ctrl-C. Exiting.')
