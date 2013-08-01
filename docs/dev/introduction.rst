Introduction and definitions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Acknowledgements
================

Nodes do not have to be all connected to all other nodes.

Time does not have to be synchronized between hosts, neither does it have
to run at the same speed. The clock only has to run forward.

Hosts
=====

An host is a computer/process connected to the network.

A node is an authenticated host with full access to the network database
and objects.

Authentication is made using a random token (created at runtime) and a
secret token (which is never sent over network) which are concatenated
and hashed.

Plugins
=======

Upmonitor's core does not perform any action by itself.

Instead, it loads plugins, and these plugins use the core as a mean for
transporting messages.

Event types
===========

Once authenticated, nodes may communicate with each other in three
different ways.

Database update
---------------

All nodes share the same database. Each node is allocated a part of the
database, and only this node may edit this part.
Any change made to the database is announced to all hosts connected to
the one which made the change; all these hosts will then save the
change and, if they did not already save it, will broadcast the change
to all hosts connected to them, and so on.
A change is associated with timestamp (specific to the host which made
the change) so there is no risk for conflict if a key is changed
twice, and the oldest change arrives after the newest.

The database is used for instance by nodes to register the state of
the connections between them and other hosts.

Intents
-------

When a plugin wants to perform an action, but does not want to perform
it on multiple hosts, it should create an intent.
Intents are broadcasted like database updates; but, as multiple hosts
may create similar intents at the same time (and we only want one of them
to perform the action), we ask all nodes for approval (ie. hosts will say
they let the creator of the intent perform it).
In case of conflict, nodes will use a specific algorithm to determine
precedance between hosts.

Once an intent is approved by all *connected* hosts, it is performed.

Intents are used for instance by the `MailNotification` plugin: when
the state of a connection changes, this plugin creates an intent for
mailing the contact address(es) in order to prevent multiple hosts
for sending a mail for the *same* (dis)connection.

Ping requests
-------------

Like database updates and intents, ping requests are created by a plugin
and broadcasted to the network.
The difference is a ping request asks all nodes of the network to ping
a specific host, and return the latency (ie. the delta between the moment
the ping was sent by the host, and the moment the pong was received by
the host) to the node which created the ping request (still using
broadcast).

Standard pings
~~~~~~~~~~~~~~

Standard pings are done sending a `ping` command *to* a target host,
and waiting for a `pong` command.

Custom pings
~~~~~~~~~~~~

Custom ping are done by calling a method of a plugin *on* the target
host. It may return advanced data to the creator of the ping request.

