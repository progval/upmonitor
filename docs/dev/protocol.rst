Protocol
^^^^^^^^

All messages are msgpack-encoding dictionnaries with a `command` entry.

On connection, both peers send a `handshake` message, and each replied
with a `validate_handshake` message; and finally a `validate_handshake_reply`
is sent as a reply to the `validate_handshake`. Starting from now, peers
authenticated each other and may start using other commands.

The list of all commands and the associated parameters can be found in the
:class:`upmonitor.handlers.Handler`'s reference <reference_handlers>`,
as any command `XXX` maps to a `on_XXX` method, whose parameters are the
other keys-value pairs of the dictionnary.

For the moment, plugins cannot access the protocol without accessing
protected attributes of handler objects (and this is intentional).
