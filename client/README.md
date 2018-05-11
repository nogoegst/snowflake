This is the Tor client component of Snowflake.

It is based on goptlib.

### Flags

The client uses these following `torrc` options by default:
```
ClientTransportPlugin snowflake exec ./client \
-url https://snowflake-broker.azureedge.net/ \
-front ajax.aspnetcdn.com \
-codec post \
-ice stun:stun.l.google.com:19302
```

`-url` should be the URL of a Broker instance. This is required to have
automated signalling (which is desired in most use cases).
When omitted, the client uses copy-paste signalling instead.

`-front` is an optional front domain for the Broker request.

`-codec` is an optional codec for connecting to the Broker.
It can be "post" for HTTP POST (default).

`-ice` is a comma-separated list of ICE servers. These can be STUN or TURN
servers.

