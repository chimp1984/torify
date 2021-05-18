# Torify library

Code base moved to https://github.com/chimp1984/misq/tree/master/torify/src/main/java/misq/torify for easy of development.
This lib is only used for resolving the maven dependencies for the tor binaries as the misq project is gradle based and
the maven tasks for verifying and downloading the binaries are not trivial to port to gradle. We might use a different
approach anyway later so not worth atm to spend effort to try to get those tasks into the misq gradle project.

Based and derived from work of:
- https://github.com/JesusMcCloud/netlayer,
- https://github.com/cedricwalter/tor-binary,
- https://github.com/thaliproject/Tor_Onion_Proxy_Library
- https://github.com/briar/briar

