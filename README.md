
# utdns with socks5 support


```
UDP/DNS-to-TCP/DNS-Translator 1.3.0, Bernhard R. Fischer, 4096R/8E24F29D <bf@abenteuerland.at>.
Usage: utdns [OPTIONS] <NS ip>
   -4 .......... Bind to IPv4 only instead of IP + IPv6.
   -b .......... Background process and log to syslog.
   -d .......... Set log level to LOG_DEBUG.
   -p <port> ... Set incoming UDP port number.
   -P <port> ... Set destination port number.
   -x <socks5://[user:password@]server:port> ... Via socks5 proxy
```
