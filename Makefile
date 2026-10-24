CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
# One of CAP_NET_ADMIN or CAP_NET_RAW suffices for IP_TRANSPARENT
# (see net/ipv4/ip_sockglue.c).  CAP_NET_RAW is the narrower grant for
# a proxy that does not reconfigure networking; override if preferred:
#   make setcap CAPS=cap_net_admin+ep
CAPS ?= cap_net_raw+ep

all: ip-redirect-proxy

ip-redirect-proxy: ip-redirect-proxy.c
	$(CC) $(CFLAGS) -o $@ ip-redirect-proxy.c

# Grant the TPROXY-required capabilities to the built binary only.
# File capabilities are per-binary, so (unlike setcap on the system
# python3) this grants nothing to any other program.  Re-run after
# every rebuild: linking drops the capability xattr.
setcap: ip-redirect-proxy-c
	sudo setcap $(CAPS) ip-redirect-proxy-c

# Remove the capabilities again.
rmcap:
	sudo setcap -r ip-redirect-proxy-c 2>/dev/null || true

clean:
	rm -f ip-redirect-proxy-c

.PHONY: all clean setcap rmcap

