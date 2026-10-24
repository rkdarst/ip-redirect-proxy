#!/bin/bash -l

# Destinations for you to locally overwrite
declare -a DESTINATIONS=(
    example.org.invalid
)
PORTS=22,80,443

set -x
# new chain (no effect if already exists)
sudo iptables -t nat -N SOCKS_OUT
# flush it (resert to empty for re-filling)
sudo iptables -t nat -F SOCKS_OUT
# add relevant redirects
for DESTINATION in "${DESTINATIONS[@]}"; do
    sudo iptables -t nat -A SOCKS_OUT -p tcp -m multiport --dports "$PORTS" -d "$DESTINATION" -j REDIRECT --to-ports 15001
done

# enable it by adding the chain exit
sudo iptables -t nat -I OUTPUT 1 -j SOCKS_OUT

# trap exit: disable it
trap 'sudo iptables -t nat -D OUTPUT -j SOCKS_OUT ; set +x' EXIT

# Run with C or Python
if [ -x ip-redirect-proxy ] ; then
    ./ip-redirect-proxy 15001 localhost:8123
else
    python3 ip-redirect-proxy.py 15001 localhost:8123
fi

