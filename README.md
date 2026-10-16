# iptables transparent proxy redirect.


This code is designed to capture certain connections (with iptables, at the Linux kernel level) transparently redirected them through a SOCKS proxy.  It is designed when I need to SOCKS-proxy certain connections, but the relevant SOCKS-proxy rules are not accurate enough.  It is quite similar to [sshuttle](https://github.com/sshuttle/sshuttle), and if that tool does what you want, I would recommend to use that instead.

This tool (but not this README file) is machine-generated under my review.

Specific example use case: my LLM coding harness can't configure a SOCKS proxy for just its model endpoint, and I *don't* want to put the whole model on the VPN or set a `http_proxy` environment variable for the whole harness.  (I also didn't want to run `sshuttle` without more clarifications of what it was doing, and wanted to run my own `ssh -D` command).  This works and let me redirect *just* the IP address of the model endpoint.

The steps go like this:

* **iptables** (well, the Linux kernel) trasparently redirects connections of your choosing to `localhost:15001`.
* **This program** listens on `localhost:15001`, accepts connections, figures out the original destination, and sends them via a SOCKS proxy listening on `localhost:1080`
* **The proxy** listening on `localhost:1080` may be a `ssh -D 1080` proxy that sends it somewhere else.  (You need to run this yourself)


## Usage

Run the proxy.  The first argument is the listen [host:]port (host defaults to 127.0.0.1, port defaults to 15001), the second the SOCKS proxy [host:]port (host defaults to localhost, port defaults to 1080):

```bash
python3 ip-redirect-proxy.py 15001 localhost:1080
```

Add iptables rules with:

```bash
DST=1.2.3.4
sudo iptables -t nat -N SOCKS_OUT
sudo iptables -t nat -A SOCKS_OUT -p tcp -m multiport --dports 80,443 -d $DST -j REDIRECT --to-ports 15001
sudo iptables -t nat -I OUTPUT 1 -j SOCKS_OUT
```

Remove the example rules with (the first is sufficient to temporarily disable):
```bash
sudo iptables -t nat -D OUTPUT -j SOCKS_OUT
sudo iptables -t nat -F SOCKS_OUT
sudo iptables -t nat -X SOCKS_OUT
```


## If you want to direct everything through the proxy

Again, consider `sshuttle` instead.

You must run this tool as a dedicated unprivileged user so the firewall can exempt its SOCKS connections. The OUTPUT chain supports process owner-based exclusions; the example below redirects only TCP ports 80 and 443, skips loopback traffic, and exempts the proxy user.  This is untested and probably not recommended.

```bash
sudo useradd --system --no-create-home socksproxy
sudo -u socksproxy python3 ip-redirect_socks.py \
  --socks-host 127.0.0.1 --socks-port 1080
```

Set up the example iptables rules.  This is different from above in that it exempts the socksproxy user:

```bash
sudo iptables -t nat -N SOCKS_OUT
sudo iptables -t nat -A SOCKS_OUT -o lo -j RETURN
sudo iptables -t nat -A SOCKS_OUT -m owner --uid-owner socksproxy -j RETURN
sudo iptables -t nat -A SOCKS_OUT -p tcp -m multiport --dports 80,443 \
  -j REDIRECT --to-ports 15001
sudo iptables -t nat -I OUTPUT 1 -j SOCKS_OUT
```
