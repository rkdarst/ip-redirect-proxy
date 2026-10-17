# iptables transparent proxy redirect.

This code is designed to capture certain connections (with iptables,
at the Linux kernel level) transparently redirected them through a
SOCKS proxy.  It was designed when I needed to SOCKS-proxy certain
connections, but I could not specify the SOCKS proxy precisely enough.
It is quite similar to
[sshuttle](https://github.com/sshuttle/sshuttle), and if that tool
does what you want, I would recommend to use that instead.  The proxy
is byte-transparent and works on SSL streams.

This tool (but not this README file) is machine-generated under my
review.

Specific example use case: my LLM coding harness can't configure a
SOCKS proxy for just its model endpoint, and I *don't* want to put the
whole model on a VPN or set a `http_proxy` environment variable for
the whole harness.  (I also didn't want to run `sshuttle` directly,
since it automated some things I wanted control of, like my own `ssh
-D` command).  ip-redirect-proxy works and let me redirect *just* the
IP address of the model endpoint.

The steps go like this:

* **iptables** (well, the Linux kernel) transparently redirects
  connections of your choosing to `localhost:15001`.
* **This program** listens on `localhost:15001`, accepts connections,
  figures out the original destination, and sends them via a SOCKS
  proxy listening on `localhost:1080`
* **The proxy** listening on `localhost:1080` may be a `ssh -D 1080`
  proxy that sends it somewhere else.  (You need to run this yourself)


## Technical notes

* IPv4 only right now.
* It should not currently be doing any tcp-over-tcp.
* Linux-only.  Realistically if you are on another operating system,
  use `sshuttle`.
* In the unprivileged (`-j REDIRECT`) mode, it only can capture
  traffic for the local computer.  See the privileged `TPROXY` mode
  for using this as a router.
* This is written in pure Python so not the highest performance (yet).


## Usage

Run the proxy.  The first argument is the listen [host:]port (host
defaults to 127.0.0.1, port defaults to 15001), the second the SOCKS
proxy [host:]port (host defaults to localhost, port defaults to 1080):

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

Remove the example rules with (the first is sufficient to temporarily
disable):
```bash
sudo iptables -t nat -D OUTPUT -j SOCKS_OUT
sudo iptables -t nat -F SOCKS_OUT
sudo iptables -t nat -X SOCKS_OUT
```


## If you want to direct everything through the proxy

Again, consider `sshuttle` instead.

You must run this tool to send all traffic through the tunnel, but you
need to exclude the proxy's traffic itself.  Below is one option to
exclude this, by creating a different user and using the iptables
process-owner match.  This is untested and probably not recommended.

```bash
sudo useradd --system --no-create-home socksproxy
sudo -u socksproxy python3 ip-redirect_socks.py 15001 localhost:1080
```

Set up the example iptables rules.  This is different from above in
that it exempts the socksproxy user:

```bash
sudo iptables -t nat -N SOCKS_OUT
sudo iptables -t nat -A SOCKS_OUT -o lo -j RETURN
sudo iptables -t nat -A SOCKS_OUT -m owner --uid-owner socksproxy -j RETURN
sudo iptables -t nat -A SOCKS_OUT -p tcp -m multiport --dports 80,443 \
  -j REDIRECT --to-ports 15001
sudo iptables -t nat -I OUTPUT 1 -j SOCKS_OUT
```


## TPROXY mode (serving as a network router)

*This has not yet been tested.*

The above sends connections with `-j REDIRECT`, which only works for
outgoing connections from the computer this runs on.  `-j TPROXY`
works with connections originated on other computers (and routed by
this computer).  If you want to do this, you probably know enough
about networking to do the setup yourself (it is not documented here).

* TPROXY mode requires elevated permissions (`CAP_NET_ADMIN`).
* If these permissions are present, the running program can use either
  `-j REDIRECT` or `-j TPROXY` (or both at the same time) all in the
  same running process.

The rough idea for directing packets into the socket is:

```bash
TODO
```



## See also

* [sshuttle](https://github.com/sshuttle/sshuttle)
  * For most normal uses, this is better.  You can even set it to only
    relay only IP ranges you want.
  * This runs custom Python code on the other end and doesn't reuse a
    transparent proxy.
  * This tries to do sudo and SSH both for you, which I did not want
    to delegate.
* [FoxyProxy
  Standard](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
  web browser extension (for Firefox/Chrome/??? despite the name)
  * This allows you to set up per-URL usage of a SOCKS proxy, so that
    different tabs can use different proxies.
  * If your use case is within a web browsing, this would be a better
    option.
  * Like with ip-redirect-proxy, you need to set up your own `ssh -D`.
