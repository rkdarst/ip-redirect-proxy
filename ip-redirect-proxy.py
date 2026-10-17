#!/usr/bin/env python3
import argparse
import ipaddress
import os
import signal
import socket
import struct
import sys
import threading

# Connection capture is Linux-netfilter-specific.  Two methods are supported
# and each incoming connection is detected at run time (see
# original_destination()):
#
# REDIRECT/DNAT (nat table): the kernel rewrites the connection's destination
#   to this proxy and records the original in conntrack.  REDIRECT-specific
#   readout (also what the README's nat/OUTPUT rules use):
SO_ORIGINAL_DST = 80  # getsockopt(SOL_IP, SO_ORIGINAL_DST) -> pre-NAT sockaddr_in
#
# TPROXY (mangle table, PREROUTING only): no NAT happens at all; the kernel
#   delivers the connection to the proxy with its real destination address
#   still attached, so getsockname() IS the original destination.
#   TPROXY-specific: the listener must have IP_TRANSPARENT set or the kernel
#   refuses to hand it connections addressed to other hosts.  Setting that
#   option requires CAP_NET_ADMIN or CAP_NET_RAW (see main()).
IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)  # Linux

# (dst_ip, dst_port) -> [bytes client->upstream, bytes upstream->client, connections]
stats_lock = threading.Lock()
stats = {}


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("SOCKS proxy closed the connection")
        data.extend(chunk)
    return bytes(data)


def original_destination(client, tproxy_enabled, fallback_dst=None):
    # Which capture method (if any) produced this connection is determined
    # per connection, at run time; the first path that yields a destination
    # wins:
    local = client.getsockname()[:2]
    try:
        # REDIRECT/DNAT path: conntrack kept the pre-NAT destination.
        # sockaddr_in: family (2 bytes), port (2), IPv4 address (4), padding
        raw = client.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        ip = socket.inet_ntoa(raw[4:8])
        port = struct.unpack("!H", raw[2:4])[0]
        if (ip, port) != local:
            return ip, port
        # Equal to our own address: no NAT was recorded (under TPROXY,
        # conntrack never rewrote anything, so SO_ORIGINAL_DST can echo the
        # transparent socket's own address) -- fall through rather than
        # forward the connection back to ourselves.
    except OSError:
        pass  # no conntrack NAT entry: not REDIRECT/DNAT (e.g. TPROXY)
    if tproxy_enabled:
        # TPROXY path: the transparent listener received the connection with
        # its real destination still on it, so getsockname() is the answer.
        return local
    if fallback_dst is not None:
        # Plain connection straight to the proxy port with no capture rule
        # in place, but the caller forced a destination (--only-dst):
        # treat it as a connection to that destination.
        return fallback_dst
    # Plain connection straight to the proxy port with no capture rule in
    # place; forwarding it would send it back to this same proxy via SOCKS.
    raise ConnectionError(
        "connection has no original destination "
        "(not captured by REDIRECT/DNAT, TPROXY listener not enabled, "
        "and no --only-dst destination forced)"
    )


def connect_socks5(proxy_host, proxy_port, target_ip, target_port):
    proxy = socket.create_connection((proxy_host, proxy_port), timeout=10)

    try:
        # SOCKS5, no-authentication method
        proxy.sendall(b"\x05\x01\x00")
        if recv_exact(proxy, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS proxy did not accept no-auth")

        addr = ipaddress.ip_address(target_ip)
        atyp = 1 if addr.version == 4 else 4
        request = (
            b"\x05\x01\x00" + bytes([atyp]) + addr.packed
            + struct.pack("!H", target_port)
        )
        proxy.sendall(request)

        header = recv_exact(proxy, 4)
        if header[0] != 5 or header[1] != 0:
            raise ConnectionError(f"SOCKS CONNECT failed (reply={header[1]})")

        # Consume the proxy's bound address and port.
        if header[3] == 1:
            recv_exact(proxy, 4)                  # IPv4
        elif header[3] == 4:
            recv_exact(proxy, 16)                 # IPv6
        elif header[3] == 3:
            recv_exact(proxy, recv_exact(proxy, 1)[0])  # Domain
        else:
            raise ConnectionError("Invalid SOCKS address type")
        recv_exact(proxy, 2)                      # Port

        proxy.settimeout(None)
        return proxy
    except Exception:
        proxy.close()
        raise


def copy_stream(src, dst, total):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            total[0] += len(data)
            dst.sendall(data)
    except OSError:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def parse_only_dst(text):
    # IPv4[:port], matching the destinations this tool can see.
    host, sep, port_text = text.rpartition(":")
    if not sep:
        host, port_text = text, ""
    ip = ipaddress.ip_address(host)
    if ip.version != 4:
        raise ValueError("only IPv4 destinations are supported")
    port = int(port_text) if port_text else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return ip, port


def parse_host_port(text, default_host, default_port):
    # bare port, host[:port]; host may be a hostname or IPv4 address.
    if not text:
        return default_host, default_port
    if text.isdigit():
        return default_host, int(text)
    host, sep, port_text = text.rpartition(":")
    if not sep:
        return text, default_port
    return (host or default_host), int(port_text) if port_text else default_port


def destination_allowed(only_dst, dst_ip, dst_port):
    ip, port = only_dst
    if ip != ipaddress.ip_address(dst_ip):
        return False
    return port is None or port == dst_port


def handle_client(client, args):
    peer = client.getpeername()
    upstream = None

    try:
        dst_ip, dst_port = original_destination(
            client, args.tproxy_enabled, args.only_dst
        )
        if args.only_dst is not None and not destination_allowed(
            args.only_dst, dst_ip, dst_port
        ):
            print(
                f"Connection from {peer} to {dst_ip}:{dst_port} refused "
                f"(--only-dst {args.only_dst_label})"
            )
            return
        upstream = connect_socks5(
            args.socks_host, args.socks_port, dst_ip, dst_port
        )
        print(f"{peer} -> SOCKS5 -> {dst_ip}:{dst_port}")

        sent = [0]
        received = [0]
        threads = [
            threading.Thread(target=copy_stream, args=(client, upstream, sent), daemon=True),
            threading.Thread(target=copy_stream, args=(upstream, client, received), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    except Exception as exc:
        print(f"Connection from {peer} failed: {exc}")
    finally:
        client.close()
        if upstream is not None:
            upstream.close()
            with stats_lock:
                entry = stats.setdefault((dst_ip, dst_port), [0, 0, 0])
                entry[0] += sent[0]
                entry[1] += received[0]
                entry[2] += 1


def format_stats():
    lines = ["Traffic through proxy (bytes, no TCP/IP headers):"]
    with stats_lock:
        entries = sorted(stats.items())
    if not entries:
        lines.append("  (no connections yet)")
    for (ip, port), (sent, received, conns) in entries:
        lines.append(f"  {ip}:{port}  conns={conns}  sent={sent}  recv={received}")
    return "\n".join(lines) + "\n"


def stats_stdin_watcher():
    # Interactive helper: Enter prints stats, q+Enter quits like Ctrl-C.
    try:
        for line in sys.stdin:
            cmd = line.strip().lower()
            if cmd == "q":
                os.kill(os.getpid(), signal.SIGINT)
            elif cmd == "":
                os.write(2, format_stats().encode())
    except OSError:
        pass  # stdin closed or redirected (daemon, systemd, </dev/null)


def main():
    parser = argparse.ArgumentParser(
        description="Redirected IPv4 TCP connections forwarded through SOCKS5"
    )
    parser.add_argument(
        "listen_host_port", metavar="listen-host-port",
        help="listen [host:]port - host defaults to 127.0.0.1, "
             "port defaults to 15001"
    )
    parser.add_argument(
        "socks_host_port", metavar="socks-host-port",
        help="[host:]port of target SOCKS proxy, e.g. localhost:1080 "
             " - host defaults to localhost."
    )
    parser.add_argument(
        "--only-dst", metavar="IP[:PORT]",
        help="refuse to forward connections whose original destination "
             "is not this IPv4 address (and port, if given)"
    )
    args = parser.parse_args()

    args.listen_host, args.listen_port = parse_host_port(
        args.listen_host_port, "127.0.0.1", 15001
    )
    args.socks_host, args.socks_port = parse_host_port(
        args.socks_host_port, "localhost", 1080
    )

    args.only_dst_label = None
    if args.only_dst is not None:
        try:
            ip, port = parse_only_dst(args.only_dst)
        except ValueError as exc:
            parser.error(f"--only-dst: {exc}")
        args.only_dst = (ip, port)
        args.only_dst_label = f"{ip}" + (f":{port}" if port else "")

    def dump_stats(signum, frame):
        os.write(2, format_stats().encode())

    signal.signal(signal.SIGUSR1, dump_stats)

    if sys.stdin.isatty():
        print("Press Enter for stats, q+Enter to quit.", flush=True)
    threading.Thread(target=stats_stdin_watcher, daemon=True).start()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # TPROXY-specific (REDIRECT does not need this): mark the listener
    # IP_TRANSPARENT so the kernel hands it connections whose destination is
    # not this machine.  Requires CAP_NET_ADMIN or CAP_NET_RAW, so this is
    # best-effort: an unprivileged REDIRECT-only run is unaffected, and only
    # if it succeeds is the getsockname() fallback in original_destination()
    # trusted (args.tproxy_enabled below).
    args.tproxy_enabled = False
    try:
        listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        args.tproxy_enabled = True
    except PermissionError:
        pass  # lacking the capability: REDIRECT-only mode
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(256)
    print(f"Listening on {args.listen_host}:{args.listen_port}")
    if args.tproxy_enabled:
        print("TPROXY capture enabled (listener is IP_TRANSPARENT)")

    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(
                target=handle_client, args=(client, args), daemon=True
            ).start()
    except KeyboardInterrupt:
        print(format_stats(), end="")
    finally:
        listener.close()


if __name__ == "__main__":
    main()

