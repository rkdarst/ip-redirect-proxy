#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import struct
import threading

SO_ORIGINAL_DST = 80  # Linux IPv4


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("SOCKS proxy closed the connection")
        data.extend(chunk)
    return bytes(data)


def original_destination(client):
    # sockaddr_in: family (2 bytes), port (2), IPv4 address (4), padding
    raw = client.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    ip = socket.inet_ntoa(raw[4:8])
    port = struct.unpack("!H", raw[2:4])[0]
    return ip, port


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


def copy_stream(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
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
    # host[:port]; host may be a hostname or IPv4 address.
    host, sep, port_text = text.rpartition(":")
    if host == "":
        host = default_host
    return host, int(port_text) if port_text else default_port


def destination_allowed(only_dst, dst_ip, dst_port):
    ip, port = only_dst
    if ip != ipaddress.ip_address(dst_ip):
        return False
    return port is None or port == dst_port


def handle_client(client, args):
    peer = client.getpeername()
    upstream = None

    try:
        dst_ip, dst_port = original_destination(client)
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

        threads = [
            threading.Thread(target=copy_stream, args=(client, upstream), daemon=True),
            threading.Thread(target=copy_stream, args=(upstream, client), daemon=True),
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

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(256)
    print(f"Listening on {args.listen_host}:{args.listen_port}")

    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(
                target=handle_client, args=(client, args), daemon=True
            ).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == "__main__":
    main()

