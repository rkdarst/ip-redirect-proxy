/*
 * ip-redirect-proxy.c - C version of ip-redirect-proxy.py
 *
 * Accepts TCP connections (ideally captured by iptables) and forwards
 * them through a SOCKS5 proxy to their original destination.
 *
 * The Python version is the primary source: update ip-redirect-proxy.py
 * first, then mirror changes here, within this port's stated parameters
 * (no --only-dst, no stats reporting, no stdin helper).
 *
 * Capture-method detection happens per connection, mirroring the Python
 * original (see original_destination()):
 *
 * REDIRECT/DNAT (nat table): the kernel rewrites the connection's
 *   destination to this proxy and records the original in conntrack,
 *   readable with getsockopt(SOL_IP, SO_ORIGINAL_DST).
 * TPROXY (mangle table, PREROUTING only): no NAT happens at all; the
 *   kernel delivers the connection with its real destination still
 *   attached, so getsockname() IS the original destination.  The
 *   listener must have IP_TRANSPARENT set, which requires CAP_NET_ADMIN
 *   or CAP_NET_RAW; this is attempted best-effort at startup.
 *
 * Errors are surfaced as C errnos; a failing connection is dropped but
 * the listener keeps going.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

/* Connect timeout, and (matching the Python version's socket timeout)
 * also the timeout for each SOCKS handshake send()/recv(). */
#define SOCKS_CONNECT_TIMEOUT_MS 10000

static const char *def_listen_host = "127.0.0.1";
static const int def_listen_port = 15001;
static const char *def_socks_host = "localhost";
static const int def_socks_port = 1080;

/* recv() until len bytes are read or the peer closes/errors. */
static int recv_exact(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n == 0) {
            errno = ECONNRESET; /* peer hung up mid-message */
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* send() loop: writes all of buf or fails. */
static int sendall(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;

    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int all_digits(const char *s)
{
    if (*s == '\0')
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* Parses "[host:]port"; host defaults to def_host, port to def_port.
 * A bare "port", ":port" and "host:" (default port) are accepted too.
 * Returns 0 on success, -1 on a malformed argument. */
static int parse_host_port(const char *text, const char *def_host,
                           int def_port, const char **out_host, int *out_port)
{
    const char *colon = strrchr(text, ':');
    long p;

    if (*text == '\0') {
        *out_host = def_host;
        *out_port = def_port;
        return 0;
    }
    if (colon == NULL) {
        if (!all_digits(text))
            return -1;
        p = strtol(text, NULL, 10);
        *out_host = def_host;
    } else if (colon == text) {
        /* ":port" */
        if (!all_digits(colon + 1))
            return -1;
        p = strtol(colon + 1, NULL, 10);
        *out_host = def_host;
    } else {
        /* "host:port" or "host:" (default port) */
        char *h = strndup(text, (size_t)(colon - text));
        if (h == NULL)
            return -1;
        *out_host = h;
        if (colon[1] == '\0') {
            *out_port = def_port;
            return 0;
        }
        if (!all_digits(colon + 1))
            return -1;
        p = strtol(colon + 1, NULL, 10);
    }
    if (p < 1 || p > 65535)
        return -1;
    *out_port = (int)p;
    return 0;
}

static int resolve_host(const char *host, int port, struct sockaddr_in *out)
{
    struct addrinfo hints, *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; /* IPv4-only tool */
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "cannot resolve %s: %s\n", host, gai_strerror(rc));
        return -1;
    }
    memset(out, 0, sizeof *out);
    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    freeaddrinfo(res);
    return 0;
}

static void fmt_sockaddr(const struct sockaddr_in *a, char *buf, size_t len)
{
    char ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip);
    snprintf(buf, len, "%s:%u", ip, (unsigned)ntohs(a->sin_port));
}

/*
 * Which capture method (if any) produced this connection is determined
 * per connection, at run time; the first path that yields a destination
 * wins:
 *
 * 1. REDIRECT/DNAT path: conntrack kept the pre-NAT destination.  If it
 *    equals our own address, no NAT was recorded (under TPROXY,
 *    conntrack never rewrote anything, so SO_ORIGINAL_DST can echo the
 *    transparent socket's own address) -- fall through rather than
 *    forward the connection back to ourselves.
 * 2. TPROXY path (only if the listener is IP_TRANSPARENT): the
 *    transparent listener received the connection with its real
 *    destination still on it, so getsockname() is the answer --
 *    unless it equals our own listening address, which means the
 *    connection was made directly to the proxy port (no capture
 *    rule); fall through rather than forward the connection back to
 *    ourselves.
 * 3. Neither: the connection went straight to the proxy port with no
 *    capture rule in place; forwarding it would send it back to this
 *    same proxy via SOCKS.  Returns -1 with errno ENOENT (the caller
 *    prints the explanatory message).
 */
static int get_original_destination(int fd, struct sockaddr_in *dst,
                                    int tproxy_enabled,
                                    const struct sockaddr_in *listen_addr)
{
    struct sockaddr_in local;
    struct sockaddr_in orig;
    socklen_t len = sizeof local;
    socklen_t olen = sizeof orig;

    if (getsockname(fd, (struct sockaddr *)&local, &len) < 0)
        return -1;
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) == 0 &&
        (orig.sin_addr.s_addr != local.sin_addr.s_addr ||
         orig.sin_port != local.sin_port)) {
        *dst = orig;
        return 0;
    }
    if (tproxy_enabled) {
        if (listen_addr == NULL ||
            local.sin_addr.s_addr != listen_addr->sin_addr.s_addr ||
            local.sin_port != listen_addr->sin_port) {
            *dst = local;
            return 0;
        }
        /* Our own listening address: a plain connection straight to the
         * proxy port; forwarding it would send it back to this same
         * proxy via SOCKS. */
    }
    errno = ENOENT;
    return -1;
}

/* connect() with a timeout: non-blocking connect + poll + SO_ERROR. */
static int connect_timeout(const struct sockaddr_in *addr, int timeout_ms)
{
    int fd, flags, err, pr;
    socklen_t elen = sizeof err;
    struct pollfd pfd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;
    if (connect(fd, (const struct sockaddr *)addr, sizeof *addr) < 0) {
        if (errno != EINPROGRESS)
            goto fail;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pr = poll(&pfd, 1, timeout_ms);
        if (pr == 0) {
            errno = ETIMEDOUT;
            goto fail;
        }
        if (pr < 0)
            goto fail;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0)
            goto fail;
        if (err != 0) {
            errno = err;
            goto fail;
        }
    }
    if (fcntl(fd, F_SETFL, flags) < 0) /* back to blocking */
        goto fail;
    return fd;
fail:
    {
        int e = errno;

        close(fd);
        errno = e;
    }
    return -1;
}

/* Optional SOCKS5 username/password authentication (RFC 1929),
 * configured through the IP_REDIRECT_PROXY_SOCKS_AUTH environment
 * variable ("user:pass", split at the first colon; unset means no-auth,
 * method 0x00).  The pointers refer into the environment string, which
 * persists for the process lifetime.  Returns 1 when credentials are
 * configured, 0 when unset, -1 on a malformed value. */
struct socks_auth {
    const char *user;
    unsigned char user_len;
    const char *pass;
    unsigned char pass_len;
};

static int parse_socks_auth_env(struct socks_auth *auth)
{
    const char *env = getenv("IP_REDIRECT_PROXY_SOCKS_AUTH");
    const char *colon;

    if (env == NULL)
        return 0;
    colon = strchr(env, ':');
    if (colon == NULL || colon == env || colon[1] == '\0' ||
        (size_t)(colon - env) > 255 || strlen(colon + 1) > 255) {
        fprintf(stderr, "IP_REDIRECT_PROXY_SOCKS_AUTH must be "
                        "\"user:pass\" with 1-255 bytes per part\n");
        return -1;
    }
    auth->user = env;
    auth->user_len = (unsigned char)(colon - env);
    auth->pass = colon + 1;
    auth->pass_len = (unsigned char)strlen(colon + 1);
    return 1;
}

/*
 * SOCKS5; method negotiation offers no-auth (0x00), or username/password
 * (0x02, RFC 1929) when auth is given.  The request carries the target
 * as an IPv4 address literal (ATYP 1).  Protocol failures print their
 * own detail line; errno is set to EPROTO.
 */
static int connect_socks5(const struct sockaddr_in *socks,
                          const struct sockaddr_in *dst,
                          const struct socks_auth *auth)
{
    unsigned char reply[22];
    int fd = connect_timeout(socks, SOCKS_CONNECT_TIMEOUT_MS);

    if (fd < 0)
        return -1;
    /* Match the Python version: the timeout covers not just the TCP
     * connect but also each handshake send()/recv(), so a SOCKS proxy
     * that accepts the connection but then stalls cannot hang this
     * connection forever.  The timeouts are removed again once the
     * handshake completes, so relaying itself is untimed. */
    {
        struct timeval tv = {
            .tv_sec = SOCKS_CONNECT_TIMEOUT_MS / 1000,
            .tv_usec = (SOCKS_CONNECT_TIMEOUT_MS % 1000) * 1000,
        };

        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
            goto fail;
    }
    if (sendall(fd, (unsigned char[]){0x05, 0x01, auth ? 0x02 : 0x00},
                3) < 0 ||
        recv_exact(fd, reply, 2) < 0)
        goto fail;
    if (reply[0] != 5 || reply[1] != (auth ? 2 : 0)) {
        fprintf(stderr,
                "SOCKS proxy did not accept our method (reply %02x %02x)\n",
                reply[0], reply[1]);
        errno = EPROTO;
        goto fail;
    }
    if (auth) {
        unsigned char req[1 + 1 + 255 + 1 + 255];
        size_t off = 0;

        /* RFC 1929 sub-negotiation: ver, ulen, uname, plen, passwd */
        req[off++] = 0x01;
        req[off++] = auth->user_len;
        memcpy(req + off, auth->user, auth->user_len);
        off += auth->user_len;
        req[off++] = auth->pass_len;
        memcpy(req + off, auth->pass, auth->pass_len);
        off += auth->pass_len;
        if (sendall(fd, req, off) < 0 || recv_exact(fd, reply, 2) < 0)
            goto fail;
        if (reply[0] != 1 || reply[1] != 0) {
            fprintf(stderr, "SOCKS5 username/password authentication "
                            "failed (status %d)\n", reply[1]);
            errno = EPROTO;
            goto fail;
        }
    }

    {
        unsigned char req[10] = {0x05, 0x01, 0x00, 0x01};

        memcpy(req + 4, &dst->sin_addr, 4); /* network order already */
        memcpy(req + 8, &dst->sin_port, 2);
        if (sendall(fd, req, sizeof req) < 0 || recv_exact(fd, reply, 4) < 0)
            goto fail;
    }
    if (reply[0] != 5 || reply[1] != 0) {
        fprintf(stderr, "SOCKS CONNECT failed (reply code %d)\n", reply[1]);
        errno = EPROTO;
        goto fail;
    }

    /* Consume the proxy's bound address and port. */
    if (reply[3] == 1) { /* IPv4: 4 addr + 2 port */
        if (recv_exact(fd, reply, 6) < 0)
            goto fail;
    } else if (reply[3] == 4) { /* IPv6: 16 addr + 2 port */
        if (recv_exact(fd, reply, 18) < 0)
            goto fail;
    } else if (reply[3] == 3) { /* Domain: 1 len + len + 2 port */
        if (recv_exact(fd, reply, 1) < 0 ||
            recv_exact(fd, reply, (size_t)reply[0] + 2) < 0)
            goto fail;
    } else {
        fprintf(stderr, "Invalid SOCKS address type %d\n", reply[3]);
        errno = EPROTO;
        goto fail;
    }
    /* Handshake complete: remove the handshake timeouts again so that
     * relaying itself is untimed. */
    {
        struct timeval tv0 = {0, 0};

        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof tv0);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv0, sizeof tv0);
    }
    return fd;
fail:
    {
        int e = errno;

        close(fd);
        errno = e;
    }
    return -1;
}

/* Relays one direction until EOF or error; propagates half-close. */
static void relay(int from, int to)
{
    char buf[65536];
    ssize_t n;

    for (;;) {
        n = read(from, buf, sizeof buf);
        if (n == 0) {
            shutdown(to, SHUT_WR);
            return;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "relay read: %s\n", strerror(errno));
            break;
        }
        if (sendall(to, buf, (size_t)n) < 0) {
            fprintf(stderr, "relay send: %s\n", strerror(errno));
            break;
        }
    }
    shutdown(from, SHUT_RDWR);
    shutdown(to, SHUT_RDWR);
}

static void handle_client(int cfd, const struct sockaddr_in *socks,
                          const struct sockaddr_in *listen_addr,
                          int tproxy_enabled, const struct socks_auth *auth)
{
    struct sockaddr_in peer, dst;
    socklen_t plen = sizeof peer;
    char peerbuf[64], dstbuf[64];
    int upfd;
    pid_t down, up;

    if (getpeername(cfd, (struct sockaddr *)&peer, &plen) < 0)
        memset(&peer, 0, sizeof peer);
    if (get_original_destination(cfd, &dst, tproxy_enabled,
                                 listen_addr) < 0) {
        fmt_sockaddr(&peer, peerbuf, sizeof peerbuf);
        fprintf(stderr,
                "connection from %s failed: connection has no original "
                "destination (not captured by REDIRECT/DNAT, TPROXY "
                "listener not enabled, or connected directly to the "
                "proxy port)\n", peerbuf);
        close(cfd);
        return;
    }
    upfd = connect_socks5(socks, &dst, auth);
    if (upfd < 0) {
        fmt_sockaddr(&peer, peerbuf, sizeof peerbuf);
        fmt_sockaddr(&dst, dstbuf, sizeof dstbuf);
        fprintf(stderr, "connection from %s to %s failed: %s\n",
                peerbuf, dstbuf, strerror(errno));
        close(cfd);
        return;
    }
    fmt_sockaddr(&peer, peerbuf, sizeof peerbuf);
    fmt_sockaddr(&dst, dstbuf, sizeof dstbuf);
    printf("%s -> SOCKS5 -> %s\n", peerbuf, dstbuf);

    /* One helper process per direction; EOF half-closes the peer. */
    down = fork();
    if (down == 0) {
        relay(cfd, upfd);
        _exit(0);
    }
    up = fork();
    if (up == 0) {
        relay(upfd, cfd);
        _exit(0);
    }
    while (waitpid(down, NULL, 0) < 0 && errno == EINTR)
        ;
    while (waitpid(up, NULL, 0) < 0 && errno == EINTR)
        ;
    close(cfd);
    close(upfd);
}

int main(int argc, char **argv)
{
    const char *listen_host, *socks_host;
    int listen_port, socks_port;
    struct sockaddr_in listen_addr, socks_addr;
    struct socks_auth auth;
    int lfd, on = 1, tproxy = 0, have_auth;

    if (argc != 3) {
        fprintf(stderr, "usage: %s listen-[host:]port socks-[host:]port\n",
                argv[0]);
        return 2;
    }
    if (parse_host_port(argv[1], def_listen_host, def_listen_port,
                        &listen_host, &listen_port) < 0 ||
        parse_host_port(argv[2], def_socks_host, def_socks_port,
                        &socks_host, &socks_port) < 0) {
        fprintf(stderr, "invalid [host:]port argument (port 1-65535)\n");
        return 2;
    }
    if (resolve_host(socks_host, socks_port, &socks_addr) < 0)
        return 1;
    if (resolve_host(listen_host, listen_port, &listen_addr) < 0)
        return 1;
    have_auth = parse_socks_auth_env(&auth);
    if (have_auth < 0)
        return 2;

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGCHLD, SIG_IGN); /* no zombies */
    signal(SIGPIPE, SIG_IGN);

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    /* TPROXY-specific (REDIRECT does not need this): mark the listener
     * IP_TRANSPARENT so the kernel hands it connections whose
     * destination is not this machine.  Requires CAP_NET_ADMIN or
     * CAP_NET_RAW, so this is best-effort: an unprivileged REDIRECT-only
     * run is unaffected, and only if it succeeds is the getsockname()
     * fallback in get_original_destination() trusted. */
    if (setsockopt(lfd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) == 0) {
        tproxy = 1;
    } else {
        fprintf(stderr, "could not set IP_TRANSPARENT (%s); "
                        "REDIRECT-only mode\n", strerror(errno));
    }
    /* The IP_TRANSPARENT setsockopt above is the only privileged
     * operation this program performs, so drop all capabilities now:
     * neither this process, nor the per-connection children, nor the
     * per-direction relay grandchildren forked later should run with
     * dormant capabilities (CAP_NET_RAW allows raw/packet sockets,
     * i.e. sniffing and spoofing, if a data-handling bug were ever
     * exploited).  Clearing every set unconditionally also keeps this
     * independent of which capabilities the binary happens to have
     * been granted (see the Makefile's CAPS).  Failure is not fatal:
     * this is hardening, not a functional requirement. */
    {
        struct __user_cap_header_struct hdr = {
            .version = _LINUX_CAPABILITY_VERSION_3,
            .pid = 0,
        };
        struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

        memset(data, 0, sizeof data);
        if (syscall(SYS_capset, &hdr, data) < 0)
            fprintf(stderr, "could not drop capabilities (%s)\n",
                    strerror(errno));
    }
    if (bind(lfd, (struct sockaddr *)&listen_addr, sizeof listen_addr) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 256) < 0) {
        perror("listen");
        return 1;
    }
    printf("Listening on %s:%d\n", listen_host, listen_port);
    if (tproxy)
        printf("TPROXY capture enabled (listener is IP_TRANSPARENT)\n");
    if (have_auth)
        printf("SOCKS5 username/password authentication enabled\n");

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        pid_t pid;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            continue;
        }
        pid = fork();
        if (pid < 0) {
            perror("fork");
            close(cfd);
            continue;
        }
        if (pid == 0) {
            close(lfd);
            handle_client(cfd, &socks_addr, &listen_addr, tproxy,
                          have_auth ? &auth : NULL);
            _exit(0);
        }
        close(cfd);
    }
}
