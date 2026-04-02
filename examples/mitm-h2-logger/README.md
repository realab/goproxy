# MITM HTTP/2 Logger

A full-featured MITM proxy that intercepts HTTP and HTTPS traffic with HTTP/2
support. It signs TLS certificates on the fly using goproxy's built-in CA,
and logs every request and response with detailed headers.

## Features

- **HTTPS interception** — generates TLS certificates on the fly for every host
- **HTTP/2 support** — negotiates h2 via ALPN with both clients and upstream servers
- **Detailed logging** — dumps full request/response headers with session IDs and protocol version
- **Random port** — binds to an OS-assigned port to avoid conflicts

## Usage

Start the proxy:

```sh
go run .
```

It prints the listening address and the environment variables to set:

```
2025/01/01 12:00:00 MITM proxy listening on 127.0.0.1:54321
2025/01/01 12:00:00   export https_proxy=http://127.0.0.1:54321
2025/01/01 12:00:00   export http_proxy=http://127.0.0.1:54321
```

In another terminal, make requests through the proxy:

```sh
# HTTPS request (use -k to skip CA verification, or trust the CA below)
https_proxy=http://127.0.0.1:54321 curl -k https://example.com

# HTTP request
http_proxy=http://127.0.0.1:54321 curl http://example.com
```

Enable goproxy's internal verbose logging with `-v`:

```sh
go run . -v
```

## Trusting the CA

Since the proxy generates certificates signed by goproxy's built-in CA,
clients will show TLS warnings unless the CA is trusted. You can either:

- Pass `-k` / `--insecure` to curl
- Add the CA certificate to your system trust store (see the
  [customca example](../customca/README.md) for instructions)
