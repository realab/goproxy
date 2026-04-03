// mitm-h2-logger is a full-featured MITM proxy that intercepts both HTTP and
// HTTPS traffic, supports HTTP/2, signs TLS certificates on the fly, and logs
// every request and response with detailed information.
//
// Usage:
//
//	go run . [-v]
//
// The proxy listens on a random port and prints the address to stdout.
// Configure your client to use it, for example:
//
//	https_proxy=http://127.0.0.1:<port> curl -k https://example.com
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/elazarl/goproxy"
	utls "github.com/refraction-networking/utls"
)

func main() {
	verbose := flag.Bool("v", false, "enable goproxy internal verbose logging")
	flag.Parse()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	// MITM all HTTPS connections: generate certificates on the fly using
	// goproxy's built-in CA.
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Enable HTTP/2 frame-level proxying so that clients negotiating h2
	// via ALPN are handled correctly.
	proxy.AllowHTTP2 = true
	proxy.MatchUpstreamH2 = true

	// Configure the outbound transport to speak HTTP/2 to upstream servers.
	proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}

	// Use utls to mimic Chrome's TLS fingerprint for upstream connections.
	proxy.UpstreamTLSClientHelloID = &utls.HelloChrome_Auto
	proxy.ConfigureTransport()

	// Log every request.
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Log client TLS fingerprint if available (MITM connections).
		if hello := ctx.TLSClientHello; hello != nil && hello.JA3Hash != "" {
			log.Printf("[%03d] TLS  JA3=%s JA3Hash=%s",
				ctx.Session, hello.JA3, hello.JA3Hash)
		}

		dump, err := httputil.DumpRequest(req, false)
		if err != nil {
			log.Printf("[%03d] REQ  %-7s %s (dump error: %v)",
				ctx.Session, req.Method, req.URL, err)
		} else {
			log.Printf("[%03d] REQ  %-7s %s %s\n%s",
				ctx.Session, req.Method, req.URL, req.Proto, dump)
		}
		return req, nil
	})

	// Log every response.
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			log.Printf("[%03d] RESP <nil> error=%v", ctx.Session, ctx.Error)
			return resp
		}
		dump, err := httputil.DumpResponse(resp, false)
		if err != nil {
			log.Printf("[%03d] RESP %s %s (dump error: %v)",
				ctx.Session, resp.Status, resp.Proto, err)
		} else {
			log.Printf("[%03d] RESP %s %s\n%s",
				ctx.Session, resp.Status, resp.Proto, dump)
		}
		return resp
	})

	// Listen on a random available port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("MITM proxy listening on %s", ln.Addr())
	log.Printf("  export https_proxy=http://%s", ln.Addr())
	log.Printf("  export http_proxy=http://%s", ln.Addr())

	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 30 * time.Second,
	}
	log.Fatal(server.Serve(ln))
}
