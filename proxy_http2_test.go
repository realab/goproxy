package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	pb "github.com/elazarl/goproxy/test_data/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
)

// --- gRPC Echo server implementation using generated protobuf ---

type echoServer struct {
	pb.UnimplementedEchoServer
}

func (s *echoServer) BidiChat(stream pb.Echo_BidiChatServer) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&pb.ChatMessage{Value: "echo:" + msg.GetValue()}); err != nil {
			return err
		}
	}
}

// --- helpers ---

// connectViaProxy dials the proxy, issues an HTTP CONNECT for target, and
// returns the tunnelled connection ready for TLS.
func connectViaProxy(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	connectReq, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+target, nil)
	connectReq.Host = target
	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %s", resp.Status)
	}
	return &h2ReadBufferedConn{Conn: conn, r: br}, nil
}

// h2ReadBufferedConn wraps a net.Conn with a buffered reader so that TLS
// reads from the buffer first (important after HTTP CONNECT response parsing).
type h2ReadBufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *h2ReadBufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// --- HTTP/2 MITM response tests ---

func TestMITMResponseHTTP2MissingContentLength(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // forces missing Content-Length
		}
		_, _ = w.Write([]byte("HTTP/2 response"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		assert.Equal(t, "HTTP/1.1", req.Proto)
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		assert.Equal(t, "HTTP/2.0", resp.Proto)
		return resp
	})
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}

	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxySrv.URL)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	require.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.EqualValues(t, -1, resp.ContentLength)
	assert.Equal(t, []string{"chunked"}, resp.TransferEncoding)
	assert.Len(t, body, 15)
}

func TestMITMResponseHTTP2ProtoVersion(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}

	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	// Raw HTTP/1.1 client (no ALPN) through the MITM proxy.
	proxyURL, _ := url.Parse(proxySrv.URL)
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer conn.Close()

	connectReq, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, srv.URL, nil)
	require.NoError(t, connectReq.Write(conn))
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	httpReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	require.NoError(t, httpReq.Write(tlsConn))

	tlsBr := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(tlsBr, httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "hello", string(body))
	assert.Equal(t, 1, resp.ProtoMajor,
		"MITM'd HTTP/1.1 client should receive HTTP/1.x response, got %s", resp.Proto)
}

// --- HTTP/2 client negotiation tests ---

// TestMITMClientHTTP2Negotiation groups tests for HTTP/2 ALPN negotiation
// between the client and the MITM proxy under various upstream conditions.
func TestMITMClientHTTP2Negotiation(t *testing.T) {
	t.Run("H2Upstream", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("h2 ok"))
		}))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		defer srv.Close()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.Tr = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			},
		}

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				},
			},
		}

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "h2 ok", string(body))
		assert.Equal(t, 2, resp.ProtoMajor,
			"client should negotiate h2 when upstream supports it, got %s", resp.Proto)
	})

	t.Run("H1Backend", func(t *testing.T) {
		// HTTP/1.1-only TLS server.
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("http1 backend"))
		}))
		srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
		srv.StartTLS()
		defer srv.Close()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				},
			},
		}

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "http1 backend", string(body))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("MatchUpstreamH2/H2", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("h2 ok"))
		}))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		defer srv.Close()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.MatchUpstreamH2 = true

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				},
			},
		}

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "h2 ok", string(body))
		assert.Equal(t, 2, resp.ProtoMajor,
			"client should negotiate h2 when upstream supports it, got %s", resp.Proto)
	})

	t.Run("MatchUpstreamH2/H1Only", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("h1 ok"))
		}))
		srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
		srv.StartTLS()
		defer srv.Close()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.MatchUpstreamH2 = true

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				},
			},
		}

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "h1 ok", string(body))
		assert.Equal(t, 1, resp.ProtoMajor,
			"client should get h1.1 when upstream only supports h1.1, got %s", resp.Proto)
	})

	t.Run("MatchUpstreamH2/UnreachableHost", func(t *testing.T) {
		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.MatchUpstreamH2 = true

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)

		conn, err := net.Dial("tcp", proxyURL.Host)
		require.NoError(t, err)
		defer conn.Close()

		connectReq, _ := http.NewRequestWithContext(context.Background(),
			http.MethodConnect, "http://127.0.0.1:19999", nil)
		connectReq.Host = "127.0.0.1:19999"
		require.NoError(t, connectReq.Write(conn))
		br := bufio.NewReader(conn)
		connectResp, err := http.ReadResponse(br, connectReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, connectResp.StatusCode)

		tlsConn := tls.Client(&h2ReadBufferedConn{Conn: conn, r: br}, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		require.NoError(t, tlsConn.HandshakeContext(context.Background()))

		// When the upstream is unreachable, the proxy should still offer h2
		// so the client can negotiate its preferred protocol for the error response.
		assert.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol,
			"proxy should offer h2 for unreachable upstream to deliver error in best protocol")
	})

	t.Run("MatchUpstreamH2/UnreachableHost/H1Client", func(t *testing.T) {
		// Verify that an HTTP/1.1-only client gets a proper 502 error
		// response (not an empty reply) when the upstream is unreachable.
		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.MatchUpstreamH2 = true

		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()

		proxyURL, _ := url.Parse(proxySrv.URL)

		conn, err := net.Dial("tcp", proxyURL.Host)
		require.NoError(t, err)
		defer conn.Close()

		connectReq, _ := http.NewRequestWithContext(context.Background(),
			http.MethodConnect, "http://127.0.0.1:19999", nil)
		connectReq.Host = "127.0.0.1:19999"
		require.NoError(t, connectReq.Write(conn))
		br := bufio.NewReader(conn)
		connectResp, err := http.ReadResponse(br, connectReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, connectResp.StatusCode)

		// HTTP/1.1-only client (no h2 in ALPN).
		tlsConn := tls.Client(&h2ReadBufferedConn{Conn: conn, r: br}, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
		require.NoError(t, tlsConn.HandshakeContext(context.Background()))
		assert.Equal(t, "http/1.1", tlsConn.ConnectionState().NegotiatedProtocol)

		// Send an HTTP/1.1 request through the tunnel.
		httpReq, _ := http.NewRequestWithContext(context.Background(),
			http.MethodGet, "https://127.0.0.1:19999/", nil)
		require.NoError(t, httpReq.Write(tlsConn))

		// Should get a 502 Bad Gateway, not an empty reply.
		tlsBr := bufio.NewReader(tlsConn)
		resp, err := http.ReadResponse(tlsBr, httpReq)
		require.NoError(t, err, "expected a valid HTTP response, not an empty reply")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})
}

// --- gRPC bidirectional streaming tests ---

func TestMITMGRPCBidirectionalStream(t *testing.T) {
	runBidiChat := func(t *testing.T, grpcConn *grpc.ClientConn, messages []string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client := pb.NewEchoClient(grpcConn)
		stream, err := client.BidiChat(ctx)
		require.NoError(t, err)

		for _, msg := range messages {
			require.NoError(t, stream.Send(&pb.ChatMessage{Value: msg}), "Send(%q)", msg)
			reply, err := stream.Recv()
			require.NoError(t, err, "Recv after %q", msg)
			assert.Equal(t, "echo:"+msg, reply.GetValue())
		}

		require.NoError(t, stream.CloseSend())
		_, err = stream.Recv()
		assert.ErrorIs(t, err, io.EOF, "stream should end after CloseSend")
	}

	t.Run("TLS", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		serverTLSCert, err := tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
		require.NoError(t, err)
		grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
		})))
		pb.RegisterEchoServer(grpcServer, &echoServer{})
		go grpcServer.Serve(lis)
		defer grpcServer.Stop()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxy.Tr = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}
		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()
		proxyURL, _ := url.Parse(proxySrv.URL)

		grpcConn, err := grpc.NewClient(
			lis.Addr().String(),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true,
			})),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return connectViaProxy(ctx, proxyURL.Host, addr)
			}),
		)
		require.NoError(t, err)
		defer grpcConn.Close()

		runBidiChat(t, grpcConn, []string{"hello", "goproxy", "bidirectional", "stream"})
	})

	t.Run("H2C", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		grpcServer := grpc.NewServer()
		pb.RegisterEchoServer(grpcServer, &echoServer{})
		go grpcServer.Serve(lis)
		defer grpcServer.Stop()

		proxy := goproxy.NewProxyHttpServer()
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		proxy.AllowHTTP2 = true
		proxySrv := httptest.NewServer(proxy)
		defer proxySrv.Close()
		proxyURL, _ := url.Parse(proxySrv.URL)

		grpcConn, err := grpc.NewClient(
			lis.Addr().String(),
			grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return connectViaProxy(ctx, proxyURL.Host, addr)
			}),
		)
		require.NoError(t, err)
		defer grpcConn.Close()

		runBidiChat(t, grpcConn, []string{"h2c", "plaintext", "bidirectional"})
	})
}
