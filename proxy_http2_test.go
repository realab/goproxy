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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestMITMResponseHTTP2MissingContentLength(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			// Force missing Content-Length
			f.Flush()
		}
		_, _ = w.Write([]byte("HTTP/2 response"))
	})

	// Explicitly make an HTTP/2 server
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// proxy server
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Connection between the proxy client and the proxy server
		assert.Equal(t, "HTTP/1.1", req.Proto)
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// Connection between the proxy server and the origin
		assert.Equal(t, "HTTP/2.0", resp.Proto)
		return resp
	})

	// Configure proxy transport to use HTTP/2 to communicate with the server
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
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
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
	// Upstream HTTP/2 server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// Proxy with MITM and HTTP/2 upstream transport
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

	// Client talks HTTP/1.1 through the MITM proxy
	proxyURL, _ := url.Parse(proxySrv.URL)
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer conn.Close()

	// Send CONNECT
	connectReq, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, srv.URL, nil)
	require.NoError(t, connectReq.Write(conn))
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	// TLS handshake with the MITM'd proxy
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(context.Background()))

	// Send an HTTP/1.1 request through the tunnel
	httpReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/test", nil)
	require.NoError(t, httpReq.Write(tlsConn))

	// Read response — must be HTTP/1.x, not HTTP/2.0
	tlsBr := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(tlsBr, httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "hello", string(body))
	assert.Equal(t, 1, resp.ProtoMajor,
		"MITM'd client should receive HTTP/1.x response, got %s", resp.Proto)
}

// TestMITMClientHTTP2Negotiation verifies that when a client supports HTTP/2
// via TLS ALPN and the remote server also supports HTTP/2, the MITM proxy
// should negotiate HTTP/2 with the client (not downgrade to HTTP/1.1).
func TestMITMClientHTTP2Negotiation(t *testing.T) {
	// Remote server that supports HTTP/2
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("h2 response"))
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// Proxy with MITM and HTTP/2 enabled
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

	// Client that supports both HTTP/2 and HTTP/1.1 via TLS ALPN
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

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "h2 response", string(body))

	// The client should have negotiated HTTP/2 with the MITM proxy,
	// not been downgraded to HTTP/1.1.
	assert.Equal(t, 2, resp.ProtoMajor,
		"Client supporting HTTP/2 through MITM proxy should get HTTP/2, got %s", resp.Proto)
}

type echoService interface{}

// echoServiceDesc defines a gRPC service with a single bidirectional streaming
// method, registered manually so we don't need protoc-generated code.
var echoServiceDesc = grpc.ServiceDesc{
	ServiceName: "echo.Echo",
	HandlerType: (*echoService)(nil),
	Streams: []grpc.StreamDesc{
		{
			StreamName:   "BidiChat",
			Handler:      bidiChatHandler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

type echoServer struct{}

// bidiChatHandler receives StringValue messages and echoes them back with an
// "echo:" prefix. The stream ends when the client closes its send side.
func bidiChatHandler(_ any, stream grpc.ServerStream) error {
	for {
		var msg wrapperspb.StringValue
		if err := stream.RecvMsg(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		reply := &wrapperspb.StringValue{Value: "echo:" + msg.GetValue()}
		if err := stream.SendMsg(reply); err != nil {
			return err
		}
	}
}

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
	// The bufio.Reader may have buffered bytes beyond the HTTP response;
	// wrap so that TLS reads from the buffer first.
	return &h2ReadBufferedConn{Conn: conn, r: br}, nil
}

// h2ReadBufferedConn wraps a net.Conn with a buffered reader, identical to the
// unexported type in https.go.
type h2ReadBufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *h2ReadBufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// TestMITMGRPCBidirectionalStream verifies that a gRPC bidirectional streaming
// RPC works end-to-end through the MITM proxy over HTTP/2.
func TestMITMGRPCBidirectionalStream(t *testing.T) {
	// --- gRPC server (TLS, HTTP/2) ---
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverTLSCert, err := tls.X509KeyPair(goproxy.CA_CERT, goproxy.CA_KEY)
	require.NoError(t, err)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	})))
	grpcServer.RegisterService(&echoServiceDesc, &echoServer{})
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	// --- MITM proxy ---
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.AllowHTTP2 = true
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)

	// --- gRPC client through the proxy ---
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

	// Open bidirectional stream.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streamDesc := &grpc.StreamDesc{
		StreamName:   "BidiChat",
		ServerStreams: true,
		ClientStreams: true,
	}
	stream, err := grpcConn.NewStream(ctx, streamDesc, "/echo.Echo/BidiChat")
	require.NoError(t, err)

	// Send several messages and read back echoes.
	messages := []string{"hello", "goproxy", "bidirectional", "stream"}
	for _, msg := range messages {
		err := stream.SendMsg(&wrapperspb.StringValue{Value: msg})
		require.NoError(t, err, "SendMsg(%q)", msg)

		var reply wrapperspb.StringValue
		err = stream.RecvMsg(&reply)
		require.NoError(t, err, "RecvMsg after %q", msg)
		assert.Equal(t, "echo:"+msg, reply.GetValue())
	}

	// Close the send side and verify the server also finishes.
	require.NoError(t, stream.CloseSend())
	var trailing wrapperspb.StringValue
	err = stream.RecvMsg(&trailing)
	assert.ErrorIs(t, err, io.EOF, "stream should end after CloseSend")
}

// TestMITMH2CGRPCBidirectionalStream verifies that gRPC bidirectional streaming
// works through the MITM proxy over h2c (HTTP/2 cleartext, no TLS).
func TestMITMH2CGRPCBidirectionalStream(t *testing.T) {
	// --- gRPC server (plaintext h2c) ---
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	grpcServer.RegisterService(&echoServiceDesc, &echoServer{})
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	// --- MITM proxy (ConnectHTTPMitm for plaintext interception) ---
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.AllowHTTP2 = true
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)

	// --- gRPC client through the proxy (h2c, no TLS) ---
	grpcConn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return connectViaProxy(ctx, proxyURL.Host, addr)
		}),
	)
	require.NoError(t, err)
	defer grpcConn.Close()

	// Open bidirectional stream.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streamDesc := &grpc.StreamDesc{
		StreamName:   "BidiChat",
		ServerStreams: true,
		ClientStreams: true,
	}
	stream, err := grpcConn.NewStream(ctx, streamDesc, "/echo.Echo/BidiChat")
	require.NoError(t, err)

	// Send several messages and read back echoes.
	messages := []string{"h2c", "plaintext", "bidirectional"}
	for _, msg := range messages {
		err := stream.SendMsg(&wrapperspb.StringValue{Value: msg})
		require.NoError(t, err, "SendMsg(%q)", msg)

		var reply wrapperspb.StringValue
		err = stream.RecvMsg(&reply)
		require.NoError(t, err, "RecvMsg after %q", msg)
		assert.Equal(t, "echo:"+msg, reply.GetValue())
	}

	// Close the send side and verify the server also finishes.
	require.NoError(t, stream.CloseSend())
	var trailing wrapperspb.StringValue
	err = stream.RecvMsg(&trailing)
	assert.ErrorIs(t, err, io.EOF, "stream should end after CloseSend")
}
