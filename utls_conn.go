package goproxy

import (
	"context"
	"crypto/tls"
	"net"

	utls "github.com/refraction-networking/utls"
)

// negotiatedProtocol returns the ALPN protocol negotiated on a TLS connection.
// Works with both standard *tls.Conn and *utls.UConn.
func negotiatedProtocol(conn net.Conn) string {
	switch c := conn.(type) {
	case *tls.Conn:
		return c.ConnectionState().NegotiatedProtocol
	case *utls.UConn:
		return c.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}

// utlsHandshake performs a TLS handshake using utls with the given
// ClientHelloID. It converts the standard tls.Config to a utls.Config,
// performs the handshake, and returns the established connection.
func utlsHandshake(ctx context.Context, conn net.Conn, tlsCfg *tls.Config, helloID utls.ClientHelloID) (net.Conn, error) {
	uCfg := &utls.Config{
		ServerName:         tlsCfg.ServerName,
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		NextProtos:         tlsCfg.NextProtos,
		RootCAs:            tlsCfg.RootCAs,
		MinVersion:         tlsCfg.MinVersion,
		MaxVersion:         tlsCfg.MaxVersion,
	}

	uConn := utls.UClient(conn, uCfg, helloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uConn, nil
}

// utlsDialTLSContext returns a DialTLSContext function that performs TCP
// dialing followed by a utls TLS handshake using the given ClientHelloID.
// The baseCfg provides TLS settings (ServerName, InsecureSkipVerify, etc.).
// If dialCtxFn is non-nil it is used for the TCP dial; otherwise net.Dialer is used.
func utlsDialTLSContext(
	helloID utls.ClientHelloID,
	baseCfg *tls.Config,
	dialCtxFn func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if dialCtxFn != nil {
			rawConn, err = dialCtxFn(ctx, network, addr)
		} else {
			var d net.Dialer
			rawConn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}

		cfg := baseCfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = stripPort(addr)
		}

		tlsConn, err := utlsHandshake(ctx, rawConn, cfg, helloID)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}
