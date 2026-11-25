package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// selfSignedCertificate is a certificate for the name "doq.test", for a server the tests reach
// with verification off.
func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doq.test"},
		DNSNames:     []string{"doq.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509 create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{certificate}, PrivateKey: key}
}

// serveDoq serves DoQ on a loopback address until the test ends, answering each query with an
// empty reply when answer is set and never otherwise. Each connection's context is sent on
// connections as it is accepted; it is done once the connection is closed.
func serveDoq(t *testing.T, answer bool) (string, <-chan context.Context) {
	t.Helper()

	listener, err := quic.ListenAddr(
		"127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{selfSignedCertificate(t)}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
		&quic.Config{MaxIdleTimeout: 30 * time.Second},
	)
	if err != nil {
		t.Fatalf("quic listen addr: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	connections := make(chan context.Context, 8)
	go func() {
		for {
			connection, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			connections <- connection.Context()

			go func() {
				stream, err := connection.AcceptStream(context.Background())
				if err != nil {
					return
				}
				query, err := io.ReadAll(stream)
				if err != nil || len(query) < 2 || !answer {
					return
				}

				request := new(dns.Msg)
				if err := request.Unpack(query[2:]); err != nil {
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(request)
				packed, err := reply.Pack()
				if err != nil {
					return
				}
				_ = binary.Write(stream, binary.BigEndian, uint16(len(packed))) //nolint:gosec // A reply to one question.
				_, _ = stream.Write(packed)
				_ = stream.Close()
			}()
		}
	}()

	address := listener.Addr()
	if address == nil {
		t.Fatal("the listener has no address")
		return "", nil
	}

	return address.String(), connections
}

// An exchange ends when its context does, though the server keeps the connection alive and never
// answers, and its connection is closed once it is over, answered or not: the server sees it end.
func TestExchange_EndsWithItsContextAndClosesItsConnection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		answer  bool
		wantErr error
	}{
		{name: "an answered query", answer: true},
		{name: "a query never answered", answer: false, wantErr: context.DeadlineExceeded},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			address, connections := serveDoq(t, testCase.answer)

			message := new(dns.Msg)
			message.SetQuestion("example.com.", dns.TypeA)
			message.Id = 0

			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				_, err := Exchange(
					ctx,
					message,
					address,
					&tls.Config{NextProtos: []string{"doq"}, ServerName: "doq.test", InsecureSkipVerify: true}, //nolint:gosec // A test server's own certificate.
					&quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 2 * time.Second},
				)
				done <- err
			}()

			select {
			case err := <-done:
				if testCase.wantErr == nil && err != nil {
					t.Fatalf("exchange: %v", err)
				}
				if testCase.wantErr != nil && !errors.Is(err, testCase.wantErr) {
					t.Fatalf("exchange: got %v, want %v", err, testCase.wantErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the exchange outlived its context")
			}

			var connectionCtx context.Context
			select {
			case connectionCtx = <-connections:
			case <-time.After(time.Second):
				t.Fatal("the server saw no connection")
			}
			select {
			case <-connectionCtx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("the exchange left its connection open")
			}
		})
	}
}
