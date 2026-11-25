package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"time"

	dnsUtilsContext "github.com/altshiftab/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/altshiftab/dns_utils/pkg/errors"
	dnsUtilsQuicErrors "github.com/altshiftab/dns_utils/pkg/quic/errors"
	dnsUtilsTypes "github.com/altshiftab/dns_utils/pkg/types"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// doqNoError is DoQ's DOQ_NO_ERROR (RFC 9250, section 4.3), closing a connection with nothing
// to signal.
const doqNoError quic.ApplicationErrorCode = 0x0

// Exchange sends message to the DoQ server at serverAddress over a connection of its own, and
// returns the answer. The exchange ends when ctx does, and its connection is closed with it.
func Exchange(
	ctx context.Context,
	message *dns.Msg,
	serverAddress string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*dns.Msg, error) {
	if message == nil {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	dnsContext.QuestionMessage = message
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if serverAddress == "" {
		return nil, altshiftErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{NextProtos: []string{"doq"}}
	}

	messageBytes, err := message.Pack()
	if err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("request pack: %w", err))
	}

	connection, err := quic.DialAddr(ctx, serverAddress, tlsConfig, quicConfig)
	if err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("quic dial addr: %w", err))
	}

	// The connection is this exchange's alone, and is closed with it: left open, its keep-alives
	// would hold it, its socket and its goroutines until the server ended it. Closing it when ctx
	// ends is also what ends the stream's reads and writes, which take no context: a server that
	// keeps the connection alive but never answers would otherwise hold the exchange past ctx.
	defer func() { _ = connection.CloseWithError(doqNoError, "") }()
	stopClosing := context.AfterFunc(ctx, func() { _ = connection.CloseWithError(doqNoError, "") })
	defer stopClosing()

	// streamError is err from a stream operation, or ctx's error where ctx ending was what failed it.
	streamError := func(err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}

	var localAddrString string
	if localAddr := connection.LocalAddr(); localAddr != nil {
		localAddrString = localAddr.String()
	}

	var remoteAddrString string
	var transport string
	if remoteAddr := connection.RemoteAddr(); remoteAddr != nil {
		remoteAddrString = remoteAddr.String()
		transport = remoteAddr.Network()
	}

	dnsContext.ClientAddress = localAddrString
	dnsContext.ServerAddress = remoteAddrString
	dnsContext.Transport = transport

	// TODO: Not sure if I can obtain TLS information? Maybe if I call something other than `quic.DialAddr`?

	closeStreamInDefer := true
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("connection open stream sync: %w", streamError(err)),
		)
	}
	defer func() {
		if closeStreamInDefer {
			if err := stream.Close(); err != nil {
				slog.WarnContext(
					altshiftContext.WithError(
						ctx,
						altshiftErrors.NewWithTrace(fmt.Errorf("stream close: %w", err)),
					),
					"An error occurred when closing a stream.",
				)
			}
		}
	}()

	rawMessageLength := len(messageBytes)
	if rawMessageLength > 0xFFFF {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("%w (%d)", dnsUtilsQuicErrors.ErrMessageLengthOverflow, rawMessageLength),
		)
	}
	messageLength := uint16(rawMessageLength)

	if err := binary.Write(stream, binary.BigEndian, messageLength); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("binary write (message length): %w", streamError(err)),
		)
	}
	if _, err := stream.Write(messageBytes); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("binary write (message bytes): %w", streamError(err)),
		)
	}

	if err := stream.Close(); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("stream close: %w", streamError(err)))
	}
	closeStreamInDefer = false

	var responseLength uint16
	if err := binary.Read(stream, binary.BigEndian, &responseLength); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("binary read (response length): %w", streamError(err)),
		)
	}

	responseBuffer := make([]byte, responseLength)
	if _, err := io.ReadFull(stream, responseBuffer); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("io read full (response): %w", streamError(err)),
		)
	}

	var response dns.Msg
	if err := response.Unpack(responseBuffer); err != nil {
		return nil, altshiftErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("response unpack: %w", err))
	}

	// TODO: Maybe I can obtain an earlier time?
	t := time.Now()
	dnsContext.Time = &t
	dnsContext.AnswerMessage = &response

	if response.Rcode != dns.RcodeSuccess {
		return &response, altshiftErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			&dnsUtilsErrors.RcodeError{Rcode: response.Rcode},
		)
	}

	return &response, nil
}
