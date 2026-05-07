package dnstap

import (
	"net"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestDecoder_Decode tests DNSTap message decoding.
func TestDecoder_Decode(t *testing.T) {
	decoder := NewDecoder()

	// Create a DNS query
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion("example.com.", dns.TypeA)
	queryData, err := dnsQuery.Pack()
	require.NoError(t, err)

	// Create a DNS response
	dnsResponse := new(dns.Msg)
	dnsResponse.SetReply(dnsQuery)
	dnsResponse.Rcode = dns.RcodeSuccess
	dnsResponse.AuthenticatedData = true
	dnsResponse.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"),
		},
	}
	responseData, err := dnsResponse.Pack()
	require.NoError(t, err)

	// Create DNSTap CLIENT_RESPONSE message
	queryTimeSec := uint64(time.Now().Unix())
	queryTimeNsec := uint32(0)
	responseTimeSec := queryTimeSec
	responseTimeNsec := uint32(5000000) // 5ms later
	socketProto := dnstap.SocketProtocol_UDP
	msgType := dnstap.Message_CLIENT_RESPONSE
	dnstapType := dnstap.Dnstap_MESSAGE

	clientIP := net.ParseIP("192.0.2.100")

	dt := &dnstap.Dnstap{
		Type: &dnstapType,
		Message: &dnstap.Message{
			Type:             &msgType,
			SocketProtocol:   &socketProto,
			QueryAddress:     clientIP,
			QueryMessage:     queryData,
			ResponseMessage:  responseData,
			QueryTimeSec:     &queryTimeSec,
			QueryTimeNsec:    &queryTimeNsec,
			ResponseTimeSec:  &responseTimeSec,
			ResponseTimeNsec: &responseTimeNsec,
		},
	}

	// Marshal to protobuf
	data, err := proto.Marshal(dt)
	require.NoError(t, err)

	// Decode
	query, err := decoder.Decode(data)
	require.NoError(t, err)
	require.NotNil(t, query)

	// Verify decoded data
	assert.Equal(t, "example.com.", query.QueryName)
	assert.Equal(t, uint16(dns.TypeA), query.QueryType)
	assert.Equal(t, uint16(dns.RcodeSuccess), query.ResponseCode)
	assert.Equal(t, "udp", query.Transport)
	assert.True(t, query.DNSSECValid)
	assert.True(t, query.IsResponse)
	assert.Equal(t, clientIP.String(), query.ClientIP.String())
	assert.InDelta(t, 5.0, query.Latency, 0.1) // 5ms +/- 0.1ms
}

// TestDecoder_DecodeClientQuery tests CLIENT_QUERY message type.
func TestDecoder_DecodeClientQuery(t *testing.T) {
	decoder := NewDecoder()

	// Create a DNS query
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion("test.org.", dns.TypeAAAA)
	queryData, err := dnsQuery.Pack()
	require.NoError(t, err)

	// Create DNSTap CLIENT_QUERY message
	queryTimeSec := uint64(time.Now().Unix())
	queryTimeNsec := uint32(0)
	socketProto := dnstap.SocketProtocol_TCP
	msgType := dnstap.Message_CLIENT_QUERY
	dnstapType := dnstap.Dnstap_MESSAGE

	clientIP := net.ParseIP("2001:db8::1")

	dt := &dnstap.Dnstap{
		Type: &dnstapType,
		Message: &dnstap.Message{
			Type:           &msgType,
			SocketProtocol: &socketProto,
			QueryAddress:   clientIP,
			QueryMessage:   queryData,
			QueryTimeSec:   &queryTimeSec,
			QueryTimeNsec:  &queryTimeNsec,
		},
	}

	// Marshal to protobuf
	data, err := proto.Marshal(dt)
	require.NoError(t, err)

	// Decode
	query, err := decoder.Decode(data)
	require.NoError(t, err)
	require.NotNil(t, query)

	// Verify decoded data
	assert.Equal(t, "test.org.", query.QueryName)
	assert.Equal(t, uint16(dns.TypeAAAA), query.QueryType)
	assert.Equal(t, "tcp", query.Transport)
	assert.Equal(t, clientIP.String(), query.ClientIP.String())
	assert.Equal(t, uint16(0), query.ResponseCode) // No response in CLIENT_QUERY
	assert.Equal(t, 0.0, query.Latency)            // No latency in CLIENT_QUERY
	assert.False(t, query.IsResponse)
}

// TestDecoder_DecodeInvalidProtobuf tests handling of invalid protobuf data.
func TestDecoder_DecodeInvalidProtobuf(t *testing.T) {
	decoder := NewDecoder()

	// Invalid protobuf data
	_, err := decoder.Decode([]byte("invalid data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

// TestDecoder_DecodeNonClientMessage tests skipping non-client messages.
func TestDecoder_DecodeNonClientMessage(t *testing.T) {
	decoder := NewDecoder()

	// Create DNSTap RESOLVER_QUERY message (not CLIENT_*)
	msgType := dnstap.Message_RESOLVER_QUERY
	dnstapType := dnstap.Dnstap_MESSAGE

	dt := &dnstap.Dnstap{
		Type: &dnstapType,
		Message: &dnstap.Message{
			Type: &msgType,
		},
	}

	// Marshal to protobuf
	data, err := proto.Marshal(dt)
	require.NoError(t, err)

	// Decode - should return nil without error (skip message)
	query, err := decoder.Decode(data)
	assert.NoError(t, err)
	assert.Nil(t, query)
}

// TestQueryTypeToString tests query type to string conversion.
func TestQueryTypeToString(t *testing.T) {
	testCases := []struct {
		qtype    uint16
		expected string
	}{
		{dns.TypeA, "A"},
		{dns.TypeAAAA, "AAAA"},
		{dns.TypeMX, "MX"},
		{dns.TypeTXT, "TXT"},
		{dns.TypeNS, "NS"},
		{dns.TypeSOA, "SOA"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := QueryTypeToString(tc.qtype)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestRCodeToString tests response code to string conversion.
func TestRCodeToString(t *testing.T) {
	testCases := []struct {
		rcode    uint16
		expected string
	}{
		{uint16(dns.RcodeSuccess), "NOERROR"},
		{uint16(dns.RcodeFormatError), "FORMERR"},
		{uint16(dns.RcodeServerFailure), "SERVFAIL"},
		{uint16(dns.RcodeNameError), "NXDOMAIN"},
		{uint16(dns.RcodeNotImplemented), "NOTIMP"},
		{uint16(dns.RcodeRefused), "REFUSED"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := RCodeToString(tc.rcode)
			assert.Equal(t, tc.expected, result)
		})
	}
}
