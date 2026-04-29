package dnstap

import (
	"fmt"
	"net"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// Query represents a parsed DNS query from DNSTap.
type Query struct {
	Timestamp    time.Time
	ClientIP     net.IP
	QueryType    uint16
	QueryName    string
	ResponseCode uint16
	Transport    string  // "tcp" or "udp"
	Latency      float64 // milliseconds
	DNSSECValid  bool
}

// Decoder decodes DNSTap protobuf messages.
type Decoder struct{}

// NewDecoder creates a new DNSTap decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode decodes a DNSTap frame into a Query.
func (d *Decoder) Decode(frameData []byte) (*Query, error) {
	// Parse DNSTap protobuf message
	var dt dnstap.Dnstap
	if err := proto.Unmarshal(frameData, &dt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal dnstap message: %w", err)
	}

	// Only process MESSAGE type
	if dt.Type == nil || *dt.Type != dnstap.Dnstap_MESSAGE {
		return nil, fmt.Errorf("unsupported dnstap type: %v", dt.Type)
	}

	msg := dt.Message
	if msg == nil {
		return nil, fmt.Errorf("dnstap message is nil")
	}

	// Only process CLIENT_QUERY and CLIENT_RESPONSE
	if msg.Type == nil {
		return nil, fmt.Errorf("dnstap message type is nil")
	}

	msgType := *msg.Type
	if msgType != dnstap.Message_CLIENT_QUERY && msgType != dnstap.Message_CLIENT_RESPONSE {
		// Skip non-client messages (e.g., resolver queries, forwarder messages)
		return nil, nil
	}

	// Extract query details
	query := &Query{}

	// Timestamp
	if msg.QueryTimeSec != nil && msg.QueryTimeNsec != nil {
		query.Timestamp = time.Unix(int64(*msg.QueryTimeSec), int64(*msg.QueryTimeNsec))
	} else if msg.ResponseTimeSec != nil && msg.ResponseTimeNsec != nil {
		query.Timestamp = time.Unix(int64(*msg.ResponseTimeSec), int64(*msg.ResponseTimeNsec))
	} else {
		query.Timestamp = time.Now()
	}

	// Client IP
	if msg.QueryAddress != nil {
		query.ClientIP = net.IP(msg.QueryAddress)
	}

	// Transport
	if msg.SocketProtocol != nil {
		switch *msg.SocketProtocol {
		case dnstap.SocketProtocol_UDP:
			query.Transport = "udp"
		case dnstap.SocketProtocol_TCP:
			query.Transport = "tcp"
		default:
			query.Transport = "unknown"
		}
	}

	// Parse DNS message
	if msgType == dnstap.Message_CLIENT_QUERY && msg.QueryMessage != nil {
		if err := d.parseQueryMessage(msg.QueryMessage, query); err != nil {
			return nil, fmt.Errorf("failed to parse query message: %w", err)
		}
	}

	// Parse DNS response for response code and latency
	if msgType == dnstap.Message_CLIENT_RESPONSE && msg.ResponseMessage != nil {
		if err := d.parseResponseMessage(msg.ResponseMessage, query); err != nil {
			return nil, fmt.Errorf("failed to parse response message: %w", err)
		}

		// Calculate latency
		if msg.QueryTimeSec != nil && msg.QueryTimeNsec != nil &&
			msg.ResponseTimeSec != nil && msg.ResponseTimeNsec != nil {
			queryTime := time.Unix(int64(*msg.QueryTimeSec), int64(*msg.QueryTimeNsec))
			responseTime := time.Unix(int64(*msg.ResponseTimeSec), int64(*msg.ResponseTimeNsec))
			query.Latency = float64(responseTime.Sub(queryTime).Microseconds()) / 1000.0
		}
	}

	return query, nil
}

// parseQueryMessage parses a DNS query message.
func (d *Decoder) parseQueryMessage(data []byte, query *Query) error {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	// Extract query type and name from first question
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		query.QueryType = q.Qtype
		query.QueryName = q.Name
	}

	return nil
}

// parseResponseMessage parses a DNS response message.
func (d *Decoder) parseResponseMessage(data []byte, query *Query) error {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	// Extract response code
	query.ResponseCode = uint16(msg.Rcode)

	// Extract query details from question section (if query details not set)
	if len(msg.Question) > 0 && query.QueryName == "" {
		q := msg.Question[0]
		query.QueryType = q.Qtype
		query.QueryName = q.Name
	}

	// Check DNSSEC validation (AD bit)
	query.DNSSECValid = msg.AuthenticatedData

	return nil
}

// QueryTypeToString converts DNS query type to string.
func QueryTypeToString(qtype uint16) string {
	return dns.TypeToString[qtype]
}

// RCodeToString converts DNS response code to string.
func RCodeToString(rcode uint16) string {
	return dns.RcodeToString[int(rcode)]
}
