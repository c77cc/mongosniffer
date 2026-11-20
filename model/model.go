package model

import "time"

type Direction uint8

const (
	ClientToServer Direction = iota
	ServerToClient
)

type ConnectionMetadata struct {
	ClientAddress       string   `json:"client_address,omitempty"`
	ServerAddress       string   `json:"server_address,omitempty"`
	ApplicationName     string   `json:"application_name,omitempty"`
	DriverName          string   `json:"driver_name,omitempty"`
	DriverVersion       string   `json:"driver_version,omitempty"`
	OS                  string   `json:"os,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	LoadBalanced        bool     `json:"load_balanced,omitempty"`
	APIVersion          string   `json:"api_version,omitempty"`
	MaxWireVersion      int64    `json:"max_wire_version,omitempty"`
	MaxMessageSizeBytes int64    `json:"max_message_size_bytes,omitempty"`
	MaxBSONObjectSize   int64    `json:"max_bson_object_size,omitempty"`
	MaxWriteBatchSize   int64    `json:"max_write_batch_size,omitempty"`
	ServiceIDPresent    bool     `json:"service_id_present,omitempty"`
	CompressionOffered  []string `json:"compression_offered,omitempty"`
	CompressionAccepted []string `json:"compression_accepted,omitempty"`
	HandshakeObserved   bool     `json:"handshake_observed"`
	Midstream           bool     `json:"midstream,omitempty"`
}

type ResultSummary struct {
	ReturnedDocuments  int64           `json:"returned_documents,omitempty"`
	AffectedDocuments  int64           `json:"affected_documents,omitempty"`
	ModifiedDocuments  int64           `json:"modified_documents,omitempty"`
	Upserts            int64           `json:"upserts,omitempty"`
	WriteErrors        int64           `json:"write_errors,omitempty"`
	WriteConcernErrors int64           `json:"write_concern_errors,omitempty"`
	ResponseBytes      int64           `json:"response_protocol_bytes,omitempty"`
	Error              bool            `json:"error,omitempty"`
	ErrorCode          int64           `json:"error_code,omitempty"`
	ErrorCodeName      string          `json:"error_code_name,omitempty"`
	WriteErrorCodes    map[int64]int64 `json:"-"`
	WriteConcernCodes  map[int64]int64 `json:"-"`
	ErrorLabels        []string        `json:"-"`
	PartialResults     bool            `json:"partial_results_returned,omitempty"`
	CursorID           int64           `json:"-"`
	CursorNamespace    string          `json:"-"`
	CursorNonZero      bool            `json:"cursor_non_zero,omitempty"`
}

type OperationEvent struct {
	Command, Database, Collection string
	Fingerprint, FingerprintID    string
	FingerprintKey                string
	RawCommand                    string
	FingerprintTruncated          bool
	StartedAt, FinishedAt         time.Time
	FirstResponseAt               time.Time
	Duration, FirstResponse       time.Duration
	ResponseTransfer              time.Duration
	Acknowledged, Incomplete      bool
	IncompleteReason              string
	Transactional, RetryableWrite bool
	CursorKind                    string
	RequestBytes                  int64
	Compression                   string
	Metadata                      ConnectionMetadata
	Result                        ResultSummary
}

type CaptureStats struct {
	PacketsSeen                  uint64 `json:"packets_seen"`
	PacketsMatched               uint64 `json:"packets_matched"`
	BytesCaptured                uint64 `json:"bytes_captured"`
	TruncatedPackets             uint64 `json:"truncated_packets"`
	KernelPacketsDropped         uint64 `json:"kernel_packets_dropped"`
	InterfacePacketsDropped      uint64 `json:"interface_packets_dropped"`
	TCPGapEvents                 uint64 `json:"tcp_gap_events"`
	TCPBytesSkipped              uint64 `json:"tcp_bytes_skipped"`
	TCPSequenceDiscontinuities   uint64 `json:"tcp_sequence_discontinuities"`
	ConnectionsObserved          uint64 `json:"connections_observed"`
	HandshakeObservedConnections uint64 `json:"handshake_observed_connections"`
	MidstreamConnections         uint64 `json:"midstream_connections"`
	ProtocolStateLossConnections uint64 `json:"protocol_state_loss_connections"`
}
