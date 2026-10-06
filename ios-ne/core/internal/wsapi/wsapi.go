package wsapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Client sends data to WebSocket connections via the YC management API.
type Client interface {
	Send(connectionID string, data []byte, dataType string, iamToken string) error
	Disconnect(connectionID string, iamToken string) error
}

// NewClient creates a gRPC client (only gRPC supported in v4).
func NewClient() Client {
	return &grpcClient{}
}

// IsConnectionNotFound reports whether err indicates the target WebSocket
// connection is definitively gone (the API answered NOT_FOUND). Transient
// failures — timeouts (DeadlineExceeded), rate limiting (ResourceExhausted),
// server errors (Internal/Unavailable) — return false so callers do NOT discard
// a peer ID that is still valid and will likely work on the next attempt.
func IsConnectionNotFound(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.NotFound
}

