package peers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"
)

type PeerRequestStatus string

const (
	Pending PeerRequestStatus = "pending"
	// In rare cases requests may remain in this state forever.
	ConfigRequested PeerRequestStatus = "config-requested"
	Created         PeerRequestStatus = "created"
	Cancelled       PeerRequestStatus = "cancelled"
	Failed          PeerRequestStatus = "failed"
)

func ParsePeerRequestStatus(s string) (PeerRequestStatus, error) {
	switch s {
	case string(Pending):
		fallthrough
	case string(ConfigRequested):
		fallthrough
	case string(Created):
		fallthrough
	case string(Failed):
		fallthrough
	case string(Cancelled):
		return PeerRequestStatus(s), nil
	default:
		return Pending, fmt.Errorf("Peer request has invalid status %s", s)
	}
}

func (status PeerRequestStatus) Completed() bool {
	return status == Created || status == Failed || status == Cancelled
}

type PeerRequest struct {
	RandomID string
	Status   PeerRequestStatus
	// Cleared after the peer was created.
	Sensitive struct {
		InterfaceName       string
		RequestedAt         time.Time
		RequestedByUserUUID string
	}
	NodeUUID  string
	OwnerUUID string
}

var (
	InterfaceNameRegexp     = regexp.MustCompile(`[a-zA-Z0-9_=+.-]{1,15}`)
	ErrInvalidInterfaceName = errors.New("Invalid interface name")
)

// Errors: ErrInvalidInterfaceName
func NewPeerRequest(
	InterfaceName string,
	RequestedByUserUUID string,
	NodeUUID string,
	OwnerUUID string,
) (PeerRequest, error) {
	if !InterfaceNameRegexp.MatchString(InterfaceName) {
		return PeerRequest{}, ErrInvalidInterfaceName
	}
	var randomIDBytes [32]byte
	if _, err := rand.Read(randomIDBytes[:]); err != nil {
		panic(err)
	}
	var req PeerRequest
	req.RandomID = base64.RawURLEncoding.EncodeToString(randomIDBytes[:])
	req.Status = Pending
	req.Sensitive.InterfaceName = InterfaceName
	req.Sensitive.RequestedAt = time.Now()
	req.Sensitive.RequestedByUserUUID = RequestedByUserUUID
	req.NodeUUID = NodeUUID
	req.OwnerUUID = OwnerUUID
	return req, nil
}

var ErrRequestNotFound = errors.New("Peer request was not found")

// Errors: ErrRequestNotFound
type UpdateRequestInRepo = func(
	ctx context.Context,
	randID string,
	updateFn func(ctx context.Context, req *PeerRequest) error,
) (PeerRequest, error)

type CreatePeerOnNode = func(
	ctx context.Context,
	owner string,
) (WGQuickConf, Peer, error)

var ErrRequestIsNotPending = errors.New("Request is not in the pending state")

func (req *PeerRequest) zeroOutSensitive() {
	req.Sensitive.InterfaceName = ""
	req.Sensitive.RequestedAt = time.Time{}
	req.Sensitive.RequestedByUserUUID = ""
}

// Errors: ErrRequestIsNotPending, ErrRequestNotFound
func (req *PeerRequest) Complete(
	ctx context.Context,
	updateRequest UpdateRequestInRepo,
	createPeer CreatePeerOnNode,
) (conf WGQuickConf, peer Peer, interfaceName string, err error) {
	// Mark request as being processed.
	*req, err = updateRequest(ctx, req.RandomID, func(ctx context.Context, updReq *PeerRequest) error {
		if updReq.Status != Pending {
			return ErrRequestIsNotPending
		}
		interfaceName = updReq.Sensitive.InterfaceName
		updReq.zeroOutSensitive()
		updReq.Status = ConfigRequested
		return nil
	})
	if err != nil {
		return WGQuickConf{}, Peer{}, "", err
	}

	// Do the job
	config, peer, err := createPeer(ctx, req.OwnerUUID)
	if err != nil {
		// Set the failed status
		var updErr error
		*req, updErr = updateRequest(ctx, req.RandomID, func(ctx context.Context, updReq *PeerRequest) error {
			updReq.Status = Failed
			return nil
		})
		if updErr != nil {
			return WGQuickConf{},
				Peer{},
				"",
				fmt.Errorf("Error %s while setting `failed` status to the request due to error %s", err, updErr)
		}
		return WGQuickConf{}, Peer{}, "", err
	}

	// Success
	*req, err = updateRequest(ctx, req.RandomID, func(ctx context.Context, updReq *PeerRequest) error {
		updReq.Status = Created
		return nil
	})
	if err != nil {
		return WGQuickConf{}, Peer{}, "", err
	}

	// XXX: The situation in which client succedes to create a peer on the remote node, but the local DB
	// fails to update a status may lead to creation of a peer that could never connect to the node (due to
	// its private key being lost).
	// Such request will remain in the status "config-requested" forever.
	// It is not a vulnerability, but a very rare bug.
	// I am not planning to fix it.

	return config, peer, interfaceName, nil
}

// Errors: ErrRequestIsNotPending, ErrRequestNotFound
func (req *PeerRequest) Cancel(ctx context.Context, updateRequest UpdateRequestInRepo) error {
	var err error
	*req, err = updateRequest(ctx, req.RandomID, func(ctx context.Context, updReq *PeerRequest) error {
		if updReq.Status != Pending {
			return ErrRequestIsNotPending
		}
		updReq.zeroOutSensitive()
		updReq.Status = Cancelled
		return nil
	})
	return err
}
