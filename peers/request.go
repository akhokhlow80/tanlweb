package peers

import (
	"context"
	"errors"
	"time"
)

type PeerRequestStatus string

const (
	Pending         PeerRequestStatus = "pending"
	ConfigRequested PeerRequestStatus = "config-requested"
	Created         PeerRequestStatus = "created"
	Cancelled       PeerRequestStatus = "cancelled"
)

func (status PeerRequestStatus) Completed() bool {
	return status == Created || status == Cancelled
}

type PeerRequest struct {
	UUID   string
	Status PeerRequestStatus
	// Cleared after the peer was created.
	Sensitive struct {
		InterfaceName       string
		RequestedAt         time.Time
		RequestedByUserUUID string
	}
	NodeUUID  string
	OwnerUUID string
}

var ErrPeerRequestNotFound = errors.New("Create peer request was not found")

type RequestUpdater interface {
	// Errors: ErrCreatePeerRequestNotFound
	Do(
		ctx context.Context,
		reqUUID string,
		updateFn func(ctx context.Context, req *PeerRequest) error,
	) error
}

type CreatePeerNodeClient interface {
	Do(ctx context.Context, owner string) (WGQuickConf, Peer, error)
}

var ErrRequestCompleted = errors.New("Request is either successfuly completed or cancelled")

// Errors: ErrRequestCompleted
func (req *PeerRequest) Complete(
	ctx context.Context,
	updateRequest RequestUpdater,
	createPeer CreatePeerNodeClient,
) (WGQuickConf, Peer, error) {
	err := updateRequest.Do(ctx, req.UUID, func(ctx context.Context, updReq *PeerRequest) error {
		if updReq.Status != Pending {
			return ErrRequestCompleted
		}
		updReq.Sensitive.RequestedAt = time.Time{}
		updReq.Sensitive.InterfaceName = ""
		updReq.Status = ConfigRequested
		*req = *updReq
		return nil
	})
	if err != nil {
		return WGQuickConf{}, Peer{}, err
	}

	config, peer, err := createPeer.Do(ctx, req.OwnerUUID)
	if err != nil {
		return WGQuickConf{}, Peer{}, err
	}

	err = updateRequest.Do(ctx, req.UUID, func(ctx context.Context, updReq *PeerRequest) error {
		updReq.Status = Created
		*req = *updReq
		return nil
	})
	if err != nil {
		return WGQuickConf{}, Peer{}, err
	}

	// XXX: The situation in which client succedes to create a peer on the remote node, but the local DB
	// fails to update a status may lead to creation of a peer that could never connect to the node (due to
	// its private key being lost).
	// It is not a vulnerability, but a very rare bug.
	// I am not planning to fix it.

	return config, peer, nil
}
