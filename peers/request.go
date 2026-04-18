package peers

import (
	"akhokhlow80/tanlweb/peerconfig"
	"context"
	"errors"
	"time"
)

type PeerRequestStatus int

const (
	Pending PeerRequestStatus = iota
	ConfigRequested
	Created
	Cancelled
)

type CreatePeerRequest struct {
	UUID   string
	Status PeerRequestStatus
	// Cleared after the peer was created.
	Sensitive struct {
		InterfaceName   string
		AddedAt         time.Time
		AddedByUserUUID string
	}
	Node  NodeUUID
	Owner UserUUID
}

var ErrCreatePeerRequestNotFound = errors.New("Create peer request was not found")

type RequestStorage interface {
	// Errors: ErrCreatePeerRequestNotFound
	Update(
		ctx context.Context,
		reqUUID string,
		updateFn func(ctx context.Context, req *CreatePeerRequest) error,
	) error
}

var ErrRequestCompleted = errors.New("Request is either successfuly completed or cancelled")

// Errors: ErrRequestCompleted
func (req *CreatePeerRequest) Complete(
	ctx context.Context,
	storage RequestStorage,
	nodeClient NodeClient,
) (peerconfig.WGQuick, Peer, error) {
	err := storage.Update(ctx, req.UUID, func(ctx context.Context, updReq *CreatePeerRequest) error {
		if updReq.Status != Pending {
			return ErrRequestCompleted
		}
		updReq.Sensitive.AddedAt = time.Time{}
		updReq.Sensitive.InterfaceName = ""
		updReq.Status = ConfigRequested
		*req = *updReq
		return nil
	})
	if err != nil {
		return peerconfig.WGQuick{}, Peer{}, err
	}

	config, peer, err := nodeClient.CreatePeer(ctx, req.Owner)
	if err != nil {
		return peerconfig.WGQuick{}, Peer{}, err
	}

	err = storage.Update(ctx, req.UUID, func(ctx context.Context, updReq *CreatePeerRequest) error {
		updReq.Status = Created
		*req = *updReq
		return nil
	})
	if err != nil {
		return peerconfig.WGQuick{}, Peer{}, err
	}

	// XXX: The situation in which client succedes to create a peer on the remote node, but the local DB
	// fails to update a status may lead to creation of a peer that could never connect to the node (due to
	// its private key being lost).
	// It is not a vulnerability, but a very rare bug.
	// I am not planning to fix it.

	return config, peer, nil
}
