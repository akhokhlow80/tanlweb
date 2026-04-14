package peers

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	NodeUUID      string
	OwnerUserUUID string
}

type WGQuickConfig struct {
	Interface struct {
		PrivateKey *string  `json:"private_key"`
		Addresses  []string `json:"addresses"`
		DNS        *string  `json:"dns"`
		MTU        *int     `json:"mtu"`
	} `json:"interface"`
	NodePeer struct {
		PublicKey           string  `json:"public_key"`
		PresharedKey        *string `json:"preshared_key"`
		Endpoint            string  `json:"endpoint"`
		PersistentKeepalive *int    `json:"persistent_keepalive"`
	} `json:"node_peer"`
}

func (conf *WGQuickConfig) String() {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	if conf.Interface.PrivateKey != nil {
		fmt.Fprintf(&sb, "PrivateKey = %s\n", *conf.Interface.PrivateKey)
	}
	fmt.Fprintf(&sb, "Address = %s\n", strings.Join(conf.Interface.Addresses, ", "))
	if conf.Interface.DNS != nil {
		fmt.Fprintf(&sb, "DNS = %s\n", *conf.Interface.DNS)
	}
	if conf.Interface.MTU != nil {
		fmt.Fprintf(&sb, "MTU = %d\n", *conf.Interface.MTU)
	}
	sb.WriteRune('\n')

	sb.WriteString("[Peer]")
	fmt.Fprintf(&sb, "PublicKey = %s\n", conf.NodePeer.PublicKey)
	if conf.NodePeer.PresharedKey != nil {
		fmt.Fprintf(&sb, "PresharedKey = %s\n", *conf.NodePeer.PresharedKey)
	}
	fmt.Fprintf(&sb, "Endpoint = %s\n", conf.NodePeer.Endpoint)
	if conf.NodePeer.PersistentKeepalive != nil {
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", *conf.NodePeer.PersistentKeepalive)
	}
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

type CreatePeerOnRemoteNodeHandler interface {
	CreatePeer(ctx context.Context, peer *CreatePeerRequest) (WGQuickConfig, error)
}

var ErrRequestCompleted = errors.New("Request is either successfuly completed or cancelled")

// Errors: ErrRequestCompleted
func (req *CreatePeerRequest) Complete(
	ctx context.Context,
	storage RequestStorage,
	createPeerOnNode CreatePeerOnRemoteNodeHandler,
) (WGQuickConfig, error) {
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
		return WGQuickConfig{}, err
	}

	config, err := createPeerOnNode.CreatePeer(ctx, req)
	if err != nil {
		return WGQuickConfig{}, err
	}

	err = storage.Update(ctx, req.UUID, func(ctx context.Context, updReq *CreatePeerRequest) error {
		updReq.Status = Created
		*req = *updReq
		return nil
	})
	if err != nil {
		return WGQuickConfig{}, err
	}

	// XXX: The situation in which client succedes to create a peer on the remote node, but the local DB
	// fails to update a status may lead to creation of a peer that could never connect to the node (due to
	// its private key being lost).
	// It is not a vulnerability, but a very rare bug.
	// I am not planning to fix it.

	return config, nil
}
