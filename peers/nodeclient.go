package peers

import (
	"akhokhlow80/tanlweb/peerconfig"
	"context"
)

type NodeClient interface {
	GetPeers(ctx context.Context) ([]Peer, error)
	CreatePeer(ctx context.Context, Owner UserUUID) (peerconfig.WGQuick, Peer, error)
}
