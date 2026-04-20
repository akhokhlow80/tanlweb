package nodes

import (
	"akhokhlow80/tanlweb/peers"
	"context"
	"fmt"
	"strings"
	"sync"
)

type MultiClient struct {
	sync.RWMutex
	clients map[string]*Client
}

func (mc *MultiClient) AddNode(uuid string, client *Client) {
	defer mc.Unlock()
	mc.Lock()
	mc.clients[uuid] = client
}

func (mc *MultiClient) GetClient(nodeUUID string) *Client {
	defer mc.RUnlock()
	mc.RLock()
	return mc.clients[nodeUUID]
}

type MultiError struct {
	msg     string
	wrapped []error
}

func (err *MultiError) Error() string {
	return err.msg
}

func (err *MultiError) Unwrap() []error {
	return err.wrapped
}

type ErrorsByNode map[string]error

func (errs ErrorsByNode) Ok() bool {
	return len(errs) == 0
}

func (errs ErrorsByNode) Error() error {
	if errs.Ok() {
		return nil
	}

	var (
		wrapped = make([]error, 0, len(errs))
		sb      strings.Builder
		i       int
	)
	sb.WriteString("Errors occurred while making requests to nodes: ")
	for nodeUUID, err := range errs {
		wrapped = append(wrapped, err)

		fmt.Fprintf(&sb, "node %s: %s", nodeUUID, err)
		if i != len(errs)-1 {
			sb.WriteString(", ")
		}

		i++
	}
	return &MultiError{
		msg:     sb.String(),
		wrapped: wrapped,
	}
}

func runParallelRequests[R any](
	ctx context.Context,
	mc *MultiClient,
	req func(ctx context.Context, client *Client) (R, error),
) ([]R, ErrorsByNode) {
	resultChs := make([]<-chan R, 0, len(mc.clients))
	errChs := make([]<-chan struct {
		nodeUUID string
		err      error
	}, 0, len(mc.clients))

	func() {
		defer mc.RUnlock()
		mc.RLock()
		for _, client := range mc.clients {
			resultCh := make(chan R)
			errCh := make(chan error)
			go func() {
				r, err := req(ctx, client)
				if err != nil {
					errCh <- err
				} else {
					resultCh <- r
				}
			}()
		}
	}()

	rs := make([]R, 0, len(mc.clients))
	errs := ErrorsByNode(make(map[string]error, 0))
	for i := range len(mc.clients) {
		select {
		case r := <-resultChs[i]:
			rs = append(rs, r)
		case err := <-errChs[i]:
			errs[err.nodeUUID] = err.err
		}
	}
	return rs, errs
}

func (mc *MultiClient) getPeersByOwner(ctx context.Context, owner string) ([]peers.Peer, ErrorsByNode) {
	result, errs := runParallelRequests(ctx, mc, func(ctx context.Context, client *Client) ([]peers.Peer, error) {
		return client.getPeersByOwner(ctx, owner)
	})
	var merged []peers.Peer
	for _, result := range result {
		merged = append(merged, result...)
	}
	return merged, errs
}

// Owner is optional; calling with empty will result in return of all peers from the node.
// Result may be partially succesful.
func (mc *MultiClient) GetPeers(ctx context.Context) ([]peers.Peer, ErrorsByNode) {
	return mc.getPeersByOwner(ctx, "")
}

// Returns nil peer if not found
// Result may be partially succesful.
func (mc *MultiClient) GetPeer(ctx context.Context, pubkey string) (*peers.Peer, ErrorsByNode) {
	results, err := runParallelRequests(ctx, mc, func(ctx context.Context, client *Client) (*peers.Peer, error) {
		return client.GetPeer(ctx, pubkey)
	})
	for _, peer := range results {
		if peer != nil {
			return peer, err
		}
	}
	return nil, err
}

// Result may be partially succesful.
func (mc *MultiClient) GetUserPeers(ctx context.Context, userUUID string) ([]peers.Peer, ErrorsByNode) {
	return mc.getPeersByOwner(ctx, userUUID)
}
