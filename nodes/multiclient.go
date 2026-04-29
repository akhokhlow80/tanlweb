package nodes

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type MultiClient struct {
	sync.RWMutex
	clients map[string]*Client
}

func NewMultiClient() *MultiClient {
	return &MultiClient{
		clients: make(map[string]*Client),
	}
}

func (mc *MultiClient) Put(client *Client) {
	defer mc.Unlock()
	mc.Lock()
	mc.clients[client.Node.UUID] = client
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

type ErrorsByNode struct {
	errors map[string]error
	error  error // the error that wraps all nodes' errors
}

func newErrorsByNode(errors map[string]error) ErrorsByNode {
	if len(errors) == 0 {
		return ErrorsByNode{
			errors: nil,
			error:  nil,
		}
	}
	var (
		wrapped = make([]error, 0, len(errors))
		sb      strings.Builder
		i       int
	)
	sb.WriteString("Errors occurred while making requests to nodes: ")
	for nodeUUID, err := range errors {
		wrapped = append(wrapped, err)

		fmt.Fprintf(&sb, "node %s: %s", nodeUUID, err)
		if i != len(errors)-1 {
			sb.WriteString(", ")
		}

		i++
	}
	return ErrorsByNode{
		errors: errors,
		error: &MultiError{
			msg:     sb.String(),
			wrapped: wrapped,
		},
	}
}

func (errs ErrorsByNode) Ok() bool {
	return errs.error == nil
}

func (errs ErrorsByNode) Error() error {
	return errs.error
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
			errCh := make(chan struct {
				nodeUUID string
				err      error
			})
			resultChs = append(resultChs, resultCh)
			errChs = append(errChs, errCh)
			go func() {
				r, err := req(ctx, client)
				if err != nil {
					errCh <- struct {
						nodeUUID string
						err      error
					}{client.Node.UUID, err}
				} else {
					resultCh <- r
				}
			}()
		}
	}()

	rs := make([]R, 0, len(mc.clients))
	errorsByNode := make(map[string]error, 0)
	for i := range len(mc.clients) {
		select {
		case r := <-resultChs[i]:
			rs = append(rs, r)
		case err := <-errChs[i]:
			errorsByNode[err.nodeUUID] = err.err
		}
	}
	return rs, newErrorsByNode(errorsByNode)
}

func (mc *MultiClient) getPeersByOwner(ctx context.Context, owner string) ([]PeerFromNode, ErrorsByNode) {
	result, errs := runParallelRequests(ctx, mc, func(ctx context.Context, client *Client) ([]PeerFromNode, error) {
		return client.getPeersByOwner(ctx, owner)
	})
	var merged []PeerFromNode
	for _, result := range result {
		merged = append(merged, result...)
	}
	sortPeers(merged)
	return merged, errs
}

// Owner is optional; calling with empty will result in return of all peers from the node.
// Result may be partially succesful.
func (mc *MultiClient) GetPeers(ctx context.Context) ([]PeerFromNode, ErrorsByNode) {
	return mc.getPeersByOwner(ctx, "")
}

// Returns nil peer if not found
// Result may be partially succesful.
func (mc *MultiClient) GetPeer(ctx context.Context, pubkey string) (*PeerFromNode, ErrorsByNode) {
	results, err := runParallelRequests(ctx, mc, func(ctx context.Context, client *Client) (*PeerFromNode, error) {
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
func (mc *MultiClient) GetUserPeers(ctx context.Context, userUUID string) ([]PeerFromNode, ErrorsByNode) {
	return mc.getPeersByOwner(ctx, userUUID)
}
