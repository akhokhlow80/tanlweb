package peers

import (
	"context"
	"sync"
)

type CachedPendingPeerRequest struct {
	CreatePeer    CreatePeerOnNode
	UpdateRequest UpdateRequestInRepo
	PeerRequest
}

// The cache is meant to prevent the service from being DDoSed (by avoiding locking DB lookups).
// The requests with invalid random IDs are rejected after the map lookup,
// while the valid requests are processed normally.
//
// Only requests with status "pending" are allowed to be placed in the cache.
type PendingRequestsCache struct {
	sync.RWMutex
	requests map[string]CachedPendingPeerRequest
}

func NewPendingRequestsCache() *PendingRequestsCache {
	return &PendingRequestsCache{
		requests: make(map[string]CachedPendingPeerRequest),
	}
}

func (cache *PendingRequestsCache) Put(req CachedPendingPeerRequest) {
	if req.Status != Pending {
		panic("Cached peer could only have pending status")
	}

	defer cache.Unlock()
	cache.Lock()

	cache.requests[req.RandomID] = req
}

func (cache *PendingRequestsCache) Pop(randomID string) (CachedPendingPeerRequest, bool) {
	cache.RLock()
	_, ok := cache.requests[randomID]
	if !ok {
		cache.RUnlock()
		return CachedPendingPeerRequest{}, false
	}
	cache.RUnlock()

	defer cache.Unlock()
	cache.Lock()
	req, ok := cache.requests[randomID]
	if !ok {
		return CachedPendingPeerRequest{}, false
	}
	delete(cache.requests, req.RandomID)
	return req, true
}

// Errors: ErrRequestIsNotPending, ErrRequestNotFound
func (req *CachedPendingPeerRequest) Complete(ctx context.Context) (
	conf WGQuickConf,
	peer Peer,
	interfaceName string,
	err error,
) {
	return req.PeerRequest.Complete(ctx, req.UpdateRequest, req.CreatePeer)
}

// Errors: ErrRequestIsNotPending, ErrRequestNotFound
func (req *CachedPendingPeerRequest) Cancel(ctx context.Context) error {
	return req.PeerRequest.Cancel(ctx, req.UpdateRequest)
}
