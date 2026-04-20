package peers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

type (
	UserUUID     string
	NodeUUID     string
	PublicKey    string
	PresharedKey string
)

type Node struct {
	UUID   NodeUUID
	Name   string
	Client NodeClient
}

type Updated struct {
	At          time.Time
	AttemptedAt time.Time
}

func (status *Updated) Successful() bool {
	return !status.At.Before(status.AttemptedAt)
}

type Peer struct {
	PublicKey    PublicKey
	PresharedKey PresharedKey // optional
	UserUUID     UserUUID
	Endpoint     string
	Enabled      bool
}

type CachedPeer struct {
	Peer
	Node    *Node
	Updated Updated
}

type nodeCache struct {
	node  Node // read-only
	peers struct {
		sync.RWMutex // Locked on reads/writes
		m            map[PublicKey]*CachedPeer
		byUser       map[UserUUID]map[PublicKey]*CachedPeer
	}
	rfrsh struct {
		sync.RWMutex // Write-locked on update, read-locked on status read
		status       Updated
	}
}

// Call on read-locked node.peers
func (node *nodeCache) updatePeerUser(oldUserUUID *UserUUID, peer *CachedPeer) {
	if oldUserUUID != nil {
		if userMap, ok := node.peers.byUser[*oldUserUUID]; ok {
			delete(userMap, peer.PublicKey)
		}
	}
	if node.peers.byUser[peer.UserUUID] == nil {
		node.peers.byUser[peer.UserUUID] = make(map[PublicKey]*CachedPeer)
	}
	node.peers.byUser[peer.UserUUID][peer.PublicKey] = peer
}

func (node *nodeCache) refresh(ctx context.Context, timeout time.Duration) error {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer func() {
		node.rfrsh.Unlock()
		cancel()
	}()
	node.rfrsh.Lock()

	requestStartedAt := time.Now()
	node.rfrsh.status.AttemptedAt = requestStartedAt
	func() {
		node.peers.Lock()
		defer node.peers.Unlock()
		for uuid, peer := range node.peers.m {
			peer.Updated.AttemptedAt = requestStartedAt
			node.peers.m[uuid] = peer
		}
	}()

	peers, err := node.node.Client.GetPeers(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get peers from node %s: %s", node.node.UUID, err)
	}

	requestCompletedAt := time.Now()

	func() {
		defer node.peers.Unlock()
		node.peers.Lock()

		for _, peer := range peers {
			cachedPeer := node.peers.m[peer.PublicKey]
			var oldUserUUID UserUUID
			if cachedPeer == nil {
				cachedPeer = new(CachedPeer)
				cachedPeer.Node = &node.node
				cachedPeer.Updated.AttemptedAt = requestStartedAt
			} else {
				if cachedPeer.Updated.At.After(requestStartedAt) {
					// Update only if no newer changes to the peer were made since the request was started
					continue
				}
				oldUserUUID = cachedPeer.UserUUID
			}

			cachedPeer.Peer = peer
			cachedPeer.Updated.At = requestCompletedAt
			node.peers.m[peer.PublicKey] = cachedPeer
			node.updatePeerUser(&oldUserUUID, cachedPeer)
		}
	}()

	node.rfrsh.status.At = time.Now()
	return nil
}

func (node *nodeCache) refreshRoutine(
	ctx context.Context,
	timeout time.Duration,
	errOut chan<- error,
) {
	defer func() {
		r := recover()
		if r != nil {
			log.Printf("Panic in peer update routine (node=%s): %s", node.node.UUID, debug.Stack())
			errOut <- fmt.Errorf("Panic during peer update: %v", r)
		}
	}()
	errOut <- node.refresh(ctx, timeout)
}

type Cache struct {
	sync.RWMutex
	nodes         map[NodeUUID]*nodeCache
	updateTimeout time.Duration
	ttl           time.Duration
}

func NewCache(nodeUpdatePeersTimeout time.Duration, ttl time.Duration) *Cache {
	return &Cache{
		updateTimeout: nodeUpdatePeersTimeout,
		ttl:           ttl,
		nodes:         make(map[NodeUUID]*nodeCache),
	}
}

type RefreshError struct {
	wrapped []error
}

func (err RefreshError) Error() string {
	var sb strings.Builder
	sb.WriteString("Failed to update peers: ")
	for i, wrapped := range err.wrapped {
		sb.WriteString(wrapped.Error())
		if i != len(err.wrapped)-1 {
			sb.WriteString(", ")
		}
	}
	return sb.String()
}

func (err RefreshError) Unwrap() []error {
	return err.wrapped
}

// Call on a read-locked cache.
func (cache *Cache) refreshPeers(ctx context.Context, force bool) error {
	errOutChans := make([]<-chan error, 0, len(cache.nodes))
	for _, node := range cache.nodes {
		node.rfrsh.RLock()
		updatedAt := node.rfrsh.status.At
		node.rfrsh.RUnlock()
		if !force && time.Since(updatedAt) <= cache.ttl {
			continue
		}

		errOut := make(chan error)
		errOutChans = append(errOutChans, errOut)
		go node.refreshRoutine(ctx, cache.updateTimeout, errOut)
	}
	var err RefreshError
	for _, errOut := range errOutChans {
		updateErr := <-errOut
		if updateErr != nil {
			err.wrapped = append(err.wrapped, updateErr)
		}
	}
	if len(err.wrapped) == 0 {
		return nil
	} else {
		return err
	}
}

// Errors: RefreshError
func (cache *Cache) Refresh(ctx context.Context) error {
	defer cache.RUnlock()
	cache.RLock()
	return cache.refreshPeers(ctx, true)
}

func (cache *Cache) PutNode(node Node) {
	defer cache.Unlock()
	cache.Lock()

	var nodeCache nodeCache
	nodeCache.node = node
	nodeCache.peers.m = make(map[PublicKey]*CachedPeer)
	nodeCache.peers.byUser = make(map[UserUUID]map[PublicKey]*CachedPeer)
	cache.nodes[node.UUID] = &nodeCache
}

// Returns false iff no such peer exists.
// If peer was not cached yet, the updateFn will be called with a pointer to a zero peer.
func (cache *Cache) UpdatePeer(pubkey PublicKey, updateFn func(peer *CachedPeer)) bool {
	// Returns unlocked node (if not nil)
	node := func() *nodeCache {
		defer cache.RUnlock()
		cache.RLock()
		for _, node := range cache.nodes {
			node.peers.Lock()
			peer := node.peers.m[pubkey]
			if peer == nil {
				node.peers.Unlock()
				continue
			} else {
				return node
			}
		}
		return nil
	}()
	if node == nil {
		return false
	}
	defer node.peers.Unlock()

	cached := node.peers.m[pubkey]
	if cached == nil {
		panic("never")
	}

	oldUserUUID := cached.UserUUID
	updateFn(cached)
	node.updatePeerUser(&oldUserUUID, cached)

	cached.Updated.AttemptedAt = time.Now()
	cached.Updated.At = time.Now()

	return true
}

// Returns false iff no such node exists.
func (cache *Cache) PutPeer(newPeer Peer, nodeUUID NodeUUID) bool {
	cache.RLock()
	node := cache.nodes[nodeUUID]
	cache.RUnlock()
	if node == nil {
		return false
	}
	node.peers.Lock()
	defer node.peers.Unlock()

	var oldUserUUID *UserUUID
	cachedPeer := node.peers.m[newPeer.PublicKey]
	if cachedPeer != nil {
		oldUserUUID = &cachedPeer.UserUUID
	} else {
		cachedPeer = new(CachedPeer)
		cachedPeer.Node = &node.node
	}
	cachedPeer.Peer = newPeer

	node.peers.m[newPeer.PublicKey] = cachedPeer
	node.updatePeerUser(oldUserUUID, cachedPeer)
	return true
}

var ErrPeerNotFound = errors.New("Peer not found")

// Errors: ErrPeerNotFound, RefreshError
func (cache *Cache) GetPeer(ctx context.Context, pubkey PublicKey) (CachedPeer, error) {
	defer cache.RUnlock()
	cache.RLock()
	if err := cache.refreshPeers(ctx, false); err != nil {
		return CachedPeer{}, err
	}
	for _, node := range cache.nodes {
		node.peers.RLock()
		peerPtr := node.peers.m[pubkey]
		if peerPtr != nil {
			peer := *peerPtr
			node.peers.RUnlock()
			return peer, nil
		}
		node.peers.RUnlock()
	}
	return CachedPeer{}, ErrPeerNotFound
}

func sortPeers(peers []CachedPeer) {
	sort.Slice(peers, func(i, j int) bool {
		return strings.Compare(
			string(peers[i].PublicKey),
			string(peers[j].PublicKey)) < 0
	})
}

var ErrNodeNotFound = errors.New("Node not found")

// Errors: ErrNodeNotFound, RefreshError
func (cache *Cache) GetNodePeers(ctx context.Context, nodeUUID NodeUUID) ([]CachedPeer, error) {
	cache.RLock()
	node := cache.nodes[nodeUUID]
	cache.RUnlock()
	if node == nil {
		return nil, ErrNodeNotFound
	}

	node.rfrsh.RLock()
	updatedAt := node.rfrsh.status.At
	node.rfrsh.RUnlock()
	if time.Since(updatedAt) > cache.ttl {
		err := node.refresh(ctx, cache.updateTimeout)
		if err != nil {
			return nil, err
		}
	}

	node.peers.RLock()
	peers := make([]CachedPeer, 0, len(node.peers.m))
	for _, peer := range node.peers.m {
		peers = append(peers, *peer)
	}
	node.peers.RUnlock()
	sortPeers(peers)
	return peers, nil
}

// Errors: RefreshError
func (cache *Cache) GetAllPeers(ctx context.Context) ([]CachedPeer, error) {
	defer cache.RUnlock()
	cache.RLock()
	err := cache.refreshPeers(ctx, false)
	if err != nil {
		return nil, err
	}
	var peers []CachedPeer
	for _, node := range cache.nodes {
		node.peers.RLock()
		for _, peer := range node.peers.m {
			peers = append(peers, *peer)
		}
		node.peers.RUnlock()
	}
	sortPeers(peers)
	return peers, nil
}

// Errors: RefreshError
func (cache *Cache) GetUserPeers(ctx context.Context, userUUID UserUUID) ([]CachedPeer, error) {
	peers, err := func() ([]CachedPeer, error) {
		defer cache.RUnlock()
		cache.RLock()
		err := cache.refreshPeers(ctx, false)
		if err != nil {
			return nil, err
		}

		var peers []CachedPeer
		for _, node := range cache.nodes {
			node.peers.RLock()
			userPeers, ok := node.peers.byUser[userUUID]
			if !ok {
				node.peers.RUnlock()
				continue
			}

			for _, peer := range userPeers {
				if peer.UserUUID != userUUID {
					panic("never")
				}
				peers = append(peers, *peer)
			}

			node.peers.RUnlock()
		}

		return peers, nil
	}()
	if err != nil {
		return nil, err
	}
	sortPeers(peers)
	return peers, err
}
