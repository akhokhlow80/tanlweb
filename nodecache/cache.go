package nodecache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Node struct {
	UUID    string
	Name    string
	BaseURI string
}

type UpdateStatus struct {
	At          time.Time
	AttemptedAt time.Time
}

func (status *UpdateStatus) Successful() bool {
	return !status.At.Before(status.AttemptedAt)
}

type Peer struct {
	PublicKeyBase64    string
	PresharedKeyBase64 string // optional
	UserUUID           string
	Node               *Node // set nil only when putting peer
	Endpoint           string
	Enabled            bool
	Updated            UpdateStatus
}

type nodesPeer struct {
	sync.RWMutex
	peers   map[string]Peer
	node    Node // read-only
	updated UpdateStatus
}

const NodeUpdateTimeout = time.Second * 40

func (node *nodesPeer) updateRoutine(
	ctx context.Context,
	cancel context.CancelFunc,
	errOut chan<- error,
) {
	defer func() {
		r := recover()
		if r != nil {
			log.Printf("Panic in peer update routine (node=%s): %s", node.node.UUID, debug.Stack())
			errOut <- fmt.Errorf("Panic during peer update: %v", r)
		}
		node.Unlock()
		cancel()
	}()
	node.Lock()

	node.updated.AttemptedAt = time.Now()

	uri := node.node.BaseURI + "/api/v1/peers"
	resp, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		errOut <- fmt.Errorf("Update peers from node %s request failed: %w", node.node.UUID, err)
		return
	}
	if resp.Response.StatusCode != http.StatusOK {
		errOut <- fmt.Errorf(
			"Update request to node %s failed with code %d",
			node.node.UUID,
			resp.Response.StatusCode,
		)
		return
	}

	type apiPeerResp struct {
		PublicKeyBase64     string  `json:"public_key_base64"`
		IsEnabled           bool    `json:"is_enabled"`
		PresharedKeyBase64  *string `json:"preshared_key_base64"`
		Endpoint            *string `json:"endpoint"`
		PersistentKeepalive *int64  `json:"persistent_keepalive"`
		Owner               *string `json:"owner"`
	}

	var peers []apiPeerResp
	if err = json.NewDecoder(resp.Response.Body).Decode(&peers); err != nil {
		errOut <- fmt.Errorf(
			"Node %s responded with invalid JSON: %w",
			node.node.UUID,
			err,
		)
		return
	}

	for _, apiPeer := range peers {
		var peer Peer
		peer.PublicKeyBase64 = apiPeer.PublicKeyBase64
		if apiPeer.PresharedKeyBase64 != nil {
			peer.PresharedKeyBase64 = *apiPeer.PresharedKeyBase64
		}
		if apiPeer.Owner != nil {
			ownerUUID, err := uuid.Parse(*apiPeer.Owner)
			if err != nil {
				log.Printf(
					"Node %s response contains peer %s with invalid owner %s",
					node.node.UUID,
					peer.PublicKeyBase64,
					*apiPeer.Owner,
				)
				continue
			}
			peer.UserUUID = ownerUUID.String()
		}
		peer.Node = &node.node
		if apiPeer.Endpoint != nil {
			peer.Endpoint = *apiPeer.Endpoint
		}
		peer.Enabled = apiPeer.IsEnabled
		peer.Updated.AttemptedAt = time.Now()
		peer.Updated.At = time.Now()
		node.peers[apiPeer.PublicKeyBase64] = peer
	}

	node.updated.At = time.Now()
	errOut <- nil
}

func (node *nodesPeer) update(
	ctx context.Context,
	force bool,
	ttl time.Duration,
	timeout time.Duration,
) <-chan error {
	if !force {
		node.RLock()
		updatedAt := node.updated.At
		node.RUnlock()
		if time.Since(updatedAt) <= ttl {
			return nil
		}
	}
	errOut := make(chan error)
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	go node.updateRoutine(updateCtx, cancel, errOut)
	return errOut
}

type Cache struct {
	sync.RWMutex
	nodes                  map[string]*nodesPeer
	nodeUpdatePeersTimeout time.Duration
	ttl                    time.Duration
}

func New(nodeUpdatePeersTimeout time.Duration, ttl time.Duration) *Cache {
	return &Cache{
		nodeUpdatePeersTimeout: nodeUpdatePeersTimeout,
		ttl:                    ttl,
	}
}

type UpdateError struct {
	wrapped []error
}

func (err UpdateError) Error() string {
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

func (err UpdateError) Unwrap() []error {
	return err.wrapped
}

// Call on read-locked cache.
func (cache *Cache) updatePeers(ctx context.Context, force bool) error {
	errOutChans := make([]<-chan error, 0, len(cache.nodes))
	for _, node := range cache.nodes {
		errOut := node.update(ctx, force, cache.ttl, cache.nodeUpdatePeersTimeout)
		if errOut != nil {
			errOutChans = append(errOutChans, errOut)
		}
	}
	var err UpdateError
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

// Errors: UpdateError
func (cache *Cache) Update(ctx context.Context) error {
	defer cache.RUnlock()
	cache.RLock()
	return cache.updatePeers(ctx, true)
}

func (cache *Cache) PutNode(node Node) {
	defer cache.Unlock()
	cache.Lock()
	cache.nodes[node.UUID] = &nodesPeer{
		node: node,
	}
}

// Errors: UpdateError
func (cache *Cache) GetNodes(ctx context.Context) ([]*Node, error) {
	defer cache.RUnlock()
	cache.RLock()
	err := cache.updatePeers(ctx, false)
	if err != nil {
		return nil, err
	}
	nodes := make([]*Node, 0, len(cache.nodes))
	for _, node := range cache.nodes {
		nodes = append(nodes, &node.node)
	}
	return nodes, nil
}

var ErrNodeNotFound = errors.New("Node not found")

// Errors: UpdateError, ErrNodeNotFound
func (cache *Cache) GetNode(ctx context.Context, uuid string) (*Node, error) {
	defer cache.RUnlock()
	cache.RLock()
	if err := cache.updatePeers(ctx, false); err != nil {
		return nil, err
	}
	node, ok := cache.nodes[uuid]
	if !ok {
		return nil, ErrNodeNotFound
	} else {
		return &node.node, nil
	}
}

// Returns false iff no such node exists.
func (cache *Cache) PutPeer(peer Peer, nodeUUID string) bool {
	node := cache.nodes[nodeUUID]
	cache.RUnlock()
	if node == nil {
		return false
	}
	node.Lock()
	node.peers[nodeUUID] = peer
	node.Unlock()
	return true
}

var ErrPeerNotFound = errors.New("Peer not found")

// Errors: ErrPeerNotFound, UpdateError
func (cache *Cache) GetPeer(ctx context.Context, uuid string) (Peer, error) {
	defer cache.RUnlock()
	cache.RLock()
	if err := cache.updatePeers(ctx, false); err != nil {
		return Peer{}, err
	}
	for _, node := range cache.nodes {
		node.RLock()
		peer, ok := node.peers[uuid]
		node.RUnlock()
		if ok {
			return peer, nil
		}
	}
	return Peer{}, ErrPeerNotFound
}

func sortPeers(peers []Peer) {
	sort.Slice(peers, func(i, j int) bool {
		return strings.Compare(peers[i].PublicKeyBase64, peers[j].PublicKeyBase64) < 0
	})
}

// Errors: ErrNodeNotFound, UpdateError
func (cache *Cache) GetNodePeers(ctx context.Context, nodeUUID string) ([]Peer, error) {
	cache.RLock()
	node := cache.nodes[nodeUUID]
	cache.RUnlock()
	if node == nil {
		return nil, ErrNodeNotFound
	}
	errOut := node.update(ctx, false, cache.ttl, cache.nodeUpdatePeersTimeout)
	err := <-errOut
	if err != nil {
		return nil, err
	}
	node.Lock()
	peers := make([]Peer, 0, len(node.peers))
	for _, peer := range node.peers {
		peers = append(peers, peer)
	}
	node.Unlock()
	sortPeers(peers)
	return peers, nil
}

// Errors: UpdateError
func (cache *Cache) GetUserPeers(ctx context.Context, userUUID string) ([]Peer, error) {
	defer cache.RUnlock()
	cache.RLock()
	err := cache.updatePeers(ctx, false)
	if err != nil {
		return nil, err
	}
	var peers []Peer
	for _, node := range cache.nodes {
		node.RLock()
		for _, peer := range node.peers {
			if peer.UserUUID == userUUID {
				peers = append(peers, peer)
			}
		}
		node.RUnlock()
	}
	sortPeers(peers)
	return peers, nil
}

// Errors: UpdateError
func (cache *Cache) GetAllPeers(ctx context.Context) ([]Peer, error) {
	defer cache.RUnlock()
	cache.RLock()
	err := cache.updatePeers(ctx, false)
	if err != nil {
		return nil, err
	}
	var peers []Peer
	for _, node := range cache.nodes {
		node.RLock()
		for _, peer := range node.peers {
			peers = append(peers, peer)
		}
		node.RUnlock()
	}
	sortPeers(peers)
	return peers, nil
}
