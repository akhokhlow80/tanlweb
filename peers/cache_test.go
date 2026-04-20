package peers_test

import (
	"akhokhlow80/tanlweb/peerconfig"
	"akhokhlow80/tanlweb/peers"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func randKey(rnd *rand.Rand) string {
	var key [32]byte
	for j := range key {
		key[j] = byte(rnd.Int())
	}
	return base64.StdEncoding.EncodeToString(key[:])
}

type mockNodeClient struct {
	sync.RWMutex
	rnd              *rand.Rand
	peers            []*peers.Peer
	uuid             peers.NodeUUID
	GetPeersStart    <-chan struct{} // not protected by mutex
	GetPeersComplete <-chan struct{} // not protected by mutex
}

func newMockNodeClient() *mockNodeClient {
	return &mockNodeClient{
		rnd:  rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		uuid: peers.NodeUUID(uuid.NewString()),
	}
}

var _ peers.NodeClient = (*mockNodeClient)(nil)

// Generate a new peer and return a pointer (to mutate later). For test use only.
func (m *mockNodeClient) CreatePeerPtr(Owner peers.UserUUID) *peers.Peer {
	defer m.Unlock()
	m.Lock()
	var peer peers.Peer
	peer.PublicKey = peers.PublicKey(randKey(m.rnd))
	peer.PresharedKey = peers.PresharedKey(randKey(m.rnd))
	peer.UserUUID = peers.UserUUID(Owner)
	peer.Enabled = true
	peer.Endpoint = fmt.Sprintf("%d.%d.%d.%d:%d", m.rnd.IntN(256), m.rnd.IntN(256), m.rnd.IntN(256), m.rnd.IntN(256), m.rnd.IntN(65536))
	m.peers = append(m.peers, &peer)
	return &peer
}

// CreatePeer implements peers.NodeClient.
func (m *mockNodeClient) CreatePeer(ctx context.Context, Owner peers.UserUUID) (peerconfig.WGQuick, peers.Peer, error) {
	return peerconfig.WGQuick{}, *m.CreatePeerPtr(Owner), nil
}

// GetPeers implements peers.NodeClient.
func (m *mockNodeClient) GetPeers(ctx context.Context) ([]peers.Peer, error) {
	if m.GetPeersStart != nil {
		<-m.GetPeersStart
	}
	defer m.RUnlock()
	m.RLock()
	peers := make([]peers.Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, *peer)
	}
	if m.GetPeersComplete != nil {
		<-m.GetPeersComplete
	}
	return peers, nil
}

// Ignores Updated field
func assertCachedPeer(t *testing.T, p1 *peers.CachedPeer, p2 *peers.CachedPeer) {
	p1.Updated = peers.Updated{}
	p2.Updated = peers.Updated{}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatalf("Cached peers are different: %v vs %v", p1, p2)
	}
}

// Ignores Updated field
func assertCachedPeerLists(t *testing.T, ps1 []peers.CachedPeer, ps2 []peers.CachedPeer) {
	if len(ps1) != len(ps2) {
		t.Fatalf("Cached peers lists are different: %v vs %v", ps1, ps2)
	}
	m := make(map[peers.PublicKey]peers.CachedPeer)
	for _, peer := range ps1 {
		m[peer.PublicKey] = peer
	}
	var failed bool
	for _, peer2 := range ps2 {
		peer1, contains := m[peer2.PublicKey]
		if !contains {
			failed = true
			t.Errorf("No match for peer %v", peer2)
		}
		peer2.Updated = peers.Updated{}
		peer1.Updated = peers.Updated{}
		if !reflect.DeepEqual(peer1, peer2) {
			t.Errorf("Cached peers are different: %v vs %v", peer1, peer2)
		}
	}
	if failed {
		t.Fatalf("Cached peers lists are different: %v vs %v", ps1, ps2)
	}
}

func TestCache(t *testing.T) {
	const (
		ttl     = time.Millisecond * 50
		timeout = time.Millisecond * 50
	)
	cache := peers.NewCache(timeout, ttl)
	node1Client := newMockNodeClient()
	node1 := peers.Node{
		UUID:   node1Client.uuid,
		Name:   "node1",
		Client: node1Client,
	}
	cache.PutNode(node1)
	node2Client := newMockNodeClient()
	node2 := peers.Node{
		UUID:   node2Client.uuid,
		Name:   "node2",
		Client: node2Client,
	}
	cache.PutNode(node2)
	user1UUID := peers.UserUUID(uuid.NewString())
	user2UUID := peers.UserUUID(uuid.NewString())

	peer1 := node1Client.CreatePeerPtr(user1UUID)
	peer2 := node2Client.CreatePeerPtr(user1UUID)
	peer3 := node2Client.CreatePeerPtr(user2UUID)

	t.Run("test PutPeer()", func(t *testing.T) {
		if !cache.PutPeer(*peer1, node1Client.uuid) {
			t.Fatalf("Unexpected return value from PutPeer()")
		}
		if !cache.PutPeer(*peer1, node1Client.uuid) {
			t.Fatalf("Unexpected return value from PutPeer()")
		}
		if !cache.PutPeer(*peer2, node2Client.uuid) {
			t.Fatalf("Unexpected return value from PutPeer()")
		}
		if cache.PutPeer(*peer2, "not-a-valid-node-uuid") {
			t.Fatalf("Unexpected return value from PutPeer()")
		}
		if !cache.PutPeer(*peer3, node2Client.uuid) {
			t.Fatalf("Unexpected return value from PutPeer()")
		}
	})

	cachedPeer1Exp := peers.CachedPeer{
		Peer: *peer1,
		Node: &node1,
	}
	cachedPeer2Exp := peers.CachedPeer{
		Peer: *peer2,
		Node: &node2,
	}
	cachedPeer3Exp := peers.CachedPeer{
		Peer: *peer3,
		Node: &node2,
	}

	t.Run("test GetPeer()", func(t *testing.T) {
		cachedPeer1, err := cache.GetPeer(context.Background(), peer1.PublicKey)
		if err != nil {
			t.Fatalf("Unexpected error from GetPeer(): %s", err)
		}
		assertCachedPeer(t, &cachedPeer1, &cachedPeer1Exp)

		cachedPeer2, err := cache.GetPeer(context.Background(), peer2.PublicKey)
		if err != nil {
			t.Fatalf("Unexpected error from GetPeer(): %s", err)
		}
		assertCachedPeer(t, &cachedPeer2, &cachedPeer2Exp)
		cachedPeer3, err := cache.GetPeer(context.Background(), peer3.PublicKey)
		if err != nil {
			t.Fatalf("Unexpected error from GetPeer(): %s", err)
		}
		assertCachedPeer(t, &cachedPeer3, &cachedPeer3Exp)
		_, err = cache.GetPeer(context.Background(), "not-a-peer-public-key")
		if !errors.Is(err, peers.ErrPeerNotFound) {
			t.Fatalf("Expected ErrPeerNotFound, got: %s", err)
		}
	})

	t.Run("test UpdatePeer()", func(t *testing.T) {
		cache.UpdatePeer(peer1.PublicKey, func(peer *peers.CachedPeer) {
			peer.Enabled = false
		})
		cache.UpdatePeer(peer3.PublicKey, func(peer *peers.CachedPeer) {
			peer.Enabled = false
		})
		cachedPeer1Exp.Enabled = false
		cachedPeer3Exp.Enabled = false
		peer3.Enabled = false
	})

	t.Run("test GetAllPeers()", func(t *testing.T) {
		cachedPeersExp := []peers.CachedPeer{
			cachedPeer1Exp,
			cachedPeer2Exp,
			cachedPeer3Exp,
		}
		cachedPeers, err := cache.GetAllPeers(context.Background())
		if err != nil {
			t.Fatalf("Unexpected error from GetAllPeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedPeers, cachedPeersExp)
	})

	t.Run("test GetNodePeers()", func(t *testing.T) {
		node1CachedPeers, err := cache.GetNodePeers(context.Background(), node1.UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetNodePeers(): %s", err)
		}
		node1CachedPeersExp := []peers.CachedPeer{
			cachedPeer1Exp,
		}
		assertCachedPeerLists(t, node1CachedPeers, node1CachedPeersExp)

		node2CachedPeers, err := cache.GetNodePeers(context.Background(), node2.UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetNodePeers(): %s", err)
		}
		node2CachedPeersExp := []peers.CachedPeer{
			cachedPeer2Exp,
			cachedPeer3Exp,
		}
		assertCachedPeerLists(t, node2CachedPeers, node2CachedPeersExp)
	})

	t.Run("test GetUserPeers()", func(t *testing.T) {
		user1CachedPeers, err := cache.GetUserPeers(context.Background(), user1UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		user1CachedPeersExp := []peers.CachedPeer{
			cachedPeer1Exp,
			cachedPeer2Exp,
		}
		assertCachedPeerLists(t, user1CachedPeers, user1CachedPeersExp)

		user2CachedPeers, err := cache.GetUserPeers(context.Background(), user2UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		user2CachedPeersExp := []peers.CachedPeer{
			cachedPeer3Exp,
		}
		assertCachedPeerLists(t, user2CachedPeers, user2CachedPeersExp)

		unknownUserCachedPeers, err := cache.GetUserPeers(context.Background(), "not a user UUID")
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		assertCachedPeerLists(t, unknownUserCachedPeers, nil)
	})

	t.Run("test Refresh()", func(t *testing.T) {
		peer1.Endpoint = "[::1]:1234"
		cachedPeer1Exp.Endpoint = "[::1]:1234"
		cachedPeer1Exp.Enabled = true // This was set false by Update() test, but it was never commited to the node.
		peer2.UserUUID = user2UUID
		cachedPeer2Exp.UserUUID = user2UUID

		if err := cache.Refresh(context.Background()); err != nil {
			t.Fatalf("Unexpected error from Refresh(): %s", err)
		}

		cachedPeers, err := cache.GetAllPeers(context.Background())
		if err != nil {
			t.Fatalf("Unexpected error from GetAllPeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedPeers, []peers.CachedPeer{
			cachedPeer1Exp,
			cachedPeer2Exp,
			cachedPeer3Exp,
		})

		user1CachedPeers, err := cache.GetUserPeers(context.Background(), user1UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		assertCachedPeerLists(t, user1CachedPeers, []peers.CachedPeer{
			cachedPeer1Exp,
		})

		user2CachedPeers, err := cache.GetUserPeers(context.Background(), user2UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		assertCachedPeerLists(t, user2CachedPeers, []peers.CachedPeer{
			cachedPeer2Exp,
			cachedPeer3Exp,
		})
	})

	rnd := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

	t.Run("test GetAllPeers() auto-refresh", func(t *testing.T) {
		peer1.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer1Exp.PresharedKey = peer1.PresharedKey
		peer2.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer2Exp.PresharedKey = peer2.PresharedKey
		time.Sleep(ttl * 2)
		cachedPeers, err := cache.GetAllPeers(context.Background())
		if err != nil {
			t.Fatalf("Unexpected error from GetAllPeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedPeers, []peers.CachedPeer{
			cachedPeer1Exp,
			cachedPeer2Exp,
			cachedPeer3Exp,
		})
	})

	t.Run("test GetPeer() auto-refresh", func(t *testing.T) {
		peer3.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer3Exp.PresharedKey = peer3.PresharedKey
		time.Sleep(ttl * 2)
		cachedPeer3, err := cache.GetPeer(context.Background(), peer3.PublicKey)
		if err != nil {
			t.Fatalf("Unexpected error from GetPeers(): %s", err)
		}
		assertCachedPeer(t, &cachedPeer3, &cachedPeer3Exp)
	})

	t.Run("test GetNodePeers() auto-refresh", func(t *testing.T) {
		peer2.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer2Exp.PresharedKey = peer2.PresharedKey
		time.Sleep(ttl * 2)
		cachedNodePeers, err := cache.GetNodePeers(context.Background(), node2.UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetNodePeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedNodePeers, []peers.CachedPeer{
			cachedPeer2Exp,
			cachedPeer3Exp,
		})
	})

	t.Run("test GetUserPeers() auto-refresh", func(t *testing.T) {
		peer2.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer2Exp.PresharedKey = peer2.PresharedKey
		peer3.PresharedKey = peers.PresharedKey(randKey(rnd))
		cachedPeer3Exp.PresharedKey = peer3.PresharedKey
		time.Sleep(ttl * 2)
		cachedUserPeers, err := cache.GetUserPeers(context.Background(), user2UUID)
		if err != nil {
			t.Fatalf("Unexpected error from GetUserPeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedUserPeers, []peers.CachedPeer{
			cachedPeer2Exp,
			cachedPeer3Exp,
		})
	})

	peer4 := node1Client.CreatePeerPtr(user1UUID)
	cachedPeer4Exp := peers.CachedPeer{
		Peer: *peer4,
		Node: &node1,
	}
	t.Run("test Refresh() on new peer from node", func(t *testing.T) {
		refreshStart := time.Now()
		if err := cache.Refresh(context.Background()); err != nil {
			t.Fatalf("Unexpected error from Refresh(): %s", err)
		}
		cachedPeers, err := cache.GetAllPeers(context.Background())
		if err != nil {
			t.Fatalf("Unexpected error from GetAllPeers(): %s", err)
		}
		assertCachedPeerLists(t, cachedPeers, []peers.CachedPeer{
			cachedPeer1Exp,
			cachedPeer2Exp,
			cachedPeer3Exp,
			cachedPeer4Exp,
		})

		cachedPeer4, err := cache.GetPeer(context.Background(), peer4.PublicKey)
		if err != nil {
			t.Fatalf("Unexpected error from GetPeer(): %s", err)
		}
		assertCachedPeer(t, &cachedPeer4, &cachedPeer4Exp)
		if !cachedPeer4.Updated.At.Before(refreshStart) {
			t.Fatalf("Peer4 update at timestamp is past the refresh start timestamp")
		}
		if !cachedPeer4.Updated.Successful() {
			t.Fatalf("Unexpected update failure reported for peer4")
		}
	})

	t.Run("test Refresh() doesn't overwrite dirty peers", func(t *testing.T) {
		newPresharedKeyOnNode := peers.PresharedKey(randKey(rnd))
		newPresharedKeyInCache := peers.PresharedKey(randKey(rnd))
		t.Logf("PSK NODE %s", newPresharedKeyOnNode)
		t.Logf("PSK CACHE %s", newPresharedKeyInCache)
		t.Logf("PUBKEY %s", peer4.PublicKey)
		peer4.PresharedKey = newPresharedKeyOnNode

		cachedPeer4Exp.PresharedKey = newPresharedKeyInCache
		if !cache.UpdatePeer(peer4.PublicKey, func(peer *peers.CachedPeer) {
			peer.PresharedKey = newPresharedKeyInCache
		}) {
			t.Fatalf("Unexpected failure of UpdatePeer()")
		}

		getPeersBegin := make(chan struct{})
		getPeersComplete := make(chan struct{})
		node1Client.GetPeersStart = getPeersBegin
		node1Client.GetPeersComplete = getPeersComplete

		t.Run("Refresh()", func(t *testing.T) {
			t.Parallel()

			if err := cache.Refresh(context.Background()); err != nil {
				t.Fatalf("Unexpected error from Refresh(): %s", err)
			}

			cachedPeer4, err := cache.GetPeer(context.Background(), peer4.PublicKey)
			if err != nil {
				t.Fatalf("Unexpected error from Refresh(): %s", err)
			}
			assertCachedPeer(t, &cachedPeer4, &cachedPeer4Exp)
		})
		t.Run("Put() then GetPeer()", func(t *testing.T) {
			t.Parallel()
			getPeersBegin <- struct{}{}
			if !cache.PutPeer(cachedPeer4Exp.Peer, node1Client.uuid) {
				t.Fatalf("Unexpected return from PutPeer()")
			}
			getPeersComplete <- struct{}{}
		})

		// var wg sync.WaitGroup
		// wg.Add(2)
		// go func() {
		// 	// t.Parallel()

		// 	if err := cache.Refresh(context.Background()); err != nil {
		// 		// t.Fatalf("Unexpected error from Refresh(): %s", err)
		// 	}
		// 	wg.Done()
		// }()
		// go func(){
		// 	// t.Parallel()
		// 	getPeersBegin <- struct{}{}
		// 	if !cache.PutPeer(cachedPeer4Exp.Peer, node1Client.uuid) {
		// 		// t.Fatalf("Unexpected return from PutPeer()")
		// 	}
		// 	getPeersComplete <- struct{}{}
		// 	wg.Done()
		// }()
		// wg.Wait()
	})

	// TODO: add refresh-overwrite test
}

// TODO: add race test

// func TestCacheRefreshOnTTLExpire(t *testing.T) {
// 	const ttl = time.Millisecond * 300
// 	cache := peers.NewCache(time.Second*10, ttl)

// }

// func TestCache(t *testing.T) {
// 	const (
// 		nodeCnt              = 80
// 		usersCnt             = 1000
// 		operationsCntPerUser = 1000
// 	)
// 	cache := peers.NewCache(time.Second*10, time.Millisecond*300)

// 	var wg sync.WaitGroup
// 	wg.Add(nodeCnt)
// 	var nodes []peers.Node
// 	for i := range nodeCnt {
// 		go func() {
// 			nodeclient := mockNodeClient{
// 				rnd: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
// 			}
// 			node := peers.Node{
// 				UUID:   peers.NodeUUID(uuid.NewString()),
// 				Name:   fmt.Sprintf("node %d", i),
// 				Client: &nodeclient,
// 			}
// 			nodes = append(nodes, node)
// 			cache.PutNode(node)
// 		}()
// 	}
// 	wg.Wait()

// 	var userUUIDs []peers.UserUUID
// 	for i := range usersCnt {
// 		userUUIDs[i] = peers.UserUUID(uuid.NewString())
// 	}
// 	for i := range usersCnt {
// 		t.Run(
// 			fmt.Sprintf("random cache operations - %d", i),
// 			func(t *testing.T) {
// 				t.Parallel()
// 				rnd := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
// 				mypeersMap := make(map[peers.PublicKey]peers.Peer)
// 				var myPeers []peers.Peer
// 				myuuid := userUUIDs[i]
// 				for j := range operationsCntPerUser {
// 					switch rnd.IntN(3) {
// 					case 0:
// 						node := nodes[rnd.IntN(len(nodes))]
// 						conf, err := node.Client.CreatePeer(context.Background(), string(myuuid))
// 						if err != nil {
// 							t.Fatal(err)
// 						}
// 						peer := peers.Peer{
// 							PublicKey:    peers.PublicKey(conf.NodePeer.PublicKey),
// 							PresharedKey: peers.PresharedKey(*conf.NodePeer.PresharedKey),
// 							UserUUID:     myuuid,
// 							Endpoint:     conf.NodePeer.Endpoint,
// 							Enabled:      true,
// 						}
// 						ok := cache.PutPeer(peer, node.UUID)
// 						if !ok {
// 							t.Fatal("Unexpected PutPeer() failure")
// 						}
// 						mypeersMap[peer.PublicKey] = peer
// 					case 1:
// 						pubkey := publicKeys[rnd.IntN(len(publicKeys))]
// 						ok := cache.UpdatePeer(pubkey, func(peer *peers.CachedPeer) {
// 							peer.PresharedKey = peers.PresharedKey(publicKeys[rnd.IntN(len(publicKeys))])
// 							peer.Endpoint = fmt.Sprintf("%d.%d.%d.%d:%d", j, j, j, j, j)
// 							peer.Enabled = rnd.IntN(2) == 0
// 							peer.Dirty = rnd.IntN(2) == 0
// 						})
// 						if !ok {
// 							t.Fatal("Unexpected UpdatePeer() failure")
// 						}
// 					case 2:
// 					}
// 				}
// 			},
// 		)
// 	}
// }
