package nodes

import (
	"sync"
)

type ClientsCache struct {
	sync.RWMutex
	clients map[string]*Client
}

func NewClientsCache() *ClientsCache {
	return &ClientsCache{
		clients: make(map[string]*Client),
	}
}

func (mc *ClientsCache) Put(client *Client) {
	defer mc.Unlock()
	mc.Lock()
	mc.clients[client.Node.UUID.String()] = client
}

func (mc *ClientsCache) Get(nodeUUID string) *Client {
	defer mc.RUnlock()
	mc.RLock()
	return mc.clients[nodeUUID]
}

// TODO: return sorted
func (mc *ClientsCache) Clients() []*Client {
	defer mc.RUnlock()
	mc.RLock()
	clients := make([]*Client, 0, len(mc.clients))
	for _, client := range mc.clients {
		clients = append(clients, client)
	}
	return clients
}
