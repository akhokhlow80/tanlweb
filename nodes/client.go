package nodes

import (
	"akhokhlow80/tanlweb/peers"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

type Client struct {
	// TODO: add TLS support (including client-side auth)
	UUID string
	BaseURI string
}

// I prefer parsing to validation, but too lazy to implement it here
func validateUserOwner(owner string) bool {
	_, err := uuid.Parse(owner)
	return err != nil
}

// owner is optional; calling with empty will result in return of all peers from the node
func (client *Client) getPeersByOwner(ctx context.Context, owner string) ([]peers.Peer, error) {
	query := url.Values{}
	query.Add("owner", owner)
	uri := client.BaseURI + "/api/v1/peers?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned code %d", uri, resp.StatusCode)
	}

	var respPeers []peers.Peer
	if err = json.NewDecoder(resp.Body).Decode(&respPeers); err != nil {
		return nil, err
	}
	validatedPeers := make([]peers.Peer, 0, len(respPeers))
	for _, peer := range respPeers {
		if !validateUserOwner(peer.UserUUID) {
			log.Printf("Got peer with non-valid owner %s in GET %s query response", peer.UserUUID, uri)
			continue
		}
		validatedPeers = append(validatedPeers, peer)
	}
	return validatedPeers, nil
}

func (client *Client) GetPeers(ctx context.Context) ([]peers.Peer, error) {
	return client.getPeersByOwner(ctx, "")
}

func (client *Client) CreatePeer(ctx context.Context, Owner string) (peers.WGQuickConf, peers.Peer, error) {
	type apiCreatePeerReq struct {
		Owner string `json:"owner"`
	}

	reqBytes, err := json.Marshal(apiCreatePeerReq{Owner})
	if err != nil {
		return peers.WGQuickConf{}, peers.Peer{}, err
	}

	uri := client.BaseURI + "/api/v1/peers"
	req, err := http.NewRequestWithContext(ctx, "POST", uri, bytes.NewBuffer(reqBytes))
	if err != nil {
		return peers.WGQuickConf{}, peers.Peer{}, err
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		return peers.WGQuickConf{},
			peers.Peer{},
			fmt.Errorf("POST %s returned code %d", uri, resp.StatusCode)
	}

	var parsedResp struct {
		Peer   peers.Peer        `json:"peer"`
		Config peers.WGQuickConf `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsedResp); err != nil {
		return peers.WGQuickConf{},
			peers.Peer{},
			fmt.Errorf("Failed to parse POST %s response: %s", uri, err)
	}
	if !validateUserOwner(parsedResp.Peer.UserUUID) {
		return peers.WGQuickConf{},
			peers.Peer{},
			fmt.Errorf("Peer has invalid owner UUID %s", parsedResp.Peer.UserUUID)
	}

	return parsedResp.Config, parsedResp.Peer, nil
}

// Returns nil peer if not found
func (client *Client) GetPeer(ctx context.Context, pubkey string) (*peers.Peer, error) {
	uri := fmt.Sprintf("%s/api/v1/peers/%s", client.BaseURI, url.PathEscape(pubkey))
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned code %d", uri, resp.StatusCode)
	}

	var peer peers.Peer

	if err := json.NewDecoder(resp.Body).Decode(&peer); err != nil {
		return nil, fmt.Errorf("Failed to parse GET %s response: %s", uri, err)
	}
	if !validateUserOwner(peer.UserUUID) {
		return nil, fmt.Errorf("Peer has invalid owner UUID %s", peer.UserUUID)
	}

	return &peer, nil
}

func (client *Client) GetUserPeers(ctx context.Context, userUUID string) ([]peers.Peer, error) {
	return client.getPeersByOwner(ctx, userUUID)
}
