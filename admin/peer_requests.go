package admin

import (
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func parsePeerRequestFromDB(dbReq *sqlgen.PeerRequest, dbOwner *sqlgen.User, dbNode *sqlgen.Node) (peers.PeerRequest, error) {
	var (
		req peers.PeerRequest
		err error
	)
	req.RandomID = dbReq.RandomID
	req.Status, err = peers.ParsePeerRequestStatus(dbReq.Status)
	if err != nil {
		return peers.PeerRequest{}, fmt.Errorf("Peer request %d from DB has invalid status: %s", dbReq.RandomID, err)
	}
	req.Sensitive.InterfaceName = dbReq.InterfaceName
	req.Sensitive.RequestedAt = dbReq.RequestedAt
	if dbReq.RequestedByUserUuid != nil {
		req.Sensitive.RequestedByUserUUID = *dbReq.RequestedByUserUuid
	}
	req.NodeUUID = dbNode.Uuid
	req.OwnerUUID = dbOwner.Uuid
	return req, nil
}

func (app *App) updatePeerRequestInDB(
	ctx context.Context,
	randID string,
	updateFn func(ctx context.Context, req *peers.PeerRequest) error,
) (peers.PeerRequest, error) {
	defer app.db.Unlock()
	app.db.Lock()
	dbReq, err := app.db.GetPeerRequestByRandomID(ctx, randID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return peers.PeerRequest{}, peers.ErrRequestNotFound
		} else {
			return peers.PeerRequest{}, err
		}
	}
	req, err := parsePeerRequestFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
	if err != nil {
		return peers.PeerRequest{}, err
	}
	if err := updateFn(ctx, &req); err != nil {
		return peers.PeerRequest{}, err
	}
	var requestedByUserUUID *string
	if len(req.Sensitive.RequestedByUserUUID) != 0 {
		requestedByUserUUID = &req.Sensitive.RequestedByUserUUID
	}
	rows, err := app.db.UpdatePeerRequest(ctx, sqlgen.UpdatePeerRequestParams{
		InterfaceName:       req.Sensitive.InterfaceName,
		RequestedAt:         req.Sensitive.RequestedAt,
		RequestedByUserUuid: requestedByUserUUID,
		Status:              string(req.Status),
		RandomID:            req.RandomID,
	})
	if err != nil {
		return peers.PeerRequest{}, err
	}
	if rows != 1 {
		return peers.PeerRequest{}, peers.ErrRequestNotFound
	}
	return req, err
}

func (app *App) putPendingPeerRequestToCache(req peers.PeerRequest) error {
	nodeClient := app.nodeClients.GetClient(req.NodeUUID)
	if nodeClient == nil {
		return fmt.Errorf("No client found for node with uuid=%s", req.NodeUUID)
	}
	app.peerReqCache.Put(peers.CachedPendingPeerRequest{
		PeerRequest:   req,
		CreatePeer:    nodeClient.CreatePeer,
		UpdateRequest: app.updatePeerRequestInDB,
	})
	return nil
}
