package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

func parsePeerRequestFromDB(dbReq *sqlgen.PeerRequest, dbOwner *sqlgen.User, dbNode *sqlgen.Node) (peers.PeerRequest, error) {
	var (
		req peers.PeerRequest
		err error
	)
	req.RandomID = dbReq.RandomID
	req.Status, err = peers.ParsePeerRequestStatus(dbReq.Status)
	if err != nil {
		return peers.PeerRequest{}, fmt.Errorf("Peer request %s from DB has invalid status: %s", dbReq.RandomID, err)
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
	nodeClient := app.nodeClients.Get(req.NodeUUID)
	if nodeClient == nil {
		return fmt.Errorf("No client found for node with uuid=%s", req.NodeUUID)
	}
	app.peerReqCache.Put(peers.CachedPendingPeerRequest{
		PeerRequest:   req,
		CreatePeer:    nodeClient.CreatePeer,
		UpdateRequest: app.updatePeerRequestInDB,
		AllowedIPs:    nodeClient.Node.AllowedIPs,
	})
	return nil
}

func (app *App) registerPeerRequestHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /users/{user_uuid}/peers/new",
		web.FailableHandler(app.standardErrorHandler, app.newPeerPageHandler))
	m.HandleFunc("POST /peers",
		web.FailableHandler(app.htmxErrorHandler, app.addPeerHandler))
	m.HandleFunc("GET /peers/requests/{random_id}",
		web.FailableHandler(app.standardErrorHandler, app.peerRequestPageHandler))
	m.HandleFunc("POST /peers/requests/{random_id}/cancel",
		web.FailableHandler(app.htmxErrorHandler, app.cancelPeerRequestHandler))
}

type newPeerNodeSelectOption struct {
	UUID string
	Name string
}

type newPeerPageView struct {
	R *http.Request

	UserUUID string
	Nodes    []newPeerNodeSelectOption
}

func (app *App) newPeerPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.W}); err != nil {
		return err
	}

	userUUID := r.PathValue("user_uuid")

	dbNodes, err := func() ([]sqlgen.Node, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.GetNodes(r.Context())
	}()
	if err != nil {
		return err
	}
	nodes := make([]newPeerNodeSelectOption, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		nodes = append(nodes, newPeerNodeSelectOption{
			UUID: dbNode.Uuid,
			Name: dbNode.Name,
		})
	}

	return app.tmpl.ExecuteTemplate(w, "peers/new", newPeerPageView{
		R:        r,
		UserUUID: userUUID,
		Nodes:    nodes,
	})
}

type peerErrors struct {
	NodeUUIDEmpty        bool
	InvalidInterfaceName bool
}

func (errs *peerErrors) Ok() bool {
	return !(errs.NodeUUIDEmpty || errs.InvalidInterfaceName)
}

func (app *App) addPeerHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.W}); err != nil {
		return err
	}

	// Parse form

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	userUUID := web.FormScalar(r.Form, "user-uuid")
	nodeUUID := web.FormScalar(r.Form, "node-uuid")
	interfaceName := web.FormScalar(r.Form, "interface-name")

	var peerErrors peerErrors
	if len(nodeUUID) == 0 {
		peerErrors.NodeUUIDEmpty = true
	}
	req, err := peers.NewPeerRequest(
		interfaceName,
		getAuthenticatedUser(r.Context()).ID,
		nodeUUID,
		userUUID,
	)
	if err != nil {
		if errors.Is(err, peers.ErrInvalidInterfaceName) {
			peerErrors.InvalidInterfaceName = true
		} else {
			return err
		}
	}
	if !peerErrors.Ok() {
		return app.tmpl.ExecuteTemplate(w, "peers/invalid", peerErrors)
	}

	// Put to the db

	err = func(ctx context.Context) error {
		defer app.db.Unlock()
		app.db.Lock()
		user, err := app.db.GetUserByUUID(ctx, req.OwnerUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errNotFound
			} else {
				return err
			}
		}
		node, err := app.db.GetNodeByUUID(ctx, req.NodeUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errNotFound
			} else {
				return err
			}
		}
		return app.db.CreatePeerRequest(r.Context(), sqlgen.CreatePeerRequestParams{
			RandomID:            req.RandomID,
			InterfaceName:       req.Sensitive.InterfaceName,
			RequestedAt:         req.Sensitive.RequestedAt,
			RequestedByUserUuid: &req.Sensitive.RequestedByUserUUID,
			OwnedByUserID:       user.ID,
			NodeID:              node.ID,
		})
	}(r.Context())
	if err != nil {
		return err
	}

	// Put to the cache
	if err := app.putPendingPeerRequestToCache(req); err != nil {
		return err
	}

	w.Header().Set("HX-Redirect", app.encryptURI("peers/requests/"+url.PathEscape(req.RandomID)))

	return nil
}

type peerRequestView struct {
	RandomID            string
	ShortRandomID       string
	Status              peers.PeerRequestStatus
	InterfaceName       string // zero if completed
	RequestedAtUnix     int64  // zero if completed
	RequestedByUserUUID string // zero if completed
	OwnedByUserUUID     string
	NodeUUID            string
	NodeName            string
	ConfigURL           string       // zero if status is not pending
	ConfigURLQRImage    template.URL // zero if status is not pending

	// To compare with real status in templates
	ConstStatus struct {
		Pending,
		ConfigRequested,
		Created,
		Failed,
		Cancelled peers.PeerRequestStatus
	}
}

type singlePeerRequestView struct {
	R *http.Request
	peerRequestView
}

func (app *App) parsePeerRequestViewFromDB(
	dbReq *sqlgen.PeerRequest,
	dbOwner *sqlgen.User,
	dbNode *sqlgen.Node,
) (peerRequestView, error) {
	var requestedBy string
	if dbReq.RequestedByUserUuid != nil {
		requestedBy = *dbReq.RequestedByUserUuid
	}

	status, err := peers.ParsePeerRequestStatus(dbReq.Status)
	if err != nil {
		return peerRequestView{}, err
	}

	var (
		configURL        string
		configURLQRImage string
	)
	if status == peers.Pending {
		configURL = app.cfg.PeerConfigsBaseURI + "/" + url.PathEscape(dbReq.RandomID)
		qrBytes, err := qrcode.Encode(configURL, qrcode.Medium, 256)
		if err != nil {
			return peerRequestView{}, fmt.Errorf("Failed to encode QR: %s", err)
		}
		configURLQRImage = fmt.Sprintf(
			"data:image/png;base64,%s",
			base64.StdEncoding.EncodeToString(qrBytes),
		)
		println(configURLQRImage)
	}

	return peerRequestView{
		RandomID:            dbReq.RandomID,
		ShortRandomID:       dbReq.RandomID[31:],
		Status:              status,
		InterfaceName:       dbReq.InterfaceName,
		RequestedAtUnix:     dbReq.RequestedAt.Unix(),
		RequestedByUserUUID: requestedBy,
		OwnedByUserUUID:     dbOwner.Uuid,
		NodeUUID:            dbNode.Uuid,
		NodeName:            dbNode.Name,
		ConfigURL:           configURL,
		ConfigURLQRImage:    template.URL(configURLQRImage),
		ConstStatus: struct {
			Pending, ConfigRequested, Created, Failed, Cancelled peers.PeerRequestStatus
		}{
			Pending:         peers.Pending,
			ConfigRequested: peers.ConfigRequested,
			Created:         peers.Created,
			Failed:          peers.Failed,
			Cancelled:       peers.Cancelled,
		},
	}, nil
}

func (app *App) peerRequestPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	randomID := r.PathValue("random_id")

	dbReq, err := func() (sqlgen.GetPeerRequestByRandomIDRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetPeerRequestByRandomID(r.Context(), randomID)
	}()
	if err != nil {
		return err
	}

	view, err := app.parsePeerRequestViewFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"peers/request-page",
		singlePeerRequestView{
			R:               r,
			peerRequestView: view,
		},
	)
}

func (app *App) cancelPeerRequestHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.W}); err != nil {
		return err
	}

	randomID := r.PathValue("random_id")

	peerReq, ok := app.peerReqCache.Pop(randomID)
	if !ok {
		return errNotFound
	}

	if err := peerReq.Cancel(r.Context()); err != nil {
		if errors.Is(err, peers.ErrRequestNotFound) {
			return errNotFound
		} else if errors.Is(err, peers.ErrRequestIsNotPending) {
			return app.renderError(w, "Request is no longer pending")
		} else {
			return err
		}
	}

	dbReq, err := func() (sqlgen.GetPeerRequestByRandomIDRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetPeerRequestByRandomID(r.Context(), randomID)
	}()
	if err != nil {
		return err
	}

	view, err := app.parsePeerRequestViewFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
	if err != nil {
		return err
	}
	if err := app.tmpl.ExecuteTemplate(
		w,
		"peers/request-page",
		singlePeerRequestView{
			R:               r,
			peerRequestView: view,
		},
	); err != nil {
		return err
	}

	return app.renderSuccess(w, "Cancelled")
}
