package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/nodes"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
)

func (app *App) registerPeerHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /peers/{public_key}",
		web.FailableHandler(app.standardErrorHandler, app.peerPageHandler))
	m.HandleFunc("GET /users/{user_uuid}/peers/new",
		web.FailableHandler(app.standardErrorHandler, app.newPeerPageHandler))
	m.HandleFunc("GET /peers",
		web.FailableHandler(app.standardErrorHandler, app.peersListHandler))
	m.HandleFunc("POST /peers",
		web.FailableHandler(app.htmxErrorHandler, app.addPeer))
	m.HandleFunc("GET /peers/requests/{random_id}",
		web.FailableHandler(app.standardErrorHandler, app.peerRequestHandler))
	m.HandleFunc("POST /peers/requests/{random_id}/cancel",
		web.FailableHandler(app.standardErrorHandler, app.cancelPeerRequestHandler))
}

type peerView struct {
	Peer  *nodes.PeerFromNode
	Error error
}

type peerViewWithHttpReq struct {
	R *http.Request
	peerView
}

func (app *App) peerPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	pubkey := r.PathValue("public_key")

	peer, errors := app.nodeClients.GetPeer(r.Context(), pubkey)
	return app.tmpl.ExecuteTemplate(w, "peers/page", peerViewWithHttpReq{
		R: r,
		peerView: peerView{
			Peer:  peer,
			Error: errors.Error(),
		},
	})
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

func (app *App) addPeer(w http.ResponseWriter, r *http.Request) error {
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
		user, err := app.db.GetUser(ctx, req.OwnerUUID)
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
	ConfigURL           string // zero if status is not pending

	// To compare with real status in templates
	ConstStatus struct {
		Pending,
		ConfigRequested,
		Created,
		Failed,
		Cancelled peers.PeerRequestStatus
	}
}

type peerRequestViewWithHttpReq struct {
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
	var configURL string
	if status == peers.Pending {
		configURL = app.cfg.PeerConfigsBaseURI + "/" + url.PathEscape(dbReq.RandomID)
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

func (app *App) peerRequestHandler(w http.ResponseWriter, r *http.Request) error {
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
		peerRequestViewWithHttpReq{
			R:               r,
			peerRequestView: view,
		},
	)
}

type peersListView struct {
	R *http.Request

	Requests     []peerRequestView
	Peers        []nodes.PeerFromNode
	ErrorMessage string
}

func (app *App) peersListHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	dbReqs, err := func() ([]sqlgen.GetPeerRequestsRow, error) {
		app.db.RLock()
		defer app.db.RUnlock()
		return app.db.GetPeerRequests(r.Context())
	}()
	if err != nil {
		return err
	}
	reqs := make([]peerRequestView, 0, len(dbReqs))
	for _, dbReq := range dbReqs {
		req, err := app.parsePeerRequestViewFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
		if err != nil {
			return err
		}
		if req.Status != peers.Pending && req.Status != peers.ConfigRequested {
			continue
		}
		reqs = append(reqs, req)
	}

	peers, errors := app.nodeClients.GetPeers(r.Context())
	var errMsg string
	if errors.Error() != nil {
		errMsg = errors.Error().Error()
	}

	return app.tmpl.ExecuteTemplate(w, "peers/list", peersListView{
		R:            r,
		Requests:     reqs,
		Peers:        peers,
		ErrorMessage: errMsg,
	})
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
		peerRequestViewWithHttpReq{
			R:               r,
			peerRequestView: view,
		},
	); err != nil {
		return err
	}

	return app.renderSuccess(w, "Cancelled")
}
