package main

import (
	"akhokhlow80/tanlweb/auth"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// TODO: handle config request

func (app *app) registerPeerHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /peers/new", web.FailableHandler(app.StandardErrorHandler, app.newPeerPage))
	m.HandleFunc("GET /peers", web.FailableHandler(app.StandardErrorHandler, app.peersList))
	m.HandleFunc("POST /peers", web.FailableHandler(app.HTMXErrorHandler, app.addPeer))
	// m.HandleFunc("GET /peers/{public_key}", web.FailableHandler(app.StandardErrorHandler, app.peersList))
	m.HandleFunc("GET /peers/requests/{uuid}", web.FailableHandler(app.StandardErrorHandler, app.newPeerRequest))
	m.HandleFunc("POST /peers/requests/{uuid}/cancel", web.FailableHandler(app.StandardErrorHandler, app.cancelNewPeerRequest))
	// m.HandleFunc("POST /peers/requests/{uuid}/config", web.FailableHandler(app.StandardErrorHandler, app.retrievePendingPeerConfig))
}

// type peerView struct {
// 	PublicKey string
// 	Endpoint  string
// 	OwnerUUID string
// 	Node      struct {
// 		UUID string
// 		Name string
// 	}
// }

type newPeerNodeSelectOption struct {
	UUID string
	Name string
}

type newPeerPageView struct {
	UserUUID string
	Nodes    []newPeerNodeSelectOption
}

func (app *app) newPeerPage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	userUUID, err := uuid.Parse(r.URL.Query().Get("user-uuid"))
	if err != nil {
		return ErrParseForm
	}

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
		UserUUID: userUUID.String(),
		Nodes:    nodes,
	})
}

type peerErrors struct {
	NodeUUIDEmpty        bool
	InvalidInterfaceName bool
}

var wgInterfaceNameRegexp = regexp.MustCompile(`[a-zA-Z0-9_=+.-]{1,15}`)

func (app *app) addPeer(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return ErrParseForm
	}

	uuid := uuid.New()
	userUUID := web.FormScalar(r.Form, "user-uuid")
	nodeUUID := web.FormScalar(r.Form, "node-uuid")
	interfaceName := web.FormScalar(r.Form, "interface-name")

	var peerErrors peerErrors
	if len(nodeUUID) == 0 {
		peerErrors.NodeUUIDEmpty = true
	}
	if !wgInterfaceNameRegexp.MatchString(interfaceName) {
		peerErrors.InvalidInterfaceName = true
	}
	if peerErrors.InvalidInterfaceName || peerErrors.NodeUUIDEmpty {
		return app.tmpl.ExecuteTemplate(w, "peers/invalid", peerErrors)
	}

	err := func(ctx context.Context) error {
		defer app.db.RUnlock()
		app.db.RLock()
		user, err := app.db.GetUser(ctx, userUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			} else {
				return err
			}
		}
		node, err := app.db.GetNodeByUUID(ctx, nodeUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			} else {
				return err
			}
		}
		return app.db.CreateNewPeerRequest(r.Context(), sqlgen.CreateNewPeerRequestParams{
			Uuid:                uuid.String(),
			InterfaceName:       interfaceName,
			RequestedAt:         time.Now(),
			RequestedByUserUuid: &getAuthenticateUser(ctx).ID,
			OwnedByUserID:       user.ID,
			NodeID:              node.ID,
		})
	}(r.Context())
	if err != nil {
		return err
	}

	w.Header().Set("HX-Redirect", fmt.Sprintf("%s/peers/requests/%s", app.cfg.BaseURI, uuid.String()))

	return nil
}

func parsePeerRequestFromDB(row *sqlgen.GetNewPeerRequestsRow) (peers.PeerRequest, error) {
	var status peers.PeerRequestStatus
	switch row.Status {
	case string(peers.Pending):
	case string(peers.ConfigRequested):
	case string(peers.Created):
	case string(peers.Cancelled):
		status = peers.PeerRequestStatus(row.Status)
	default:
		return peers.PeerRequest{},
			fmt.Errorf("Unknown status `%s` while parsing new peer request %s from DB", row.Status, row.Uuid)
	}

	var requestedByUserUUID string
	if row.RequestedByUserUuid != nil {
		requestedByUserUUID = *row.RequestedByUserUuid
	}

	return peers.PeerRequest{
		UUID:   row.Uuid,
		Status: status,
		Sensitive: struct {
			InterfaceName       string
			RequestedAt         time.Time
			RequestedByUserUUID string
		}{
			InterfaceName:       row.InterfaceName,
			RequestedAt:         row.RequestedAt,
			RequestedByUserUUID: requestedByUserUUID,
		},
		NodeUUID:  row.NodeUuid,
		OwnerUUID: row.OwnedByUserUuid,
	}, nil
}

type newPeerRequestView struct {
	UUID                string
	Status              peers.PeerRequestStatus
	InterfaceName       string // zero if completed
	RequestedAtUnix     int64  // zero if completed
	RequestedByUserUUID string // zero if completed
	OwnedByUserUUID     string
	NodeUUID            string
	NodeName            string

	// To compare with real status in templates
	ConstStatus struct {
		Pending,
		ConfigRequested,
		Created,
		Cancelled peers.PeerRequestStatus
	}
}

func newPeerRequestViewFromDB(dbReq *sqlgen.GetNewPeerRequestsRow) (newPeerRequestView, error) {
	var requestedBy string
	if dbReq.RequestedByUserUuid != nil {
		requestedBy = *dbReq.RequestedByUserUuid
	}
	status, err := parsePeerRequestStatus(dbReq.Status)
	if err != nil {
		return newPeerRequestView{}, err
	}
	return newPeerRequestView{
		UUID:                dbReq.Uuid,
		Status:              status,
		InterfaceName:       dbReq.InterfaceName,
		RequestedAtUnix:     dbReq.RequestedAt.Unix(),
		RequestedByUserUUID: requestedBy,
		OwnedByUserUUID:     dbReq.OwnedByUserUuid,
		NodeUUID:            dbReq.NodeUuid,
		NodeName:            dbReq.NodeName,
		ConstStatus: struct {
			Pending, ConfigRequested, Created, Cancelled peers.PeerRequestStatus
		}{
			Pending:         peers.Pending,
			ConfigRequested: peers.ConfigRequested,
			Created:         peers.Created,
			Cancelled:       peers.Cancelled,
		},
	}, nil
}

func parsePeerRequestStatus(s string) (peers.PeerRequestStatus, error) {
	switch s {
	case string(peers.Pending):
		fallthrough
	case string(peers.ConfigRequested):
		fallthrough
	case string(peers.Created):
		fallthrough
	case string(peers.Cancelled):
		return peers.PeerRequestStatus(s), nil
	}
	return peers.Pending, fmt.Errorf("Peer request has invalid status %s", s)
}

func (app *app) newPeerRequest(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	uuid := r.PathValue("uuid")

	dbResult, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			Uuid:             &uuid,
			IncludeCompleted: true,
		})
	}()
	if err != nil {
		return err
	}
	if len(dbResult) == 0 {
		return ErrNotFound
	}
	req, err := newPeerRequestViewFromDB(&dbResult[0])
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(w, "peers/request-page", req)
}

type peersListView struct {
	NewRequests []newPeerRequestView
}

func (app *app) peersList(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	dbReqs, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		app.db.Lock()
		defer app.db.Unlock()
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			Uuid:             nil,
			IncludeCompleted: false,
		})
	}()
	if err != nil {
		return err
	}
	reqs := make([]newPeerRequestView, 0, len(dbReqs))
	for _, dbReq := range dbReqs {
		req, err := newPeerRequestViewFromDB(&dbReq)
		if err != nil {
			return err
		}
		reqs = append(reqs, req)
	}

	return app.tmpl.ExecuteTemplate(w, "peers/list", peersListView{
		NewRequests: reqs,
	})
}

func (app *app) cancelNewPeerRequest(w http.ResponseWriter, r *http.Request) error {
	uuid := r.PathValue("uuid")
	dbRows, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		app.db.Lock()
		defer app.db.Unlock()
		_, err := app.db.CancelNewPeerRequest(r.Context(), uuid)
		if err != nil {
			return nil, err
		}
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			Uuid:             &uuid,
			IncludeCompleted: true,
		})
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else {
			return err
		}
	}
	if len(dbRows) == 0 {
		return ErrNotFound
	}
	req, err := newPeerRequestViewFromDB(&dbRows[0])
	if err != nil {
		return err
	}
	if err := app.tmpl.ExecuteTemplate(w, "peers/request-view", req); err != nil {
		return err
	}
	return app.RenderNotification(w, Notification{Ok: true, Message: "Cancelled"})
}
