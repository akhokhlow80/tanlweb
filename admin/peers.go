package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// TODO: handle config request

func (app *App) registerPeerHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /users/{user_uuid}/peers/new", web.FailableHandler(app.standardErrorHandler, app.newPeerPage))
	m.HandleFunc("GET /peers", web.FailableHandler(app.standardErrorHandler, app.peersList))
	m.HandleFunc("POST /peers", web.FailableHandler(app.htmxErrorHandler, app.addPeer))
	m.HandleFunc("GET /peers/requests/{random_id}", web.FailableHandler(app.standardErrorHandler, app.newPeerRequest))
	m.HandleFunc("POST /peers/requests/{random_id}/cancel", web.FailableHandler(app.standardErrorHandler, app.cancelNewPeerRequest))
}

type newPeerNodeSelectOption struct {
	UUID string
	Name string
}

type newPeerPageView struct {
	UserUUID string
	Nodes    []newPeerNodeSelectOption
}

func (app *App) newPeerPage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
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
		UserUUID: userUUID,
		Nodes:    nodes,
	})
}

type peerErrors struct {
	NodeUUIDEmpty        bool
	InvalidInterfaceName bool
}

var wgInterfaceNameRegexp = regexp.MustCompile(`[a-zA-Z0-9_=+.-]{1,15}`)

func (app *App) addPeer(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	var randomIDBytes [32]byte
	if _, err := rand.Read(randomIDBytes[:]); err != nil {
		panic(err)
	}
	randomID := base64.RawURLEncoding.EncodeToString(randomIDBytes[:])

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
				return errNotFound
			} else {
				return err
			}
		}
		node, err := app.db.GetNodeByUUID(ctx, nodeUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errNotFound
			} else {
				return err
			}
		}
		return app.db.CreateNewPeerRequest(r.Context(), sqlgen.CreateNewPeerRequestParams{
			RandomID:            randomID,
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

	w.Header().Set("HX-Redirect", app.encryptURI("peers/requests/"+randomID))

	return nil
}

type newPeerRequestView struct {
	RandomID            string
	ShortRandomID       string
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
		RandomID:            dbReq.RandomID,
		ShortRandomID:       dbReq.RandomID[31:],
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

func (app *App) newPeerRequest(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	randomID := r.PathValue("random_id")

	dbResult, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			RandomID:         &randomID,
			IncludeCompleted: true,
		})
	}()
	if err != nil {
		return err
	}
	if len(dbResult) == 0 {
		return errNotFound
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

func (app *App) peersList(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	dbReqs, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		app.db.Lock()
		defer app.db.Unlock()
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			RandomID:         nil,
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

func (app *App) cancelNewPeerRequest(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: true}); err != nil {
		return err
	}

	randomID := r.PathValue("random_id")

	dbRows, err := func() ([]sqlgen.GetNewPeerRequestsRow, error) {
		app.db.Lock()
		defer app.db.Unlock()
		_, err := app.db.CancelNewPeerRequest(r.Context(), randomID)
		if err != nil {
			return nil, err
		}
		return app.db.GetNewPeerRequests(r.Context(), sqlgen.GetNewPeerRequestsParams{
			RandomID:         &randomID,
			IncludeCompleted: true,
		})
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}
	if len(dbRows) == 0 {
		return errNotFound
	}
	req, err := newPeerRequestViewFromDB(&dbRows[0])
	if err != nil {
		return err
	}
	if err := app.tmpl.ExecuteTemplate(w, "peers/request-view", req); err != nil {
		return err
	}
	return app.renderNotification(w, notification{Ok: true, Message: "Cancelled"})
}
