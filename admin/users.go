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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func (app *App) addRootUserIfNotExists(ctx context.Context) error {
	defer app.db.RUnlock()
	app.db.RLock()

	users, err := app.db.GetUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		user, err := app.db.AddUser(ctx, sqlgen.AddUserParams{
			Uuid:        uuid.New().String(),
			Description: "root",
			Scopes:      auth.FullScope.String(),
		})
		if err != nil {
			return fmt.Errorf("Error adding root user: %w", err)
		}
		log.Printf("Created root user %s with full scope", user.Uuid)
	}
	return nil
}

func (app *App) registerUsersHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /users/new",
		web.FailableHandler(app.standardErrorHandler, app.newUserPageHandler))
	m.HandleFunc("POST /users",
		web.FailableHandler(app.htmxErrorHandler, app.putUserHandler))
	m.HandleFunc("PUT /users/{uuid}",
		web.FailableHandler(app.htmxErrorHandler, app.putUserHandler))
	m.HandleFunc("PUT /users/{uuid}/paid-until",
		web.FailableHandler(app.htmxErrorHandler, app.putUserPaidUntilHandler))
	m.HandleFunc("PUT /users/{uuid}/ban",
		web.FailableHandler(app.htmxErrorHandler, app.putUserBanHandler))
	m.HandleFunc("GET /users/{uuid}",
		web.FailableHandler(app.standardErrorHandler, app.userPageHandler))
	m.HandleFunc("GET /users",
		web.FailableHandler(app.standardErrorHandler, app.usersListHandler))
}

type userView struct {
	UUID        string
	Description string
	Fee         string
	Scopes      auth.Scopes
	PaidUntil   string
	IsBanned    bool
}

type userOwnedPeers struct {
	Peers               []nodes.PeerFromNode
	PeersRetrievalError error
	PendingPeerRequests []peers.PeerRequest
}

type singleUserView struct {
	userView
	Owned *userOwnedPeers
	R     *http.Request
}

func userViewFromDB(dbUser *sqlgen.User) userView {
	var paidUntil string
	if dbUser.PaidUntil != nil {
		paidUntil = dbUser.PaidUntil.Format("2006-01-02")
	}
	scopes, err := auth.ParseScopes(dbUser.Scopes)
	if err != nil {
		log.Printf("Failed to parse scopes `%s` from DB of user `%s`: %s", dbUser.Scopes, dbUser.Uuid, err)
	}
	return userView{
		UUID:        dbUser.Uuid,
		Description: dbUser.Description,
		Fee:         dbUser.Fee,
		Scopes:      scopes,
		PaidUntil:   paidUntil,
		IsBanned:    dbUser.IsBanned,
	}
}

func (app *App) newUserPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "users/page", singleUserView{R: r})
}

func (app *App) putUserHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	addNew := r.Method == "POST"

	var userUUID string
	if !addNew {
		userUUID = r.PathValue("uuid")
	}
	description := web.FormScalar(r.Form, "description")
	fee := web.FormTrimmedScalar(r.Form, "fee")
	var scopes auth.Scopes
	if web.FormTrimmedScalar(r.Form, "scope-users-read") == "on" {
		scopes.Users |= auth.R
	}
	if web.FormTrimmedScalar(r.Form, "scope-users-write") == "on" {
		scopes.Users |= auth.W
	}
	if web.FormTrimmedScalar(r.Form, "scope-nodes-read") == "on" {
		scopes.Nodes |= auth.R
	}
	if web.FormTrimmedScalar(r.Form, "scope-nodes-write") == "on" {
		scopes.Nodes |= auth.W
	}
	if web.FormTrimmedScalar(r.Form, "scope-peers-read") == "on" {
		scopes.Peers |= auth.R
	}
	if web.FormTrimmedScalar(r.Form, "scope-peers-write") == "on" {
		scopes.Peers |= auth.W
	}

	var (
		dbUser     sqlgen.User
		ownedPeers *userOwnedPeers
		err        error
	)
	if addNew {
		dbUser, err = func() (sqlgen.User, error) {
			defer app.db.Unlock()
			app.db.Lock()
			return app.db.AddUser(r.Context(), sqlgen.AddUserParams{
				Uuid:        uuid.NewString(),
				Description: description,
				Scopes:      scopes.String(),
				Fee:         fee,
			})
		}()
		if err != nil {
			return err
		}

		if err := app.renderNotification(w, notification{Ok: true, Message: "Created"}); err != nil {
			return err
		}

		w.Header().Add("HX-Replace-Url", app.encryptURI("users/"+url.PathEscape(dbUser.Uuid)))

		ownedPeers = &userOwnedPeers{
			Peers:               nil,
			PeersRetrievalError: nil,
			PendingPeerRequests: nil,
		}
	} else {
		dbUser, err = func() (sqlgen.User, error) {
			defer app.db.Unlock()
			app.db.Lock()
			return app.db.UpdateUser(r.Context(), sqlgen.UpdateUserParams{
				Description: description,
				Scopes:      scopes.String(),
				Fee:         fee,
				Uuid:        userUUID,
			})
		}()
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errNotFound
			} else {
				return err
			}
		}

		if err := app.renderNotification(w, notification{Ok: true, Message: "Updated"}); err != nil {
			return err
		}
	}

	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			R:        r,
			Owned:    ownedPeers,
			userView: userViewFromDB(&dbUser),
		})
}

func (app *App) putUserPaidUntilHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	paidUntilStr := web.FormScalar(r.Form, "paid-until")
	paidUntil, err := time.ParseInLocation("2006-01-02 15:04:05", paidUntilStr+" 23:49:59", time.Local)
	if err != nil {
		return app.renderNotification(w, notification{
			Ok:      false,
			Message: "Set a valid date",
		})
	}

	// TODO: change status to active if was suspended

	dbUser, err := func() (sqlgen.User, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.UpdateUserPaidUntil(r.Context(), sqlgen.UpdateUserPaidUntilParams{
			PaidUntil: &paidUntil,
			Uuid:      r.PathValue("uuid"),
		})
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: "Updated"}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			userView: userViewFromDB(&dbUser),
			Owned:    nil,
			R:        r,
		},
	)
}

func (app *App) putUserBanHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	ban := web.FormScalar(r.Form, "ban") == "true"

	dbUser, err := func() (sqlgen.User, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.BanUser(r.Context(), sqlgen.BanUserParams{
			Banned: ban,
			Uuid:   r.PathValue("uuid"),
		})
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}

	// TODO: disable/enable owned peers.

	var msg string
	if dbUser.IsBanned {
		msg = "Banned"
	} else {
		msg = "Unbanned"
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: msg}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			R:        r,
			Owned:    nil,
			userView: userViewFromDB(&dbUser),
		},
	)
}

func (app *App) userPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.R}); err != nil {
		return err
	}

	userUuid := r.PathValue("uuid")
	dbUser, dbReqs, err := func() (sqlgen.User, []sqlgen.GetUncompletedPeerRequestsForUserRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		user, err := app.db.GetUser(r.Context(), userUuid)
		if err != nil {
			return sqlgen.User{}, nil, err
		}
		dbReqs, err := app.db.GetUncompletedPeerRequestsForUser(r.Context(), userUuid)
		if err != nil {
			return sqlgen.User{}, nil, err
		}
		return user, dbReqs, nil
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}
	reqs := make([]peers.PeerRequest, 0, len(dbReqs))
	for _, dbReq := range dbReqs {
		req, err := parsePeerRequestFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
		if err != nil {
			return err
		}
		reqs = append(reqs, req)
	}

	peers, errsByNode := app.nodeClients.GetUserPeers(r.Context(), userUuid)

	return app.tmpl.ExecuteTemplate(
		w,
		"users/page",
		singleUserView{
			userView: userViewFromDB(&dbUser),
			Owned: &userOwnedPeers{
				Peers:               peers,
				PeersRetrievalError: errsByNode.Error(),
				PendingPeerRequests: reqs,
			},
			R: r,
		},
	)
}

type usersListView struct {
	R     *http.Request
	Users []userView
}

func (app *App) usersListHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.R}); err != nil {
		return err
	}

	dbUsers, err := func() ([]sqlgen.User, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetUsers(r.Context())
	}()
	if err != nil {
		return err
	}
	users := make([]userView, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		user := userViewFromDB(&dbUser)
		users = append(users, user)
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"users/list",
		usersListView{
			R:     r,
			Users: users,
		},
	)
}
