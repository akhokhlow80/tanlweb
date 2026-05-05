package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/admin/users"
	"akhokhlow80/tanlweb/db"
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

func parseUserFromDB(dbUser *sqlgen.User) (users.User, error) {
	var paidUntil time.Time
	if dbUser.PaidUntil != nil {
		paidUntil = *dbUser.PaidUntil
	}
	scopes, err := auth.ParseScopes(dbUser.Scopes)
	if err != nil {
		return users.User{}, fmt.Errorf("User %s has invalid scopes `%s`: %s", dbUser.Name, dbUser.Scopes, err)
	}
	userUUID, err := uuid.Parse(dbUser.Uuid)
	if err != nil {
		return users.User{}, fmt.Errorf("User %s has invalid UUID `%s`", dbUser.Name, dbUser.Uuid)
	}
	profile, parseErrs := users.ParseUserProfile(
		dbUser.Name,
		dbUser.Fee,
		scopes,
	)
	if parseErrs != nil {
		return users.User{}, fmt.Errorf("User %s has invalid profile: %s", dbUser.Name, parseErrs)
	}
	return users.User{
		UUID:      userUUID,
		Profile:   profile,
		PaidUntil: paidUntil,
		IsBanned:  dbUser.IsBanned,
	}, nil
}

func (app *App) addRootUserIfNotExists(ctx context.Context) error {
	defer app.db.RUnlock()
	app.db.RLock()

	dbUsers, err := app.db.GetUsers(ctx)
	if err != nil {
		return err
	}
	if len(dbUsers) == 0 {
		root, parseErrs := users.NewUser(
			"root",
			"",
			auth.FullScope,
		)
		if parseErrs != nil {
			return parseErrs
		}
		_, err := app.db.AddUser(ctx, sqlgen.AddUserParams{
			Uuid:   root.UUID.String(),
			Name:   root.Profile.Name,
			Scopes: root.Profile.Scopes.String(),
			Fee:    root.Profile.Fee,
		})
		if err != nil {
			return fmt.Errorf("Error adding root user: %w", err)
		}
		log.Println("Created user root with full scope")
	}
	return nil
}

func (app *App) registerUsersHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /users/new",
		web.FailableHandler(app.standardErrorHandler, app.newUserPageHandler))
	m.HandleFunc("POST /users",
		web.FailableHandler(app.htmxErrorHandler, app.addUserHandler))
	m.HandleFunc("PUT /users/{uuid}",
		web.FailableHandler(app.htmxErrorHandler, app.updateUserHandler))
	m.HandleFunc("PUT /users/{uuid}/paid-until",
		web.FailableHandler(app.htmxErrorHandler, app.putUserPaidUntilHandler))
	m.HandleFunc("PUT /users/{uuid}/ban",
		web.FailableHandler(app.htmxErrorHandler, app.putUserBanHandler))
	m.HandleFunc("GET /users/{uuid}",
		web.FailableHandler(app.standardErrorHandler, app.userPageHandler))
	m.HandleFunc("GET /users",
		web.FailableHandler(app.standardErrorHandler, app.usersListHandler))
}

type userOwnedPeers struct {
	Peers               []nodes.PeerFromNode
	PeersRetrievalError error
	PendingPeerRequests []peers.PeerRequest
}

type singleUserView struct {
	users.User
	New           bool
	Owned         *userOwnedPeers
	R             *http.Request
	ConstTimeZero time.Time
}

func (app *App) newUserPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "users/page", singleUserView{New: true, R: r})
}

func readFormScopes(r *http.Request) auth.Scopes {
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
	return scopes
}

type userErrorsView struct {
	users.UserProfileParseErrors
	NameNotUnique bool
}

func (app *App) addUserHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	name := web.FormScalar(r.Form, "name")
	fee := web.FormTrimmedScalar(r.Form, "fee")
	scopes := readFormScopes(r)
	user, parseErrs := users.NewUser(name, fee, scopes)
	if parseErrs != nil {
		return app.tmpl.ExecuteTemplate(w, "users/invalid", userErrorsView{
			UserProfileParseErrors: *parseErrs,
		})
	}

	dbUser, err := func() (sqlgen.User, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.AddUser(r.Context(), sqlgen.AddUserParams{
			Uuid:   user.UUID.String(),
			Name:   user.Profile.Name,
			Scopes: user.Profile.Scopes.String(),
			Fee:    user.Profile.Fee,
		})
	}()
	if err != nil {
		if db.IsConstraintErr(err) {
			return app.tmpl.ExecuteTemplate(w, "users/invalid", userErrorsView{
				NameNotUnique: true,
			})
		} else {
			return err
		}
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: "Created"}); err != nil {
		return err
	}

	w.Header().Add("HX-Replace-Url", app.encryptURI("users/"+url.PathEscape(dbUser.Uuid)))

	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			User:  user,
			R:     r,
			Owned: &userOwnedPeers{},
		},
	)
}

func (app *App) updateUserHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	userUUID := r.PathValue("uuid")

	name := web.FormScalar(r.Form, "name")
	fee := web.FormTrimmedScalar(r.Form, "fee")
	scopes := readFormScopes(r)
	profile, parseErrs := users.ParseUserProfile(name, fee, scopes)
	if parseErrs != nil {
		return app.tmpl.ExecuteTemplate(w, "users/invalid", userErrorsView{
			UserProfileParseErrors: *parseErrs,
		})
	}
	dbUser, err := func() (sqlgen.User, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.UpdateUser(r.Context(), sqlgen.UpdateUserParams{
			Name:   profile.Name,
			Scopes: profile.Scopes.String(),
			Fee:    profile.Fee,
			Uuid:   userUUID,
		})
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else if db.IsConstraintErr(err) {
			return app.tmpl.ExecuteTemplate(w, "users/invalid", userErrorsView{
				NameNotUnique: true,
			})
		} else {
			return err
		}
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: "Updated"}); err != nil {
		return err
	}

	user, err := parseUserFromDB(&dbUser)
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			User: user,
			R:    r,
		},
	)
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

	user, err := parseUserFromDB(&dbUser)
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			User: user,
			R:    r,
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

	user, err := parseUserFromDB(&dbUser)
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"users/view",
		singleUserView{
			R:    r,
			User: user,
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
		user, err := app.db.GetUserByUUID(r.Context(), userUuid)
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
	user, err := parseUserFromDB(&dbUser)
	if err != nil {
		return err
	}
	return app.tmpl.ExecuteTemplate(
		w,
		"users/page",
		singleUserView{
			User: user,
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
	Users []users.User
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
	users := make([]users.User, 0, len(dbUsers))
	for _, dbUser := range dbUsers {
		user, err := parseUserFromDB(&dbUser)
		if err != nil {
			return err
		}
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
