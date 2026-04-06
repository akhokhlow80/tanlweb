package main

import (
	"akhokhlow80/tanlweb/auth"
	"akhokhlow80/tanlweb/scopes"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func (app *app) registerUsersHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /users/new", web.FailableHandler(app.StandardErrorHandler, app.newUserPage))
	m.HandleFunc("POST /users", web.FailableHandler(app.HTMXErrorHandler, app.putUser))
	m.HandleFunc("PUT /users/{uuid}", web.FailableHandler(app.HTMXErrorHandler, app.putUser))
	m.HandleFunc("PUT /users/{uuid}/paid-until", web.FailableHandler(app.HTMXErrorHandler, app.putUserPaidUntil))
	m.HandleFunc("PUT /users/{uuid}/ban", web.FailableHandler(app.HTMXErrorHandler, app.putUserBan))
	m.HandleFunc("GET /users/{uuid}", web.FailableHandler(app.StandardErrorHandler, app.userPage))
	m.HandleFunc("GET /users", web.FailableHandler(app.StandardErrorHandler, app.usersList))
}

type userView struct {
	UUID        string
	Description string
	Fee         string
	Scopes      scopes.Scopes
	PaidUntil   string
	IsBanned    bool
}

func userViewFromDB(dbUser *sqlgen.User) userView {
	var paidUntil string
	if dbUser.PaidUntil != nil {
		paidUntil = dbUser.PaidUntil.Format("2006-01-02")
	}
	scopes, err := scopes.Parse(dbUser.Scopes)
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

func (app *app) newUserPage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: true}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "users/page", nil)
}

func (app *app) putUser(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return ErrParseForm
	}

	addNew := r.Method == "POST"

	var userUUID string
	if !addNew {
		userUUID = r.PathValue("uuid")
	}
	description := web.FormScalar(r.Form, "description")
	fee := web.FormTrimmedScalar(r.Form, "fee")
	var scopes scopes.Scopes
	if web.FormTrimmedScalar(r.Form, "scope-users") == "on" {
		scopes.Users = true
	}
	if web.FormTrimmedScalar(r.Form, "scope-nodes") == "on" {
		scopes.Nodes = true
	}
	if web.FormTrimmedScalar(r.Form, "scope-peers") == "on" {
		scopes.Peers = true
	}

	var (
		dbUser sqlgen.User
		err    error
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

		if err := app.RenderNotification(w, Notification{Ok: true, Message: "Created"}); err != nil {
			return err
		}

		w.Header().Add("HX-Replace-Url", fmt.Sprintf("%s/users/%s", app.cfg.BaseURI, dbUser.Uuid))
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
				return ErrNotFound
			} else {
				return err
			}
		}

		if err := app.RenderNotification(w, Notification{Ok: true, Message: "Updated"}); err != nil {
			return err
		}
	}

	return app.tmpl.ExecuteTemplate(w, "users/view", userViewFromDB(&dbUser))
}

func (app *app) putUserPaidUntil(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: true}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return ErrParseForm
	}

	paidUntilStr := web.FormScalar(r.Form, "paid-until")
	paidUntil, err := time.ParseInLocation("2006-01-02 15:04:05", paidUntilStr+" 23:49:59", time.Local)
	if err != nil {
		return app.RenderNotification(w, Notification{
			Ok:      false,
			Message: "Set a valid date",
		})
	}

	// TODO: change status to active if was suspended

	dbUser, err := app.db.UpdateUserPaidUntil(r.Context(), sqlgen.UpdateUserPaidUntilParams{
		PaidUntil: &paidUntil,
		Uuid:      r.PathValue("uuid"),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else {
			return err
		}
	}

	if err := app.RenderNotification(w, Notification{Ok: true, Message: "Updated"}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "users/view", userViewFromDB(&dbUser))
}

func (app *app) putUserBan(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: true}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return ErrParseForm
	}

	ban := web.FormScalar(r.Form, "ban") == "true"

	dbUser, err := app.db.BanUser(r.Context(), sqlgen.BanUserParams{
		Banned: ban,
		Uuid:   r.PathValue("uuid"),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
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

	if err := app.RenderNotification(w, Notification{Ok: true, Message: msg}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "users/view", userViewFromDB(&dbUser))
}

func (app *app) userPage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: true}); err != nil {
		return err
	}

	uuid := r.PathValue("uuid")
	dbUser, err := func() (sqlgen.User, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetUser(r.Context(), uuid)
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else {
			return err
		}
	}
	return app.tmpl.ExecuteTemplate(w, "users/page", userViewFromDB(&dbUser))
}

func (app *app) usersList(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Users: true}); err != nil {
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
	return app.tmpl.ExecuteTemplate(w, "users/list", users)
}
