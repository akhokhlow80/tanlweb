package main

import (
	"akhokhlow80/tanlweb/auth"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"database/sql"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

func (app *app) registerNodeHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /nodes/new", web.FailableHandler(app.StandardErrorHandler, app.newNodePage))
	m.HandleFunc("POST /nodes", web.FailableHandler(app.HTMXErrorHandler, app.putNode))
	m.HandleFunc("PUT /nodes/{uuid}", web.FailableHandler(app.HTMXErrorHandler, app.putNode))
	m.HandleFunc("GET /nodes/{uuid}", web.FailableHandler(app.StandardErrorHandler, app.nodePage))
	m.HandleFunc("GET /nodes", web.FailableHandler(app.StandardErrorHandler, app.nodesList))
}

type nodeErrors struct {
	NameEmpty    bool
	BaseURIEmpty bool

	NameNotUnique bool
}

type nodeView struct {
	UUID    string
	Name    string
	BaseURI string

	Peers struct{}
}

func (app *app) newNodePage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: true}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/page", nil)
}

func (app *app) putNode(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: true}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return ErrParseForm
	}

	addNew := r.Method == "POST"

	var nodeUUID string
	if !addNew {
		nodeUUID = r.PathValue("uuid")
	}
	name := web.FormScalar(r.Form, "name")
	baseUri := web.FormScalar(r.Form, "base-uri")

	var validationErrors nodeErrors
	if len(name) == 0 {
		validationErrors.NameEmpty = true
	}
	if len(baseUri) == 0 {
		validationErrors.BaseURIEmpty = true
	}
	if validationErrors.NameEmpty || validationErrors.BaseURIEmpty {
		return app.tmpl.ExecuteTemplate(w, "nodes/invalid", validationErrors)
	}

	var (
		dbNode sqlgen.Node
		err    error
	)
	if addNew {
		dbNode, err = func() (sqlgen.Node, error) {
			defer app.db.Unlock()
			app.db.Lock()
			return app.db.AddNode(r.Context(), sqlgen.AddNodeParams{
				Uuid:    uuid.NewString(),
				Name:    name,
				BaseUri: baseUri,
			})
		}()
		if err != nil {
			if db.IsConstraintErr(err) {
				return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrors{
					NameNotUnique: true,
				})
			} else {
				return err
			}
		}

		if err := app.RenderNotification(w, Notification{Ok: true, Message: "Created"}); err != nil {
			return err
		}

		w.Header().Add("HX-Replace-Url", app.EncryptURI("nodes/"+url.PathEscape(dbNode.Uuid)))
	} else {
		dbNode, err = func() (sqlgen.Node, error) {
			defer app.db.Unlock()
			app.db.Lock()
			return app.db.UpdateNode(r.Context(), sqlgen.UpdateNodeParams{
				Uuid:    nodeUUID,
				Name:    name,
				BaseUri: baseUri,
			})
		}()
		if err != nil {
			if db.IsConstraintErr(err) {
				return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrors{
					NameNotUnique: true,
				})
			} else if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			} else {
				return err
			}
		}

		if err := app.RenderNotification(w, Notification{Ok: true, Message: "Updated"}); err != nil {
			return err
		}
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/view", nodeView{
		UUID:    dbNode.Uuid,
		Name:    dbNode.Name,
		BaseURI: dbNode.BaseUri,
	})
}

func (app *app) nodePage(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: true}); err != nil {
		return err
	}

	uuid := r.PathValue("uuid")
	dbNode, err := func() (sqlgen.Node, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetNodeByUUID(r.Context(), uuid)
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else {
			return err
		}
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/page", nodeView{
		UUID:    dbNode.Uuid,
		Name:    dbNode.Name,
		BaseURI: dbNode.BaseUri,
	})
}

func (app *app) nodesList(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: true}); err != nil {
		return err
	}

	dbNodes, err := func() ([]sqlgen.Node, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetNodes(r.Context())
	}()
	if err != nil {
		return err
	}
	nodes := make([]nodeView, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		node := nodeView{
			UUID:    dbNode.Uuid,
			Name:    dbNode.Name,
			BaseURI: dbNode.BaseUri,
		}
		nodes = append(nodes, node)
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/list", nodes)
}
