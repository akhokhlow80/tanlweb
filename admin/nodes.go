package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/nodes"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

func (app *App) registerNodeHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /nodes/new",
		web.FailableHandler(app.standardErrorHandler, app.newNodePageHandler))
	m.HandleFunc("POST /nodes",
		web.FailableHandler(app.htmxErrorHandler, app.addNodeHandler))
	m.HandleFunc("PUT /nodes/{uuid}",
		web.FailableHandler(app.htmxErrorHandler, app.updateNodeHandler))
	m.HandleFunc("GET /nodes/{uuid}",
		web.FailableHandler(app.standardErrorHandler, app.nodePageHandler))
	m.HandleFunc("GET /nodes",
		web.FailableHandler(app.standardErrorHandler, app.nodesListHandler))
}

type nodeErrors struct {
	NameEmpty    bool
	BaseURIEmpty bool

	NameNotUnique bool
}

func (errs *nodeErrors) Ok() bool {
	return !(errs.NameEmpty || errs.BaseURIEmpty || errs.NameNotUnique)
}

type nodeView struct {
	Node nodes.Node
}

type nodeViewWithHTTPReq struct {
	R *http.Request
	nodeView
}

func (app *App) newNodePageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.W}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/page", nil)
}

func validateNodeForm(node *nodes.Node) nodeErrors {
	var validationErrors nodeErrors
	if len(node.Name) == 0 {
		validationErrors.NameEmpty = true
	}
	if len(node.BaseURI) == 0 {
		validationErrors.BaseURIEmpty = true
	}
	return validationErrors
}

func (app *App) addNodeHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	node := nodes.Node{
		UUID:    uuid.NewString(),
		BaseURI: web.FormTrimmedScalar(r.Form, "base-uri"),
		Name:    web.FormTrimmedScalar(r.Form, "name"),
	}
	validationErrors := validateNodeForm(&node)
	if !validationErrors.Ok() {
		return app.tmpl.ExecuteTemplate(w, "nodes/invalid", validationErrors)
	}

	_, err := func() (sqlgen.Node, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.AddNode(r.Context(), sqlgen.AddNodeParams{
			Uuid:    node.UUID,
			Name:    node.Name,
			BaseUri: node.BaseURI,
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

	app.nodeClients.Put(nodes.NewClient(node))

	w.Header().Add("HX-Replace-Url", app.encryptURI("nodes/"+url.PathEscape(node.UUID)))

	err = app.tmpl.ExecuteTemplate(w, "nodes/view", nodeViewWithHTTPReq{
		R: r,
		nodeView: nodeView{
			Node: node,
		},
	})
	if err != nil {
		return err
	}

	return app.renderSuccess(w, "Created")
}

func (app *App) updateNodeHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	node := nodes.Node{
		UUID:    r.PathValue("uuid"),
		BaseURI: web.FormTrimmedScalar(r.Form, "base-uri"),
		Name:    web.FormTrimmedScalar(r.Form, "name"),
	}
	validationErrors := validateNodeForm(&node)
	if !validationErrors.Ok() {
		return app.tmpl.ExecuteTemplate(w, "nodes/invalid", validationErrors)
	}

	dbNode, err := func() (sqlgen.Node, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.UpdateNode(r.Context(), sqlgen.UpdateNodeParams{
			Uuid:    node.UUID,
			Name:    node.Name,
			BaseUri: node.BaseURI,
		})
	}()
	if err != nil {
		if db.IsConstraintErr(err) {
			return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrors{
				NameNotUnique: true,
			})
		} else if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}

	node = nodes.Node{
		UUID:    dbNode.Uuid,
		BaseURI: dbNode.BaseUri,
		Name:    dbNode.Name,
	}

	client := app.nodeClients.GetClient(node.UUID)
	if client == nil {
		// impossible
		return fmt.Errorf("No client found for node %s", node.UUID)
	} else {
		client.Update(node)
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: "Updated"}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/view", nodeViewWithHTTPReq{
		R: r,
		nodeView: nodeView{
			Node: node,
		},
	})
}

func (app *App) nodePageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.R}); err != nil {
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
			return errNotFound
		} else {
			return err
		}
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/page", nodeViewWithHTTPReq{
		R: r,
		nodeView: nodeView{
			Node: nodes.Node{
				UUID:    dbNode.Uuid,
				Name:    dbNode.Name,
				BaseURI: dbNode.BaseUri,
			},
		},
	})
}

type nodesListView struct {
	R     *http.Request
	Nodes []nodeView
}

func (app *App) nodesListHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.R}); err != nil {
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
	nodeViews := make([]nodeView, 0, len(dbNodes))
	for _, dbNode := range dbNodes {
		node := nodeView{
			Node: nodes.Node{
				UUID:    dbNode.Uuid,
				Name:    dbNode.Name,
				BaseURI: dbNode.BaseUri,
			},
		}
		nodeViews = append(nodeViews, node)
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/list", nodesListView{
		R:     r,
		Nodes: nodeViews,
	})
}
