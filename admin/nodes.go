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

type nodeErrorsView struct {
	nodes.NodeParseErrors
	NameNotUnique bool
}

type nodeView struct {
	nodes.Node
}

type singleNodeView struct {
	R   *http.Request
	New bool
	nodeView
}

func (app *App) newNodePageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.W}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/page", singleNodeView{
		New: true,
		R:   r,
	})
}

func (app *App) addNodeHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Nodes: auth.W}); err != nil {
		return err
	}

	if err := r.ParseForm(); err != nil {
		return errParseForm
	}

	node, parseErrs := nodes.ParseNode(
		uuid.NewString(),
		web.FormTrimmedScalar(r.Form, "base-url"),
		web.FormTrimmedScalar(r.Form, "name"),
		web.FormTrimmedScalar(r.Form, "allowed-ips"),
		nodes.TLSClientConfig{
			ClientKey:  web.FormTrimmedScalar(r.Form, "tls-client-key"),
			ClientCert: web.FormTrimmedScalar(r.Form, "tls-client-cert"),
			ServerCert: web.FormTrimmedScalar(r.Form, "tls-server-cert"),
		},
	)
	if parseErrs != nil {
		return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrorsView{
			NodeParseErrors: *parseErrs,
		})
	}

	_, err := func() (sqlgen.Node, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.AddNode(r.Context(), sqlgen.AddNodeParams{
			Uuid:          node.UUID.String(),
			Name:          node.Name,
			BaseUrl:       node.BaseURL.String(),
			TlsClientKey:  node.TLSConf.ClientKey,
			TlsClientCert: node.TLSConf.ClientCert,
			TlsServerCert: node.TLSConf.ServerCert,
			AllowedIps:    node.AllowedIPs.String(),
		})
	}()
	if err != nil {
		if db.IsConstraintErr(err) {
			return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrorsView{
				NameNotUnique: true,
			})
		} else {
			return err
		}
	}

	app.nodeClients.Put(nodes.NewClient(node))

	w.Header().Add("HX-Replace-Url", app.encryptURI("nodes/"+url.PathEscape(node.UUID.String())))

	err = app.tmpl.ExecuteTemplate(w, "nodes/view", singleNodeView{
		R:   r,
		New: false,
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

	node, parseErrs := nodes.ParseNode(
		r.PathValue("uuid"),
		web.FormTrimmedScalar(r.Form, "base-url"),
		web.FormTrimmedScalar(r.Form, "name"),
		web.FormTrimmedScalar(r.Form, "allowed-ips"),
		nodes.TLSClientConfig{
			ClientKey:  web.FormTrimmedScalar(r.Form, "tls-client-key"),
			ClientCert: web.FormTrimmedScalar(r.Form, "tls-client-cert"),
			ServerCert: web.FormTrimmedScalar(r.Form, "tls-server-cert"),
		},
	)
	if parseErrs != nil {
		return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrorsView{
			NodeParseErrors: *parseErrs,
		})
	}

	dbNode, err := func() (sqlgen.Node, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.UpdateNode(r.Context(), sqlgen.UpdateNodeParams{
			Uuid:          node.UUID.String(),
			Name:          node.Name,
			BaseUrl:       node.BaseURL.String(),
			TlsClientKey:  node.TLSConf.ClientKey,
			TlsClientCert: node.TLSConf.ClientCert,
			TlsServerCert: node.TLSConf.ServerCert,
			AllowedIps:    node.AllowedIPs.String(),
		})
	}()
	if err != nil {
		if db.IsConstraintErr(err) {
			return app.tmpl.ExecuteTemplate(w, "nodes/invalid", nodeErrorsView{
				NameNotUnique: true,
			})
		} else if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		} else {
			return err
		}
	}

	node, parseErrs = nodes.ParseNode(
		dbNode.Uuid,
		dbNode.BaseUrl,
		dbNode.Name,
		dbNode.AllowedIps,
		nodes.TLSClientConfig{
			ClientKey:  dbNode.TlsClientKey,
			ClientCert: dbNode.TlsClientCert,
			ServerCert: dbNode.TlsServerCert,
		},
	)
	if parseErrs != nil {
		return parseErrs
	}

	client := app.nodeClients.GetClient(node.UUID.String())
	if client == nil {
		// impossible
		return fmt.Errorf("No client found for node %s", node.UUID)
	} else {
		client.Update(node)
	}

	if err := app.renderNotification(w, notification{Ok: true, Message: "Updated"}); err != nil {
		return err
	}

	return app.tmpl.ExecuteTemplate(w, "nodes/view", singleNodeView{
		R:   r,
		New: false,
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
	node, parseErrs := nodes.ParseNode(
		dbNode.Uuid,
		dbNode.BaseUrl,
		dbNode.Name,
		dbNode.AllowedIps,
		nodes.TLSClientConfig{
			ClientKey:  dbNode.TlsClientKey,
			ClientCert: dbNode.TlsClientCert,
			ServerCert: dbNode.TlsServerCert,
		},
	)
	if parseErrs != nil {
		return parseErrs
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/page", singleNodeView{
		R:        r,
		New:      false,
		nodeView: nodeView{node},
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
		node, parseErrs := nodes.ParseNode(
			dbNode.Uuid,
			dbNode.BaseUrl,
			dbNode.Name,
			dbNode.AllowedIps,
			nodes.TLSClientConfig{
				ClientKey:  dbNode.TlsClientKey,
				ClientCert: dbNode.TlsClientCert,
				ServerCert: dbNode.TlsServerCert,
			},
		)
		if parseErrs != nil {
			return parseErrs
		}
		nodeViews = append(nodeViews, nodeView{node})
	}
	return app.tmpl.ExecuteTemplate(w, "nodes/list", nodesListView{
		R:     r,
		Nodes: nodeViews,
	})
}
