package main

import (
	"akhokhlow80/tanlweb/web"
	"fmt"
	"net/http"
)

func (app *app) registerIndexPage(m *http.ServeMux) {
	m.HandleFunc("/{$}", web.FailableHandler(app.StandardErrorHandler, app.indexPageHandler))
}

func (app *app) indexPageHandler(w http.ResponseWriter, r *http.Request) error {
	user := getAuthenticateUser(r.Context())
	if user.Scopes.Peers {
		w.Header().Set("Location", fmt.Sprintf("%s/peers", app.cfg.BaseURI))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else if user.Scopes.Users {
		w.Header().Set("Location", fmt.Sprintf("%s/users", app.cfg.BaseURI))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else if user.Scopes.Nodes {
		w.Header().Set("Location", fmt.Sprintf("%s/nodes", app.cfg.BaseURI))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else {
		return app.tmpl.ExecuteTemplate(w, "index", nil)
	}
}
