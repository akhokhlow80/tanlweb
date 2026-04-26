package admin

import (
	"akhokhlow80/tanlweb/web"
	"net/http"
)

func (app *App) registerIndexPage(m *http.ServeMux) {
	m.HandleFunc("/{$}", web.FailableHandler(app.standardErrorHandler, app.indexPageHandler))
}

func (app *App) indexPageHandler(w http.ResponseWriter, r *http.Request) error {
	user := getAuthenticateUser(r.Context())
	if user.Scopes.Peers {
		w.Header().Set("Location", app.encryptURI("peers"))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else if user.Scopes.Users {
		w.Header().Set("Location", app.encryptURI("users"))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else if user.Scopes.Nodes {
		w.Header().Set("Location", app.encryptURI("nodes"))
		w.WriteHeader(http.StatusSeeOther)
		return nil
	} else {
		return app.tmpl.ExecuteTemplate(w, "index", nil)
	}
}
