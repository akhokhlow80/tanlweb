package admin

import "net/http"

type notification struct {
	Ok      bool
	Message string
}

func (app *App) renderNotification(w http.ResponseWriter, n notification) error {
	return app.tmpl.ExecuteTemplate(w, "notification", n)
}

func (app *App) renderError(w http.ResponseWriter, msg string) error {
	return app.renderNotification(w, notification{Ok: false, Message: msg})
}

func (app *App) renderSuccess(w http.ResponseWriter, msg string) error {
	return app.renderNotification(w, notification{Ok: true, Message: msg})
}
