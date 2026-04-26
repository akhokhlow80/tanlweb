package admin

import "net/http"

type notification struct {
	Ok bool
	Message string
}

func (app *App) renderNotification(w http.ResponseWriter, n notification) error {
	return app.tmpl.ExecuteTemplate(w, "notification", n)
}
