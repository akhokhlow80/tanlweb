package main

import "net/http"

type Notification struct {
	Ok bool
	Message string
}

func (app *app) RenderNotification(w http.ResponseWriter, n Notification) error {
	return app.tmpl.ExecuteTemplate(w, "notification", n)
}
