package main

import (
	"akhokhlow80/tanlweb/reqlog"
	"errors"
	"net/http"
)

var ErrParseForm = errors.New("Error parsing form")
var ErrNotFound = errors.New("Not found")

func (app *app) StandardErrorHandler(w http.ResponseWriter, r *http.Request, hErr error) {
	var errorView struct {
		Status  int
		Message string
	}

	errorView.Message = hErr.Error()

	switch hErr {
	case ErrParseForm:
		errorView.Status = http.StatusBadRequest
	case ErrNotFound:
		errorView.Status = http.StatusNotFound
	default:
		errorView.Status = http.StatusInternalServerError
		errorView.Message = "Internal server error"
		reqlog.Printf(r, "Internal server error: %s", hErr)
	}

	err := app.tmpl.ExecuteTemplate(w, "error", errorView)
	if err != nil {
		reqlog.Printf(r, "Failed to render error page for %s: %s", hErr, err.Error())
	}
}

func (app *app) HTMXErrorHandler(w http.ResponseWriter, r *http.Request, hErr error) {
	var n Notification
	n.Ok = false
	switch hErr {
	case ErrParseForm:
		fallthrough
	case ErrNotFound:
		n.Message = hErr.Error()
	default:
		n.Message = "Internal server error"
		reqlog.Printf(r, "Internal server error: %s", hErr)
	}
	err := app.RenderNotification(w, n)
	if err != nil {
		reqlog.Printf(r, "Failed to render HTMX error page for %s: %s", hErr, err.Error())
	}
}
