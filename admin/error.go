package admin

import (
	"akhokhlow80/tanlweb/reqlog"
	"errors"
	"net/http"
)

var errParseForm = errors.New("Error parsing form")
var errNotFound = errors.New("Not found")
var errUnauthorized = errors.New("Unauthorized")
var errForbidden = errors.New("Access Denied")

func (app *App) standardErrorHandler(w http.ResponseWriter, r *http.Request, hErr error) {
	var errorView struct {
		Status  int
		Message string
	}

	errorView.Message = hErr.Error()

	switch hErr {
	case errParseForm:
		errorView.Status = http.StatusBadRequest
	case errNotFound:
		errorView.Status = http.StatusNotFound
	case errUnauthorized:
		errorView.Status = http.StatusUnauthorized
	case errForbidden:
		errorView.Status = http.StatusForbidden
	default:
		errorView.Status = http.StatusInternalServerError
		errorView.Message = "Internal server error"
		reqlog.Printf(r, "Internal server error: %s", hErr)
	}

	w.WriteHeader(errorView.Status)

	err := app.tmpl.ExecuteTemplate(w, "error", errorView)
	if err != nil {
		reqlog.Printf(r, "Failed to render error page for %s: %s", hErr, err.Error())
	}
}

func (app *App) htmxErrorHandler(w http.ResponseWriter, r *http.Request, hErr error) {
	var n notification
	n.Ok = false
	switch hErr {
	case errParseForm:
		n.Message = hErr.Error()
	case errNotFound:
		n.Message = hErr.Error()
	case errUnauthorized:
		w.WriteHeader(http.StatusUnauthorized)
		n.Message = hErr.Error()
	case errForbidden:
		w.WriteHeader(http.StatusForbidden)
		n.Message = hErr.Error()
	default:
		n.Message = "Internal server error"
		reqlog.Printf(r, "Internal server error: %s", hErr)
	}
	err := app.renderNotification(w, n)
	if err != nil {
		reqlog.Printf(r, "Failed to render HTMX error page for %s: %s", hErr, err.Error())
	}
}
