package admin

import "net/http"

type NavigationParams struct {
	R        *http.Request
	Resource string
}

// To be called from templates
func makeNavigationParams(r *http.Request, resource string) NavigationParams {
	return NavigationParams{
		R:        r,
		Resource: resource,
	}
}
