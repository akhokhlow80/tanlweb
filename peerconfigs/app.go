package peerconfigs

import (
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/reqlog"
	"fmt"
	"log"
	"net/http"
)

type Config struct {
	HTTPBind string
}

type App struct {
	cfg          Config
	peerReqCache *peers.PendingRequestsCache
}

func NewApp(cfg Config, peerReqCache *peers.PendingRequestsCache) *App {
	return &App{
		cfg:          cfg,
		peerReqCache: peerReqCache,
	}
}

func (app *App) Serve() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/{random_id}", func(w http.ResponseWriter, r *http.Request) {
		randomID := r.PathValue("random_id")
		req, ok := app.peerReqCache.Pop(randomID)
		if !ok {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		config, _, interfaceName, err := req.Complete(r.Context())
		if err != nil {
			reqlog.Printf(r, "Internal server error: %s", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Add(
			"Content-Disposition",
			fmt.Sprintf("inline; filename=\"%s.conf\"", interfaceName),
		)

		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(config.String()))
	})
	log.Printf("Peer configs service is binding to %s", app.cfg.HTTPBind)
	return http.ListenAndServe(app.cfg.HTTPBind, mux)
}
