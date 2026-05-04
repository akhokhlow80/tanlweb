package peerconfigs

import (
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/reqlog"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Config struct {
	HTTPBind    string
	TLSDisable  bool
	TLSCertPath string
	TLSKeyPath  string
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

func (app *App) makeTLSConfig() (*tls.Config, error) {
	if app.cfg.TLSDisable {
		return nil, nil
	}

	servCert, err := tls.LoadX509KeyPair(app.cfg.TLSCertPath, app.cfg.TLSKeyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{servCert},
	}, nil
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
			fmt.Sprintf("attachment; filename=\"%s.conf\"", interfaceName),
		)

		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(config.String()))
	})

	tlsConf, err := app.makeTLSConfig()
	if err != nil {
		return fmt.Errorf("Failed to load TLS keypair: %w", err)
	}
	server := http.Server{
		Addr:           app.cfg.HTTPBind,
		Handler:        mux,
		TLSConfig:      tlsConf,
		MaxHeaderBytes: 1 << 13, /* 8 KiB */
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
	}

	log.Printf("Peer configs service is binding to %s", app.cfg.HTTPBind)
	return server.ListenAndServeTLS("", "")
}
