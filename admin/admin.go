package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/admin/reqencrypt"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/nodes"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type App struct {
	cfg          Config
	db           *db.DB
	peerReqCache *peers.PendingRequestsCache
	reqCipher    *reqencrypt.Cipher
	tmpl         *template.Template
	auth         *auth.Service
	nodeClients  *nodes.MultiClient
}

var (
	//go:embed html/*
	htmlTemplates embed.FS
	//go:embed static/*
	staticFiles embed.FS
)

func (app *App) initReqCipher() error {
	var err error
	reqkeystore := requestEncryptionKeyStore{app.db}
	app.reqCipher, err = reqencrypt.NewCipher(
		context.Background(),
		&reqkeystore,
		time.Duration(app.cfg.RequestKeyRotationInterval)*time.Second,
	)
	return err
}

func (app *App) initTmpl() error {
	templateFuncs := map[string]any{
		"ShortenUUID": func(uuidStr string) string {
			if len(uuidStr) > 24 {
				return uuidStr[24:]
			} else {
				return uuidStr
			}
		},
		"EncryptURI": func(pathFormat string, values ...string) string {
			anyValues := make([]any, len(values))
			for i, value := range values {
				anyValues[i] = url.PathEscape(value)
			}
			return app.encryptURI(fmt.Sprintf(pathFormat, anyValues...))
		},
		"AuthUser": func(r *http.Request) auth.Subject {
			return *getAuthenticatedUser(r.Context())
		},
		"NavParams": makeNavigationParams,
		"FormatDate": func(t time.Time) string {
			return t.Format("2006-01-02")
		},
	}
	app.tmpl = template.New("").Funcs(templateFuncs)
	htmlFS, err := fs.Sub(htmlTemplates, "html")
	if err != nil {
		return err
	}
	return fs.WalkDir(htmlFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		t := app.tmpl.New(strings.TrimSuffix(path, ".tmpl.html"))
		text, err := fs.ReadFile(htmlFS, path)
		if err != nil {
			return err
		}
		if _, err := t.Parse(string(text)); err != nil {
			return err
		}
		return nil
	})
}

func (app *App) initAuth() error {
	authPrivateKey, err := base64.StdEncoding.DecodeString(app.cfg.AuthPrivateKey)
	if err != nil {
		return fmt.Errorf("Failed to parse private key: %s", err)
	}
	if len(authPrivateKey) < 128 {
		return fmt.Errorf("Key length is not safe")
	}
	app.auth = auth.NewService(
		&subjectsRepo{app.db},
		auth.TokensConfig{
			PrivateKey: authPrivateKey,
			LifeTime:   time.Duration(app.cfg.LoginTokenLifetime) * time.Second,
		},
		auth.TokensConfig{
			PrivateKey: authPrivateKey,
			LifeTime:   time.Duration(app.cfg.RefreshTokenLifetime) * time.Second,
		},
		auth.TokensConfig{
			PrivateKey: authPrivateKey,
			LifeTime:   time.Duration(app.cfg.AccessTokenLifetime) * time.Second,
		},
	)
	return nil
}

func (app *App) initNodesClient() error {
	dbNodes, err := func() ([]sqlgen.Node, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetNodes(context.Background())
	}()
	if err != nil {
		return err
	}

	app.nodeClients = nodes.NewMultiClient()
	for _, dbNode := range dbNodes {
		node, parseErrs := nodes.ParseNode(
			dbNode.Uuid,
			dbNode.BaseUrl,
			dbNode.Name,
			dbNode.AllowedIps,
			nodes.TLSClientConfig{
				ClientKey:  dbNode.TlsClientKey,
				ClientCert: dbNode.TlsClientCert,
				ServerCert: dbNode.TlsServerCert,
			},
		)
		if parseErrs != nil {
			return parseErrs
		}
		client := nodes.NewClient(node)
		app.nodeClients.Put(client)
	}

	return nil
}

func (app *App) populatePeerReqCache() error {
	dbReqs, err := func() ([]sqlgen.GetPeerRequestsRow, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetPeerRequests(context.Background())
	}()
	if err != nil {
		return err
	}
	for _, dbRow := range dbReqs {
		req, err := parsePeerRequestFromDB(&dbRow.PeerRequest, &dbRow.User, &dbRow.Node)
		if err != nil {
			return err
		}
		if req.Status != peers.Pending {
			continue
		}

		if err := app.putPendingPeerRequestToCache(req); err != nil {
			return err
		}
	}
	return nil
}

func NewApp(cfg Config, db *db.DB, peerReqCache *peers.PendingRequestsCache) (*App, error) {
	app := new(App)

	app.cfg = cfg
	app.db = db
	app.peerReqCache = peerReqCache
	if err := app.initReqCipher(); err != nil {
		return nil, err
	}
	if err := app.initTmpl(); err != nil {
		return nil, err
	}
	if err := app.initAuth(); err != nil {
		return nil, err
	}
	if err := app.initNodesClient(); err != nil {
		return nil, err
	}

	if err := app.addRootUserIfNotExists(context.Background()); err != nil {
		return nil, err
	}
	if err := app.populatePeerReqCache(); err != nil {
		return nil, err
	}

	return app, nil
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
	securedMux := http.NewServeMux()
	// TODO: enable caching for static files
	securedMux.Handle("/static/", http.FileServer(http.FS(staticFiles)))
	// TODO: disable caching for pages
	app.registerNodeHandlers(securedMux)
	app.registerUsersHandlers(securedMux)
	app.registerIndexPage(securedMux)
	app.registerPeerHandlers(securedMux)

	mux := http.NewServeMux()
	app.registerAuthHandlers(mux)
	mux.Handle("/", app.authenticationMiddleware(securedMux))

	loggedMux := web.LogMiddleware(mux)
	noCacheMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "no-store")
		loggedMux.ServeHTTP(w, r)
	})

	handler := reqencrypt.DecryptPathMiddleware(app.reqCipher, noCacheMux)

	tlsCfg, err := app.makeTLSConfig()
	if err != nil {
		return fmt.Errorf("Failed to load TLS keypair: %s", err)
	}

	server := http.Server{
		Addr:      app.cfg.HTTPBind,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}

	log.Printf("Admin service is binding to %s", app.cfg.HTTPBind)
	return server.ListenAndServeTLS("", "")
}

func (app *App) IssueLoginURL(username string) (string, error) {
	user, err := func() (sqlgen.User, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetUserByName(context.Background(), username)
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("User not found")
		} else {
			return "", err
		}
	}
	token, err := app.auth.IssueLoginToken(context.Background(), user.Uuid)
	if err != nil {
		return "", err
	}
	log.Printf("Issued token for %s (scopes %s)", user.Uuid, user.Scopes)
	loginURL := app.encryptURI("login/" + url.PathEscape(token))
	return loginURL, nil
}

func (app *App) RevokeRefreshTokens(username string) error {
	user, err := func() (sqlgen.User, error) {
		defer app.db.RUnlock()
		app.db.RLock()
		return app.db.GetUserByName(context.Background(), username)
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("User not found")
		} else {
			return err
		}
	}
	err = app.auth.RevokeRefreshTokens(context.Background(), user.Uuid)
	if err != nil {
		if errors.Is(err, auth.ErrSubjectNotFound) {
			return fmt.Errorf("User not found")
		} else {
			return err
		}
	}
	log.Printf("Revoked refresh tokens for user %s", username)
	return nil
}
