package main

import (
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/tokens"
	"akhokhlow80/tanlweb/web"
	"database/sql"
	"embed"
	"encoding/base64"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/pressly/goose/v3"
)

type config struct {
	HTTPBind             string `env:"HTTP_BIND,required"`
	DBPath               string `env:"DB_PATH,required"`
	AuthPrivateKey       string `env:"AUTH_PRIV_KEY,required"`
	RefreshTokenLifetime int    `env:"REFRESH_TOKEN_LIFETIME_SECS,required"`
	AccessTokenLifetime  int    `env:"ACCESS_TOKEN_LIFETIME_SECS,required"`
}

type app struct {
	cfg           config
	db            db.DB
	tmpl          *template.Template
	accessTokens  tokens.Service
	refreshTokens tokens.Service
}

var (
	//go:embed sql/migrations/*.sql
	migartions embed.FS
	//go:embed html/*
	htmlTemplates embed.FS
	//go:embed static/*
	staticFiles embed.FS
)

func (app *app) initDB(dbPath string) error {
	var err error
	app.db.DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	goose.SetBaseFS(migartions)
	if err := goose.SetDialect("sqlite"); err != nil {
		return err
	}
	if err := goose.Up(app.db.DB, "sql/migrations"); err != nil {
		return err
	}

	app.db.Queries = sqlgen.New(app.db.DB)

	return nil
}

func (app *app) initTmpl() error {
	templateFuncs := map[string]any{}
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

func (app *app) listen() error {
	adminMux := http.NewServeMux()
	app.registerNodeHandlers(adminMux)
	app.registerUsersHandlers(adminMux)

	mux := http.NewServeMux()
	// TODO: enable cache for static files
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))
	// TODO: disable cache for pages
	mux.Handle("/admin/", http.StripPrefix("/admin",
		// FIXME: log middleware prints stripped URL
		web.LogMiddleware(adminMux),
	))
	log.Printf("Binding to %s", app.cfg.HTTPBind)
	return http.ListenAndServe(app.cfg.HTTPBind, mux)
}

func main() {
	var (
		app app
		err error
	)

	app.cfg, err = env.ParseAs[config]()
	if err != nil {
		log.Fatalf("Failed to parse env: %s", err)
	}

	if err = app.initDB(app.cfg.DBPath); err != nil {
		log.Fatalf("Failed to init DB: %s", err)
	}

	if err = app.initTmpl(); err != nil {
		log.Fatalf("Failed to init templates: %s", err)
	}

	authPrivateKey, err := base64.StdEncoding.DecodeString(app.cfg.AuthPrivateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}
	if len(authPrivateKey) < 128 {
		log.Fatalf("Key lenght is not safe")
	}
	app.accessTokens = tokens.New(authPrivateKey, time.Second*time.Duration(app.cfg.AccessTokenLifetime))
	app.accessTokens = tokens.New(authPrivateKey, time.Second*time.Duration(app.cfg.RefreshTokenLifetime))

	log.Fatal(app.listen())
}
