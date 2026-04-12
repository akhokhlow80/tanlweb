package main

import (
	"akhokhlow80/tanlweb/auth"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

type config struct {
	HTTPBind             string `env:"HTTP_BIND,required"`
	DBPath               string `env:"DB_PATH,required"`
	AuthPrivateKey       string `env:"AUTH_PRIV_KEY,required"`
	BaseURI              string `env:"BASE_URI,required"`
	LoginTokenLifetime   int    `env:"LOGIN_TOKEN_LIFETIME_SECS,required"`
	RefreshTokenLifetime int    `env:"REFRESH_TOKEN_LIFETIME_SECS,required"`
	AccessTokenLifetime  int    `env:"ACCESS_TOKEN_LIFETIME_SECS,required"`
	DebugMode            bool   `env:"DEBUG_MODE"`
}

type app struct {
	cfg  config
	db   db.DB
	tmpl *template.Template
	auth *auth.Service
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

	users, err := app.db.GetUsers(context.Background())
	if err != nil {
		return err
	}
	if len(users) == 0 {
		user, err := app.db.AddUser(context.Background(), sqlgen.AddUserParams{
			Uuid:        uuid.New().String(),
			Description: "root",
			Scopes:      auth.FullScope.String(),
		})
		if err != nil {
			return fmt.Errorf("Error adding root user: %w", err)
		}
		log.Printf("Created root user %s with full scope", user.Uuid)
	}

	return nil
}

func (app *app) initTmpl() error {
	templateFuncs := map[string]any{
		"BaseURI": func() string {
			return app.cfg.BaseURI
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

func (app *app) cmdListen() error {
	securedMux := http.NewServeMux()
	// TODO: enable caching for static files
	securedMux.Handle("/static/", http.FileServer(http.FS(staticFiles)))
	// TODO: disable caching for pages
	app.registerNodeHandlers(securedMux)
	app.registerUsersHandlers(securedMux)
	app.registerIndexPage(securedMux)

	mux := http.NewServeMux()
	app.registerAuthHandlers(mux)
	mux.Handle("/", app.authenticationMiddleware(securedMux))

	log.Printf("Binding to %s", app.cfg.HTTPBind)
	return http.ListenAndServe(app.cfg.HTTPBind, web.LogMiddleware(mux))
}

func (app *app) cmdLoginToken(uuid string) error {
	user, err := app.db.GetUser(context.Background(), uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("User not found")
		} else {
			return err
		}
	}
	token, err := app.auth.IssueLoginToken(context.Background(), user.Uuid)
	if err != nil {
		return err
	}
	log.Printf("Issued token for %s (scopes %s)", user.Uuid, user.Scopes)
	fmt.Printf("%s/login/%s", app.cfg.BaseURI, token)
	return nil
}

func (app *app) cmdRevokeRefreshTokens(uuid string) error {
	err := app.auth.RevokeRefreshTokens(context.Background(), uuid)
	if err != nil {
		if errors.Is(err, auth.ErrSubjectNotFound) {
			return fmt.Errorf("User not found")
		} else {
			return err
		}
	}
	log.Printf("Revoked refresh tokens for user %s", uuid)
	return nil
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
	app.auth = auth.NewService(
		&subjectsRepo{&app.db},
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

	if len(os.Args) == 1 {
		log.Fatal(app.cmdListen())
	} else if len(os.Args) == 3 && os.Args[1] == "login-token" {
		if err := app.cmdLoginToken(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	} else if len(os.Args) == 3 && os.Args[1] == "revoke-refresh-tokens" {
		if err := app.cmdRevokeRefreshTokens(os.Args[2]); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Fprintf(
			os.Stderr,
			"usage: %s [login-token <user UUID> | revoke-refresh-tokens <user UUID>]\n",
			os.Args[0],
		)
	}
}
