package main

import (
	"akhokhlow80/tanlweb/admin"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/sqlgen"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/pressly/goose/v3"
)

type config struct {
	// Admin

	AdminHTTPBind              string `env:"ADMIN_HTTP_BIND,required"`
	AuthPrivateKey             string `env:"AUTH_PRIV_KEY,required"`
	AdminBaseURI               string `env:"ADMIN_BASE_URI,required"`
	LoginTokenLifetime         int    `env:"LOGIN_TOKEN_LIFETIME_SECS,required"`
	RefreshTokenLifetime       int    `env:"REFRESH_TOKEN_LIFETIME_SECS,required"`
	AccessTokenLifetime        int    `env:"ACCESS_TOKEN_LIFETIME_SECS,required"`
	RequestKeyRotationInterval int    `env:"REQ_KEY_ROTATION_INTERVAL_SECS,required"`

	// Common

	DebugMode bool   `env:"DEBUG_MODE"`
	DBPath    string `env:"DB_PATH,required"`
}

var (
	//go:embed sql/migrations/*.sql
	migartions embed.FS
)

func initDB(dbPath string) (*db.DB, error) {
	sqlDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	goose.SetBaseFS(migartions)
	if err := goose.SetDialect("sqlite"); err != nil {
		return nil, err
	}
	if err := goose.Up(sqlDB, "sql/migrations"); err != nil {
		return nil, err
	}

	return &db.DB{DB: sqlDB, Queries: sqlgen.New(sqlDB)}, nil
}

func main() {
	cfg, err := env.ParseAs[config]()
	if err != nil {
		log.Fatalf("Failed to parse env: %s", err)
	}
	cfg.AdminBaseURI = strings.TrimSuffix(cfg.AdminBaseURI, "/")

	db, err := initDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to init DB: %s", err)
	}

	admin, err := admin.NewApp(admin.Config{
		BaseURI:                    cfg.AdminBaseURI,
		HTTPBind:                   cfg.AdminHTTPBind,
		AuthPrivateKey:             cfg.AuthPrivateKey,
		LoginTokenLifetime:         cfg.LoginTokenLifetime,
		RefreshTokenLifetime:       cfg.RefreshTokenLifetime,
		AccessTokenLifetime:        cfg.AccessTokenLifetime,
		RequestKeyRotationInterval: cfg.RequestKeyRotationInterval,
		DebugMode:                  cfg.DebugMode,
	}, db)
	if err != nil {
		log.Fatalf("Failed to init admin app: %s", err)
	}

	if len(os.Args) == 1 {
		log.Fatal(admin.Serve())
	} else if len(os.Args) == 3 && os.Args[1] == "login-token" {
		loginURL, err := admin.IssueLoginURL(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(loginURL)
	} else if len(os.Args) == 3 && os.Args[1] == "revoke-refresh-tokens" {
		if err := admin.RevokeRefreshTokens(os.Args[2]); err != nil {
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
