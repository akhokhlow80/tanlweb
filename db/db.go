package db

import (
	"akhokhlow80/tanlweb/sqlgen"
	"database/sql"
	"sync"
)

type DB struct {
	sync.RWMutex
	*sqlgen.Queries
	*sql.DB
}
