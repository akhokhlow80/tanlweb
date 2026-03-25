package db

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

func IsConstraintErr(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		if errors.Is(sqliteErr.Code, sqlite3.ErrConstraint) {
			return true
		}
	}
	return false
}
