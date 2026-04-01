package main

import (
	"akhokhlow80/tanlweb/scopes"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/tokens"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

func (app *app) authenticateWithAccessToken(r *http.Request) (tokens.Subject, error) {
	accessTokenCookie, err := r.Cookie("access_token")
	if err != nil {
		return tokens.Subject{}, ErrUnauthorized
	}
	sub, err := app.accessTokens.Parse(accessTokenCookie.Value)
	if err != nil {
		return tokens.Subject{}, ErrUnauthorized
	}
	return sub, err
}

func (app *app) authenticateWithRefreshToken(w http.ResponseWriter, r *http.Request) (tokens.Subject, error) {
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err != nil {
		return tokens.Subject{}, ErrUnauthorized
	}
	sub, err := app.refreshTokens.Parse(refreshTokenCookie.Name)
	if err != nil {
		return tokens.Subject{}, ErrUnauthorized
	}

	// TODO: check token version

	user, err := func() (sqlgen.User, error) {
		defer app.db.Unlock()
		app.db.Lock()
		return app.db.Queries.GetUser(r.Context(), sub.Id)
	}()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tokens.Subject{}, ErrUnauthorized
		} else {
			return tokens.Subject{}, fmt.Errorf("Failed to retrieve user on auth: %w", err)
		}
	}
	realScopes, err := scopes.Parse(user.Scopes)
	if err != nil {
		return tokens.Subject{}, fmt.Errorf("Failed to parse scopes on auth: %w", err)
	}

	accessToken, err := app.accessTokens.SignToken(&tokens.Subject{
		Id: sub.Id,
		Scopes: realScopes,
	})
	if err != nil {
		return tokens.Subject{}, fmt.Errorf("Failed to sign token: %w", err)
	}
	accessTokenCookie := http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &accessTokenCookie)

	return sub, nil
}

// May only return ErrUnauthorized or ErrDenied.
// Any other internal errors are logged.
func (app *app) authorize(w http.ResponseWriter, r *http.Request, requiredScopes scopes.Scopes) error {
	var (
		sub tokens.Subject
		err error
	)
	sub, err = app.authenticateWithAccessToken(r)
	if err != nil {
		sub, err = app.authenticateWithRefreshToken(w, r)
		if err != nil {
			return err
		}
	}
	if !sub.Scopes.MatchRequired(&requiredScopes) {
		return err
	}
	return nil
}

func (app *app) setRefreshTokenCookie(w http.ResponseWriter, sub *tokens.Subject) error {
	refreshToken, err := app.accessTokens.SignToken(sub)
	if err != nil {
		return err
	}
	refreshTokenCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &refreshTokenCookie)
	return nil
}
