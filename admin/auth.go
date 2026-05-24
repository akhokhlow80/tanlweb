package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/db"
	"akhokhlow80/tanlweb/reqlog"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

func (app *App) registerAuthHandlers(m *http.ServeMux) {
	m.HandleFunc("/login/{token}", web.FailableHandler(app.standardErrorHandler, app.loginHandler))
}

func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	refreshToken, err := app.auth.LoginForRefreshToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrSubjectNotFound) {
			// If the user is logged in and cookies are set, they will be redirected to the admin interface.
			// Otherwise, they will be shown standard "unauthorized" response.
			w.Header().Set("Location", app.encryptURI(""))
			w.WriteHeader(http.StatusSeeOther)
			return nil
		} else {
			return err
		}
	}
	refreshCookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   app.cfg.RefreshTokenLifetime,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	accessCookie := http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		MaxAge:   app.cfg.AccessTokenLifetime,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &refreshCookie)
	http.SetCookie(w, &accessCookie)
	w.Header().Set("Location", app.encryptURI(""))
	w.WriteHeader(http.StatusSeeOther)
	return nil
}

type subjectsRepo struct {
	db *db.DB
}

var _ auth.SubjectsRepo = (*subjectsRepo)(nil)

// Get implements auth.SubjectsRepo.
func (repo *subjectsRepo) Get(ctx context.Context, subID string) (auth.StoredSubject, error) {
	defer repo.db.RUnlock()
	repo.db.RLock()

	user, err := repo.db.GetUserByUUID(ctx, subID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.StoredSubject{}, auth.ErrSubjectNotFound
		} else {
			return auth.StoredSubject{}, err
		}
	}
	scopes, err := auth.ParseScopes(user.Scopes)
	if err != nil {
		return auth.StoredSubject{},
			fmt.Errorf("Error while parsing scopes of user %s from DB: %w", user.Uuid, err)
	}
	return auth.StoredSubject{
		ID:                  subID,
		Scopes:              scopes,
		LoginTokenVersion:   int(user.LoginTokenVersion),
		RefreshTokenVersion: int(user.RefreshTokenVersion),
	}, err
}

// IncrementLoginVersion implements auth.SubjectsRepo.
func (repo *subjectsRepo) IncrementLoginVersion(ctx context.Context, subID string) (auth.StoredSubject, error) {
	defer repo.db.Unlock()
	repo.db.Lock()

	user, err := repo.db.IncrementUserLoginVersion(ctx, subID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.StoredSubject{}, auth.ErrSubjectNotFound
		} else {
			return auth.StoredSubject{}, err
		}
	}
	scopes, err := auth.ParseScopes(user.Scopes)
	if err != nil {
		return auth.StoredSubject{},
			fmt.Errorf("Error while parsing scopes of user %s from DB: %w", user.Uuid, err)
	}
	return auth.StoredSubject{
		ID:                  subID,
		Scopes:              scopes,
		LoginTokenVersion:   int(user.LoginTokenVersion),
		RefreshTokenVersion: int(user.RefreshTokenVersion),
	}, err
}

// IncrementRefreshVersion implements auth.SubjectsRepo.
func (repo *subjectsRepo) IncrementRefreshVersion(ctx context.Context, subID string) (auth.StoredSubject, error) {
	defer repo.db.Unlock()
	repo.db.Lock()

	user, err := repo.db.IncrementUserRefreshVersion(ctx, subID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.StoredSubject{}, auth.ErrSubjectNotFound
		} else {
			return auth.StoredSubject{}, err
		}
	}
	scopes, err := auth.ParseScopes(user.Scopes)
	if err != nil {
		return auth.StoredSubject{},
			fmt.Errorf("Error while parsing scopes of user %s from DB: %w", user.Uuid, err)
	}
	return auth.StoredSubject{
		ID:                  subID,
		Scopes:              scopes,
		LoginTokenVersion:   int(user.LoginTokenVersion),
		RefreshTokenVersion: int(user.RefreshTokenVersion),
	}, err
}

// GetAndUpdateForLogin implements auth.SubjectsRepo.
func (repo *subjectsRepo) GetAndUpdateForLogin(ctx context.Context, subID string, currentLoginVersion int) (auth.StoredSubject, error) {
	defer repo.db.Unlock()
	repo.db.Lock()

	user, err := repo.db.GetUserAndUpdateForLogin(ctx, sqlgen.GetUserAndUpdateForLoginParams{
		Uuid:                subID,
		CurrentLoginVersion: int64(currentLoginVersion),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.StoredSubject{}, auth.ErrSubjectNotFound
		} else {
			return auth.StoredSubject{}, err
		}
	}
	scopes, err := auth.ParseScopes(user.Scopes)
	if err != nil {
		return auth.StoredSubject{},
			fmt.Errorf("Error while parsing scopes of user %s from DB: %w", user.Uuid, err)
	}
	return auth.StoredSubject{
		ID:                  subID,
		Scopes:              scopes,
		LoginTokenVersion:   int(user.LoginTokenVersion),
		RefreshTokenVersion: int(user.RefreshTokenVersion),
	}, err
}

func (app *App) authenticate(w http.ResponseWriter, r *http.Request) (auth.Subject, error) {
	var accessToken, refreshToken string

	accessTokenCookie, err := r.Cookie("access_token")
	if err == nil {
		accessToken = accessTokenCookie.Value
	}
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err == nil {
		refreshToken = refreshTokenCookie.Value
	}
	newAccessToken, sub, err := app.auth.Authenticate(r.Context(), accessToken, refreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrSubjectNotFound) {
			return auth.Subject{}, errUnauthorized
		} else {
			return auth.Subject{}, err
		}
	}
	if len(newAccessToken) != 0 {
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    newAccessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   app.cfg.AccessTokenLifetime,
			SameSite: http.SameSiteStrictMode,
		})
	}
	return *sub, nil
}

type authenticatedUserCtxKey struct{}

func (app *App) authenticationMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, err := app.authenticate(w, r)
		if err != nil {
			if errors.Is(err, errUnauthorized) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			} else {
				reqlog.Printf(r, "Internal server error during authentication: %s", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}
		ctx := context.WithValue(r.Context(), authenticatedUserCtxKey{}, sub)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getAuthenticatedUser(ctx context.Context) *auth.Subject {
	subject, ok := ctx.Value(authenticatedUserCtxKey{}).(auth.Subject)
	if !ok {
		return nil
	}
	return &subject
}

// Authorize authenticated user
// Returns ErrForbidden on insufficient scope.
func authorize(ctx context.Context, requiredScopes *auth.Scopes) error {
	subject := getAuthenticatedUser(ctx)
	if subject == nil {
		return errUnauthorized
	}

	if !subject.Scopes.MatchRequired(requiredScopes) {
		return errForbidden
	} else {
		return nil
	}
}
