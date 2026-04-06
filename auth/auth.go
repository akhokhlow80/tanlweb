package auth

import (
	"context"
	"errors"
)

type Subject struct {
	ID     string
	Scopes Scopes
}

// Subject from the storage.
type StoredSubject struct {
	ID                string
	Scopes            Scopes
	LoginTokenVersion int // Always >= 0
	LoginTokenUsed    bool
}

var ErrSubjectNotFound = errors.New("Subject not found")
var ErrInvalidToken = errors.New("Invalid token")

type SubjectsRepo interface {
	// Returns ErrSubjectNotFound if no such subject was found.
	Get(ctx context.Context, subID string, loginVersion int) (StoredSubject, error)

	// Returns updated stored subject.
	// Errors: ErrSubjectNotFound, ...
	NextLoginVersion(ctx context.Context, subID string) (StoredSubject, error)

	// Updates only if the subject exists, version matches and they weren't logged in,
	// otherwise ErrSubjectNotFound is returned.
	LoggedIn(ctx context.Context, subID string, loginVersion int) (StoredSubject, error)
}

type Service struct {
	repo                            SubjectsRepo
	loginCfg, accessCfg, refreshCfg TokensConfig
}

func NewService(repo SubjectsRepo, loginTokenCfg, refreshTokenCfg, accessTokenCfg TokensConfig) *Service {
	if len(loginTokenCfg.PrivateKey) < 128 {
		panic("Login token key length is not safe")
	}
	if len(refreshTokenCfg.PrivateKey) < 128 {
		panic("Refresh token key length is not safe")
	}
	if len(accessTokenCfg.PrivateKey) < 128 {
		panic("Access token key length is not safe")
	}
	return &Service{
		repo:       repo,
		loginCfg:   loginTokenCfg,
		refreshCfg: refreshTokenCfg,
		accessCfg:  accessTokenCfg,
	}
}

func (s *Service) IssueLoginToken(ctx context.Context, subID string) (string, error) {
	storedSub, err := s.repo.NextLoginVersion(ctx, subID)
	if err != nil {
		return "", err
	}
	return signToken(&s.loginCfg, &tokenClaims{
		Subject: Subject{
			storedSub.ID,
			storedSub.Scopes,
		},
		LoginVersion: storedSub.LoginTokenVersion,
		Type:         tokenLogin,
	})
}

// Errors: ErrSubjectNotFound, ErrInvalidToken, ...
func (s *Service) LoginForRefreshToken(ctx context.Context, loginTokenStr string) (string, error) {
	parsedClaims, err := parseToken(&s.loginCfg, tokenLogin, loginTokenStr)
	if err != nil {
		return "", ErrInvalidToken
	}
	subject, err := s.repo.LoggedIn(ctx, parsedClaims.ID, parsedClaims.LoginVersion)
	if err != nil {
		return "", err
	}
	return signToken(&s.refreshCfg, &tokenClaims{
		Subject: Subject{
			subject.ID,
			subject.Scopes,
		},
		LoginVersion: subject.LoginTokenVersion,
		Type:         tokenRefresh,
	})
}

// Returns non-nil claims on success.
// Returns non-empty newAccessToken if it was renewed (only on successful auth).
//
// Errors: ErrSubjectNotFound, ErrInvalidToken, ...
func (s *Service) Authenticate(ctx context.Context, accessTokenStr, refreshTokenStr string) (
	newAccessToken string,
	sub *Subject,
	err error,
) {
	claims, err := parseToken(&s.accessCfg, tokenAccess, accessTokenStr)
	if err != nil {
		claims, err = parseToken(&s.refreshCfg, tokenRefresh, refreshTokenStr)
		if err != nil {
			return "", nil, ErrInvalidToken
		}
		var subject StoredSubject
		subject, err = s.repo.Get(ctx, claims.ID, claims.LoginVersion)
		if err != nil {
			return "", nil, err
		}
		newAccessClaims := tokenClaims{
			Subject: Subject{
				subject.ID,
				subject.Scopes,
			},
			LoginVersion: 0,
			Type:         tokenAccess,
		}
		newAccessToken, err = signToken(&s.accessCfg, &newAccessClaims)
		if err != nil {
			return "", nil, err
		}
		sub = &newAccessClaims.Subject
	} else {
		sub = &claims.Subject
	}

	return newAccessToken, sub, nil
}
