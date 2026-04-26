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
	ID                  string
	Scopes              Scopes
	LoginTokenVersion   int
	RefreshTokenVersion int
}

var ErrSubjectNotFound = errors.New("Subject not found")
var ErrInvalidToken = errors.New("Invalid token")

type SubjectsRepo interface {
	// Returns ErrSubjectNotFound if no such subject was found.
	Get(ctx context.Context, subID string) (StoredSubject, error)

	// Returns updated subject.
	// Errors: ErrSubjectNotFound, ...
	IncrementLoginVersion(ctx context.Context, subID string) (StoredSubject, error)

	// Returns updated subject.
	// Errors: ErrSubjectNotFound, ...
	IncrementRefreshVersion(ctx context.Context, subID string) (StoredSubject, error)

	// If the login version matches, increments it and returns updated subject.
	// Otherwise ErrSubjectNotFound is returned.
	GetAndUpdateForLogin(
		ctx context.Context,
		subID string,
		currentLoginVersion int,
	) (StoredSubject, error)
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
	storedSub, err := s.repo.IncrementLoginVersion(ctx, subID)
	if err != nil {
		return "", err
	}
	return signToken(&s.loginCfg, &tokenClaims{
		Subject: Subject{
			storedSub.ID,
			storedSub.Scopes,
		},
		Version: storedSub.LoginTokenVersion,
		Type:    tokenLogin,
	})
}

// Revoke all previously issued refresh tokens.
// Errors: ErrSubjectNotFound, ...
func (s *Service) RevokeRefreshTokens(ctx context.Context, subID string) error {
	_, err := s.repo.IncrementRefreshVersion(ctx, subID)
	if err != nil {
		return err
	}
	return nil
}

// Errors: ErrSubjectNotFound, ErrInvalidToken, ...
func (s *Service) LoginForRefreshToken(ctx context.Context, loginTokenStr string) (string, error) {
	parsedClaims, err := parseToken(&s.loginCfg, tokenLogin, loginTokenStr)
	if err != nil {
		return "", ErrInvalidToken
	}
	subject, err := s.repo.GetAndUpdateForLogin(ctx, parsedClaims.ID, parsedClaims.Version)
	if err != nil {
		return "", err
	}
	return signToken(&s.refreshCfg, &tokenClaims{
		Subject: Subject{
			subject.ID,
			subject.Scopes,
		},
		Version: subject.RefreshTokenVersion,
		Type:    tokenRefresh,
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
	parsedClaims, err := parseToken(&s.accessCfg, tokenAccess, accessTokenStr)
	if err != nil {
		parsedClaims, err = parseToken(&s.refreshCfg, tokenRefresh, refreshTokenStr)
		if err != nil {
			return "", nil, ErrInvalidToken
		}
		var subject StoredSubject
		subject, err = s.repo.Get(ctx, parsedClaims.ID)
		if err != nil {
			return "", nil, err
		}
		if subject.RefreshTokenVersion != parsedClaims.Version {
			return "", nil, ErrInvalidToken
		}
		newAccessClaims := tokenClaims{
			Subject: Subject{
				subject.ID,
				subject.Scopes,
			},
			Version: subject.RefreshTokenVersion,
			Type:    tokenAccess,
		}
		newAccessToken, err = signToken(&s.accessCfg, &newAccessClaims)
		if err != nil {
			return "", nil, err
		}
		sub = &newAccessClaims.Subject
	} else {
		sub = &parsedClaims.Subject
	}

	return newAccessToken, sub, nil
}
