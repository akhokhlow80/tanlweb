package auth_test

import (
	"akhokhlow80/tanlweb/auth"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

var (
	user0, user1 auth.StoredSubject
)

type mockSubjectsRepo struct {
	subjects []*auth.StoredSubject
}

var _ auth.SubjectsRepo = (*mockSubjectsRepo)(nil)

func (repo *mockSubjectsRepo) Get(ctx context.Context, subID string) (auth.StoredSubject, error) {
	for _, subject := range repo.subjects {
		if subject.ID == subID {
			return *subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func (repo *mockSubjectsRepo) IncrementLoginVersion(ctx context.Context, subID string) (auth.StoredSubject, error) {
	for _, subject := range repo.subjects {
		if subject.ID == subID {
			subject.LoginTokenVersion++
			return *subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func (repo *mockSubjectsRepo) IncrementRefreshVersion(ctx context.Context, subID string) (auth.StoredSubject, error) {
	for _, subject := range repo.subjects {
		if subject.ID == subID {
			subject.RefreshTokenVersion++
			return *subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func (repo *mockSubjectsRepo) GetAndUpdateForLogin(ctx context.Context, subID string, currentLoginVersion int) (auth.StoredSubject, error) {
	for _, subject := range repo.subjects {
		if subject.ID == subID && subject.LoginTokenVersion == currentLoginVersion {
			subject.LoginTokenVersion++
			return *subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func newSerivce(
	loginLifetime,
	refreshLifetime,
	accessLifetime time.Duration,
	loginKey []byte,
	refreshKey []byte,
	accessKey []byte,
) *auth.Service {
	user0 = auth.StoredSubject{
		ID:                  "user0",
		Scopes:              auth.Scopes{},
		LoginTokenVersion:   0,
		RefreshTokenVersion: 0,
	}
	user1 = auth.StoredSubject{
		ID:                  "user1",
		Scopes:              auth.Scopes{Users: true, Nodes: true, Peers: true},
		LoginTokenVersion:   0,
		RefreshTokenVersion: 0,
	}

	var repo mockSubjectsRepo
	repo.subjects = []*auth.StoredSubject{&user0, &user1}

	return auth.NewService(&repo,
		auth.TokensConfig{
			LifeTime:   loginLifetime,
			PrivateKey: loginKey[:],
		},
		auth.TokensConfig{
			LifeTime:   refreshLifetime,
			PrivateKey: refreshKey[:],
		},
		auth.TokensConfig{
			LifeTime:   accessLifetime,
			PrivateKey: accessKey[:],
		})
}

func newSerivceWithRandomKeys(loginLifetime, refreshLifetime, accessLifetime time.Duration) *auth.Service {
	var loginKey, refreshKey, accessKey [128]byte
	rand.Read(loginKey[:])
	rand.Read(refreshKey[:])
	rand.Read(accessKey[:])
	return newSerivce(
		loginLifetime,
		refreshLifetime,
		accessLifetime,
		loginKey[:],
		refreshKey[:],
		accessKey[:],
	)
}

func TestTokenExpire(t *testing.T) {
	const lifetime = 2 * time.Second
	service := newSerivceWithRandomKeys(lifetime, lifetime, lifetime)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}

	time.Sleep(lifetime + 1*time.Second)

	_, _, err = service.Authenticate(context.Background(), accessToken, refreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), loginToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}

func TestUsedLoginToken(t *testing.T) {
	const lifetime = 100 * time.Second
	service := newSerivceWithRandomKeys(lifetime, lifetime, lifetime)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), loginToken)
	if !errors.Is(err, auth.ErrSubjectNotFound) {
		t.Errorf("Expected ErrSubjectNotFound, got: %s", err)
	}
}

func TestOldLoginToken(t *testing.T) {
	const lifetime = 100 * time.Second
	service := newSerivceWithRandomKeys(lifetime, lifetime, lifetime)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), loginToken)
	if !errors.Is(err, auth.ErrSubjectNotFound) {
		t.Errorf("Expected ErrSubjectNotFound, got: %s", err)
	}
}

func TestAcessTokenRenewal(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Minute, 2*time.Second)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	renewedAccessToken1, _, err := service.Authenticate(context.Background(), accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if len(renewedAccessToken1) != 0 {
		t.Errorf("Unexpected access token renewal")
	}

	time.Sleep(3 * time.Second)

	renewedAccessToken2, _, err := service.Authenticate(context.Background(), renewedAccessToken1, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if len(renewedAccessToken2) == 0 {
		t.Errorf("Expected acces token renewal after the previous expired")
	}

	_, _, err = service.Authenticate(context.Background(), renewedAccessToken2, "")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
}

func TestAccessTokenSubject0(t *testing.T) {
	var user0Sub = auth.Subject{
		ID:     user0.ID,
		Scopes: user0.Scopes,
	}
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Hour)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, sub, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user0Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user0Sub)
	}
	_, sub, err = service.Authenticate(context.Background(), accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user0Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user0Sub)
	}
}

func TestAccessTokenSubject1(t *testing.T) {
	var user1Sub = auth.Subject{
		ID:     user1.ID,
		Scopes: user1.Scopes,
	}
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Hour)
	loginToken, err := service.IssueLoginToken(context.Background(), "user1")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, sub, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user1Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user1Sub)
	}
	_, sub, err = service.Authenticate(context.Background(), accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user1Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user1Sub)
	}
}

func TestInvalidSignature(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Hour)
	_, err := service.LoginForRefreshToken(
		context.Background(),
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMCIsInNjb3BlcyI6MTIzLCJ0eXBlIjoibG9naW4iLCJqdGkiOjEsImV4cCI6MjAwMDAwMDAwMDB9.d-dPZ2dThbbt3RQS1ndoQi2IlEA80hC9hCskAVwluL6CangM0ZbwKkH4Z_dk6blO",
	)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}

func TestTokenTypeCheck(t *testing.T) {
	var key [128]byte
	rand.Read(key[:])
	service := newSerivce(time.Hour, time.Hour, time.Hour, key[:], key[:], key[:])
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}

	_, _, err = service.Authenticate(context.Background(), "", accessToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), accessToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(context.Background(), refreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}

func TestAccessTokenSubjectAfterRenewal(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Second)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, sub, err := service.Authenticate(context.Background(), "", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}

	time.Sleep(2 * time.Second)

	user0.Scopes.Nodes = true
	var user0Sub = auth.Subject{
		ID:     user0.ID,
		Scopes: user0.Scopes,
	}
	_, sub, err = service.Authenticate(context.Background(), accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user0Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user0Sub)
	}
}

func TestMultipleRefreshTokens(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Second)
	loginToken1, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken1, err := service.LoginForRefreshToken(context.Background(), loginToken1)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	loginToken2, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken2, err := service.LoginForRefreshToken(context.Background(), loginToken2)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, _, err = service.Authenticate(context.Background(), "", refreshToken1)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, _, err = service.Authenticate(context.Background(), "", refreshToken2)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
}

func TestRefreshTokenRevocation(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Second)
	loginToken, err := service.IssueLoginToken(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(context.Background(), loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	err = service.RevokeRefreshTokens(context.Background(), "user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, _, err = service.Authenticate(context.Background(), "", refreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}
