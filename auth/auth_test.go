package auth_test

import (
	"akhokhlow80/tanlweb/auth"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

var (
	user0 = auth.StoredSubject{
		ID:                "user0",
		Scopes:            auth.Scopes{},
		LoginTokenVersion: 0,
		LoginTokenUsed:    false,
	}
	user1 = auth.StoredSubject{
		ID:                "user1",
		Scopes:            auth.Scopes{Users: true, Nodes: true, Peers: true},
		LoginTokenVersion: 0,
		LoginTokenUsed:    false,
	}
)

type mockSubjectsRepo struct {
	subjects [2]auth.StoredSubject
}

var _ auth.SubjectsRepo = (*mockSubjectsRepo)(nil)

func (repo *mockSubjectsRepo) Get(subID string, loginVersion int) (auth.StoredSubject, error) {
	for _, subject := range repo.subjects {
		if subject.ID == subID && subject.LoginTokenVersion == loginVersion {
			return subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func (repo *mockSubjectsRepo) NextLoginVersion(subID string) (auth.StoredSubject, error) {
	for i, subject := range repo.subjects {
		if subject.ID == subID {
			subject.LoginTokenVersion++
			subject.LoginTokenUsed = false
			repo.subjects[i] = subject
			return subject, nil
		}
	}
	return auth.StoredSubject{}, auth.ErrSubjectNotFound
}

func (repo *mockSubjectsRepo) LoggedIn(subID string, loginVersion int) (auth.StoredSubject, error) {
	for i, subject := range repo.subjects {
		if subject.ID == subID && subject.LoginTokenVersion == loginVersion && !subject.LoginTokenUsed {
			subject.LoginTokenUsed = true
			repo.subjects[i] = subject
			return subject, nil
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
	var repo mockSubjectsRepo
	repo.subjects[0] = user0
	repo.subjects[1] = user1

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
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate("", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}

	time.Sleep(lifetime + 1*time.Second)

	_, _, err = service.Authenticate(accessToken, refreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(loginToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}

func TestUsedLoginToken(t *testing.T) {
	const lifetime = 100 * time.Second
	service := newSerivceWithRandomKeys(lifetime, lifetime, lifetime)
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(loginToken)
	if !errors.Is(err, auth.ErrSubjectNotFound) {
		t.Errorf("Expected ErrSubjectNotFound, got: %s", err)
	}
}

func TestOldLoginToken(t *testing.T) {
	const lifetime = 100 * time.Second
	service := newSerivceWithRandomKeys(lifetime, lifetime, lifetime)
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(loginToken)
	if !errors.Is(err, auth.ErrSubjectNotFound) {
		t.Errorf("Expected ErrSubjectNotFound, got: %s", err)
	}
}

func TestAcessTokenRenewal(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Minute, 2*time.Second)
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate("", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	renewedAccessToken1, _, err := service.Authenticate(accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if len(renewedAccessToken1) != 0 {
		t.Errorf("Unexpected access token renewal")
	}

	time.Sleep(3 * time.Second)

	renewedAccessToken2, _, err := service.Authenticate(renewedAccessToken1, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if len(renewedAccessToken2) == 0 {
		t.Errorf("Expected acces token renewal after the previous expired")
	}

	_, _, err = service.Authenticate(renewedAccessToken2, "")
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
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, sub, err := service.Authenticate("", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user0Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user0Sub)
	}
	_, sub, err = service.Authenticate(accessToken, refreshToken)
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
	loginToken, err := service.IssueLoginToken("user1")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, sub, err := service.Authenticate("", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user1Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user1Sub)
	}
	_, sub, err = service.Authenticate(accessToken, refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	if sub == nil || *sub != user1Sub {
		t.Errorf("Subject %v differs from expected %v", sub, user1Sub)
	}
}

func TestInvalidSignature(t *testing.T) {
	service := newSerivceWithRandomKeys(time.Hour, time.Hour, time.Hour)
	_, err := service.LoginForRefreshToken("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMCIsInNjb3BlcyI6MTIzLCJ0eXBlIjoibG9naW4iLCJqdGkiOjEsImV4cCI6MjAwMDAwMDAwMDB9.d-dPZ2dThbbt3RQS1ndoQi2IlEA80hC9hCskAVwluL6CangM0ZbwKkH4Z_dk6blO")
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}

func TestTokenTypeCheck(t *testing.T) {
	var key [128]byte
	rand.Read(key[:])
	service := newSerivce(time.Hour, time.Hour, time.Hour, key[:], key[:], key[:])
	loginToken, err := service.IssueLoginToken("user0")
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	refreshToken, err := service.LoginForRefreshToken(loginToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}
	accessToken, _, err := service.Authenticate("", refreshToken)
	if err != nil {
		t.Errorf("Expected no error, got: %s", err)
	}

	_, _, err = service.Authenticate("", accessToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(accessToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
	_, err = service.LoginForRefreshToken(refreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Expected ErrInvalidToken, got: %s", err)
	}
}
