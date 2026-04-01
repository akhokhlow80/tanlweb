package tokens

import (
	"akhokhlow80/tanlweb/scopes"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Service struct {
	privateKey           []byte
	refreshTokenLifeTime time.Duration
}

func New(privateKey []byte, refreshTokenLifeTime time.Duration) Service {
	if len(privateKey) < 128 {
		panic("Key length is not safe")
	}
	return Service{
		privateKey:           privateKey,
		refreshTokenLifeTime: refreshTokenLifeTime,
	}
}

type Subject struct {
	Id     string
	Scopes scopes.Scopes
}

func (s *Service) SignToken(sub *Subject) (string, error) {
	exp := time.Now().Add(s.refreshTokenLifeTime)

	token := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{
		"sub":    sub.Id,
		"scopes": sub.Scopes.String(),
		"exp":    exp.Unix(),
	})
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

var ErrParsingClaims = errors.New("Failed to parse claims")

func (s *Service) Parse(tokenStr string) (Subject, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return s.privateKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS384.Alg()}))
	if err != nil {
		return Subject{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Subject{}, ErrParsingClaims
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return Subject{}, ErrParsingClaims
	}
	scopesStr, ok := claims["scopes"].(string)
	if !ok {
		return Subject{}, ErrParsingClaims
	}
	scopes, err := scopes.Parse(scopesStr)
	if err != nil {
		return Subject{}, err
	}

	return Subject{
		Id:     sub,
		Scopes: scopes,
	}, nil
}
