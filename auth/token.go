package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type tokenType int

const (
	tokenLogin tokenType = iota
	tokenRefresh
	tokenAccess
)

func (t tokenType) String() string {
	switch t {
	case tokenLogin:
		return "login"
	case tokenRefresh:
		return "refresh"
	case tokenAccess:
		return "access"
	default:
		panic("unknown token type")
	}
}

type tokenClaims struct {
	Subject
	// Optional, zero is none
	LoginVersion int
	Type         tokenType
}

type TokensConfig struct {
	PrivateKey []byte
	LifeTime   time.Duration
}

func signToken(cfg *TokensConfig, claims *tokenClaims) (string, error) {
	exp := time.Now().Add(cfg.LifeTime)

	jwtClaims := jwt.MapClaims{
		"sub":    claims.ID,
		"scopes": claims.Scopes.String(),
		"exp":    exp.Unix(),
		"type":   claims.Type.String(),
	}
	if claims.LoginVersion != 0 {
		jwtClaims["jti"] = claims.LoginVersion
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS384, jwtClaims)
	tokenString, err := token.SignedString(cfg.PrivateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func parseToken(cfg *TokensConfig, expectedType tokenType, tokenStr string) (tokenClaims, error) {
	var ErrParsingClaims = errors.New("Failed to parse claims")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return cfg.PrivateKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS384.Alg()}))
	if err != nil {
		return tokenClaims{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return tokenClaims{}, ErrParsingClaims
	}
	type_, ok := claims["type"].(string)
	if !ok || type_ != expectedType.String() {
		return tokenClaims{}, ErrParsingClaims
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return tokenClaims{}, ErrParsingClaims
	}
	scopesStr, ok := claims["scopes"].(string)
	if !ok {
		return tokenClaims{}, ErrParsingClaims
	}
	scopes, err := ParseScopes(scopesStr)
	if err != nil {
		return tokenClaims{}, err
	}
	version, ok := claims["jti"].(float64)
	if !ok {
		version = 0
	}

	return tokenClaims{
		Subject: Subject{
			ID:     sub,
			Scopes: scopes,
		},
		LoginVersion: int(version),
	}, nil
}
