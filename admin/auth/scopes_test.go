package auth_test

import (
	"akhokhlow80/tanlweb/admin/auth"
	"testing"
)

func TestScopesMatch(t *testing.T) {
	scopes := auth.Scopes{
		Users: auth.R | auth.W,
		Nodes: auth.R,
	}
	if !scopes.MatchRequired(&auth.Scopes{
		Users: auth.R,
	}) {
		t.Error("Scopes are expected to match required")
	}
	if !scopes.MatchRequired(&auth.Scopes{
		Users: auth.R | auth.W,
		Nodes: auth.R,
	}) {
		t.Error("Scopes are expected to match required")
	}
	if scopes.MatchRequired(&auth.Scopes{
		Peers: auth.R,
		Nodes: auth.R,
	}) {
		t.Error("Scopes are expected not to match required")
	}
	if scopes.MatchRequired(&auth.Scopes{
		Nodes: auth.W,
	}) {
		t.Error("Scopes are expected not to match required")
	}
}

func testScopesString(t *testing.T, scopes auth.Scopes, expected string) {
	s := scopes.String()
	if s != expected {
		t.Fatalf("Scope `%s` differs from `%s`", s, expected)
	}
	parsedScopes, err := auth.ParseScopes(s)
	if err != nil {
		t.Fatalf("Unexpected error when parsing scopes `%s`", s)
	}
	if parsedScopes != scopes {
		t.Fatalf("Parsed scopes %+v doesn't match expected %+v", parsedScopes, scopes)
	}
}

func TestScopesParseAndPrint(t *testing.T) {
	testScopesString(t, auth.Scopes{
		Users: auth.R,
	}, "users:r")
	testScopesString(t, auth.Scopes{
		Nodes: auth.R,
	}, "nodes:r")
	testScopesString(t, auth.Scopes{
		Peers: auth.R,
	}, "peers:r")
	testScopesString(t, auth.Scopes{}, "")
	testScopesString(t, auth.Scopes{
		Users: auth.R | auth.W,
		Peers: auth.W,
	}, "users:rw,peers:w")
	testScopesString(t, auth.Scopes{
		Users: auth.R | auth.W,
		Nodes: auth.R | auth.W,
		Peers: auth.R,
	}, "users:rw,nodes:rw,peers:r")
}
