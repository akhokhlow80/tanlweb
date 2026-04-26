package auth_test

import (
	"akhokhlow80/tanlweb/auth"
	"testing"
)

func TestScopesMatch(t *testing.T) {
	scopes := auth.Scopes{
		Users: true,
		Nodes: true,
	}
	if !scopes.MatchRequired(&auth.Scopes{
		Users: true,
	}) {
		t.Error("Scopes are expected to match required")
	}
	if !scopes.MatchRequired(&auth.Scopes{
		Users: true,
		Nodes: true,
	}) {
		t.Error("Scopes are expected to match required")
	}
	if scopes.MatchRequired(&auth.Scopes{
		Peers: true,
		Nodes: true,
	}) {
		t.Error("Scopes are expected not to match required")
	}
}
