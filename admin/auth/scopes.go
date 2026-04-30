package auth

import (
	"fmt"
	"regexp"
	"strings"
)

type ScopePermissions int

const (
	R ScopePermissions = 1
	W ScopePermissions = 2
)

func (perm ScopePermissions) String() string {
	var s string
	if perm&R != 0 {
		s += "r"
	}
	if perm&W != 0 {
		s += "w"
	}
	return s
}

func (perm ScopePermissions) HasR() bool {
	return perm&R != 0
}

func (perm ScopePermissions) HasW() bool {
	return perm&W != 0
}

type Scopes struct {
	Users ScopePermissions
	Nodes ScopePermissions
	Peers ScopePermissions
}

var FullScope = Scopes{
	Users: R | W,
	Nodes: R | W,
	Peers: R | W,
}

var scopeRegex = regexp.MustCompile(`^\s*(\w+):(r)?(w)?\s*$`)

func ParseScopes(scopesStr string) (Scopes, error) {
	var parsed Scopes
	if len(scopesStr) == 0 {
		return parsed, nil
	}
	for scope := range strings.SplitSeq(scopesStr, ",") {
		groups := scopeRegex.FindStringSubmatch(scope)
		if groups == nil {
			return Scopes{}, fmt.Errorf("Failed to parse scope `%s`", scope)
		}

		var perm ScopePermissions
		if groups[2] == "r" {
			perm |= R
		}
		if groups[3] == "w" {
			perm |= W
		}

		switch groups[1] {
		case "users":
			parsed.Users = perm
		case "nodes":
			parsed.Nodes = perm
		case "peers":
			parsed.Peers = perm
		default:
			return Scopes{}, fmt.Errorf("Unknown scope `%s` found while parsing scopes `%s`", scope, scopesStr)
		}
	}
	return parsed, nil
}

func (scopes *Scopes) String() string {
	var scopesArr []string
	if scopes.Users != 0 {
		scopesArr = append(scopesArr, "users:"+scopes.Users.String())
	}
	if scopes.Nodes != 0 {
		scopesArr = append(scopesArr, "nodes:"+scopes.Nodes.String())
	}
	if scopes.Peers != 0 {
		scopesArr = append(scopesArr, "peers:"+scopes.Peers.String())
	}
	return strings.Join(scopesArr, ",")
}

func impl(a, b bool) bool {
	return !a || b
}

func permImpl(a, b ScopePermissions) bool {
	return impl(a&R != 0, b&R != 0) && impl(a&W != 0, b&W != 0)
}

func (scopes *Scopes) MatchRequired(required *Scopes) bool {
	return permImpl(required.Users, scopes.Users) &&
		permImpl(required.Nodes, scopes.Nodes) &&
		permImpl(required.Peers, scopes.Peers)
}
