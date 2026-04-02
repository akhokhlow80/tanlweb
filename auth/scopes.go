package auth

import (
	"fmt"
	"strings"
)

type Scopes struct {
	Users bool
	Nodes bool
	Peers bool
}

func ParseScopes(scopesStr string) (Scopes, error) {
	var parsed Scopes
	if len(scopesStr) == 0 {
		return parsed, nil
	}
	for scope := range strings.SplitSeq(scopesStr, ",") {
		scope = strings.TrimSpace(scope)
		switch scope {
		case "users":
			parsed.Users = true
		case "nodes":
			parsed.Nodes = true
		case "peers":
			parsed.Peers = true
		default:
			return Scopes{}, fmt.Errorf("Unknown scope `%s` found while parsing scopes `%s`", scope, scopesStr)
		}
	}
	return parsed, nil
}

func (scopes *Scopes) String() string {
	var scopesArr []string
	if scopes.Users {
		scopesArr = append(scopesArr, "users")
	}
	if scopes.Nodes {
		scopesArr = append(scopesArr, "nodes")
	}
	if scopes.Peers {
		scopesArr = append(scopesArr, "peers")
	}
	return strings.Join(scopesArr, ",")
}

func implication(a, b bool) bool {
	return !a || b
}

func (scopes *Scopes) MatchRequired(required *Scopes) bool {
	return implication(required.Users, scopes.Users) &&
		implication(required.Nodes, scopes.Nodes) &&
		implication(required.Peers, scopes.Peers)
}
