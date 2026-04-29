package nodes

import (
	"slices"
	"strings"
)

func sortPeers(peers []PeerFromNode) {
	slices.SortFunc(peers, func(a, b PeerFromNode) int {
		return strings.Compare(a.PublicKey, b.PublicKey)
	})
}
