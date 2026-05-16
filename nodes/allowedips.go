package nodes

import (
	"fmt"
	"net/netip"
	"strings"
)

type AllowedIPs []netip.Prefix

func (ips AllowedIPs) String() string {
	var sb strings.Builder
	for i, pref := range ips {
		sb.WriteString(pref.String())
		if i != len(ips)-1 {
			sb.WriteRune(',')
		}
	}
	return sb.String()
}

func ParseAllowedIPs(text string) (AllowedIPs, error) {
	var prefs []netip.Prefix
	strPrefs := strings.SplitSeq(text, ",")
	for strPref := range strPrefs {
		strPref = strings.Trim(strPref, " \n\t")
		pref, err := netip.ParsePrefix(strPref)
		if err != nil {
			return nil, err
		}
		if pref.Masked().Addr() != pref.Addr() {
			return nil, fmt.Errorf("Non-zero host bits in prefix %s", pref.String())
		}
		prefs = append(prefs, pref)
	}
	return prefs, nil
}
