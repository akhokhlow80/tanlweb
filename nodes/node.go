package nodes

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type TLSClientConfig struct {
	ClientKey  string
	ClientCert string
	ServerCert string
}

type Node struct {
	UUID          uuid.UUID
	BaseURL       *url.URL // absolute, https, not nil after parsing
	Name          string
	AllowedIPs    AllowedIPs
	TLSConf       TLSClientConfig
	parsedTLSConf *tls.Config // not nil after parsing
}

type NodeParseErrors struct {
	InvalidUUID          bool
	InvalidBaseURL       bool
	EmptyName            bool
	InvalidClientKeypair bool
	InvalidServerCert    bool
	InvalidAllowedIPs    bool
}

func (errs *NodeParseErrors) ok() bool {
	return !(errs.InvalidUUID ||
		errs.InvalidBaseURL ||
		errs.EmptyName ||
		errs.InvalidClientKeypair ||
		errs.InvalidServerCert ||
		errs.InvalidAllowedIPs)
}

func (errs *NodeParseErrors) Error() string {
	var reasons []string
	if errs.InvalidUUID {
		reasons = append(reasons, "invalid UUID")
	}
	if errs.InvalidBaseURL {
		reasons = append(reasons, "invalid base URL")
	}
	if errs.EmptyName {
		reasons = append(reasons, "empty name")
	}
	if errs.InvalidClientKeypair {
		reasons = append(reasons, "invalid client keypair")
	}
	if errs.InvalidServerCert {
		reasons = append(reasons, "invalid server cert")
	}
	if errs.InvalidAllowedIPs {
		reasons = append(reasons, "invalid allowed ips")
	}
	return "Failed to parse node: " + strings.Join(reasons, ", ")
}

var _ error = (*NodeParseErrors)(nil)

func ParseNode(
	nodeUUID string,
	baseURL string,
	name string,
	allowedIPs string,
	tlsConf TLSClientConfig,
) (Node, *NodeParseErrors) {
	var errs NodeParseErrors

	parsedUUID, err := uuid.Parse(nodeUUID)
	if err != nil {
		errs.InvalidUUID = true
	}

	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil || !parsedBaseURL.IsAbs() || parsedBaseURL.Scheme != "https" {
		errs.InvalidBaseURL = true
	}

	if len(strings.TrimSpace(name)) == 0 {
		errs.EmptyName = true
	}
	validatedName := name

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(tlsConf.ServerCert)) {
		errs.InvalidServerCert = true
	}
	clientCert, err := tls.X509KeyPair([]byte(tlsConf.ClientCert), []byte(tlsConf.ClientKey))
	if err != nil {
		errs.InvalidClientKeypair = true
	}
	parsedTlsConf := tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}

	parsedAllowedIPs, err := ParseAllowedIPs(allowedIPs)
	if err != nil {
		errs.InvalidAllowedIPs = true
	}

	if !errs.ok() {
		return Node{}, &errs
	}

	return Node{
		parsedUUID,
		parsedBaseURL,
		validatedName,
		parsedAllowedIPs,
		tlsConf,
		&parsedTlsConf,
	}, nil
}
