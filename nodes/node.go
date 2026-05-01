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
	TLSConf       TLSClientConfig
	parsedTLSConf *tls.Config // not nil after parsing
}

type NodeParseErrors struct {
	InvalidUUID          bool
	InvalidBaseURL       bool
	EmptyName            bool
	InvalidClientKeypair bool
	InvalidServerCert    bool
}

func (errs *NodeParseErrors) ok() bool {
	return !(errs.InvalidUUID ||
		errs.InvalidBaseURL ||
		errs.EmptyName ||
		errs.InvalidClientKeypair ||
		errs.InvalidServerCert)
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
	return "Failed to parse node: " + strings.Join(reasons, ", ")
}

var _ error = (*NodeParseErrors)(nil)

func ParseNode(
	UUID string,
	baseURL string,
	Name string,
	tlsConf TLSClientConfig,
) (Node, *NodeParseErrors) {
	var errs NodeParseErrors

	parsedUUID, err := uuid.Parse(UUID)
	if err != nil {
		errs.InvalidUUID = true
	}

	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil || !parsedBaseURL.IsAbs() || parsedBaseURL.Scheme != "https" {
		errs.InvalidBaseURL = true
	}

	if len(strings.TrimSpace(Name)) == 0 {
		errs.EmptyName = true
	}
	validatedName := Name

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

	if !errs.ok() {
		return Node{}, &errs
	}

	return Node{
		parsedUUID,
		parsedBaseURL,
		validatedName,
		tlsConf,
		&parsedTlsConf,
	}, nil
}
