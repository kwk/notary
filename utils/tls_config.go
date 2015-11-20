package utils

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// Client TLS cipher suites (dropping CBC ciphers for client preferred suite set)
var clientCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// Server TLS cipher suites
var serverCipherSuites = append(clientCipherSuites, []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}...)

func poolFromFile(filename string) (*x509.CertPool, error) {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, fmt.Errorf(
			"Unable to parse certificates from %s", filename)
	}
	if len(pool.Subjects()) == 0 {
		return nil, fmt.Errorf(
			"No certificates parsed from %s", filename)
	}
	return pool, nil
}

// ServerTLSOpts generates a tls configuration for servers using the
// provided parameters.
type ServerTLSOpts struct {
	ServerCertFile string `mapstructure:"tls_cert_file"`
	ServerKeyFile  string `mapstructure:"tls_key_file"`
	ClientCAFile   string `mapstructure:"client_ca_file"`
}

// ConfigureServerTLS specifies a set of ciphersuites, the server cert and key,
// and optionally client authentication.  Note that a tls configuration is
// constructed that either requires and verifies client authentication or
// doesn't deal with client certs at all. Nothing in the middle.
//
// Also note that if the client CA file contains invalid data, behavior is not
// guaranteed.  Currently (as of Go 1.5.1) only the valid certificates up to
// the bad data will be parsed and added the client CA pool.
func ConfigureServerTLS(opts *ServerTLSOpts) (*tls.Config, error) {
	keypair, err := tls.LoadX509KeyPair(
		opts.ServerCertFile, opts.ServerKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites:             serverCipherSuites,
		Certificates:             []tls.Certificate{keypair},
		Rand:                     rand.Reader,
	}

	if opts.ClientCAFile != "" {
		pool, err := poolFromFile(opts.ClientCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// ClientTLSOpts is a struct that contains options to pass to
// ConfigureClientTLS
type ClientTLSOpts struct {
	RootCAFile         string `json:"tls_ca_file"`
	ServerName         string `json:"hostname"`
	InsecureSkipVerify bool   `json:"-"`
	ClientCertFile     string `json:"tls_client_cert"`
	ClientKeyFile      string `json:"tls_client_key"`
}

// ConfigureClientTLS generates a tls configuration for clients using the
// provided parameters.
///
// Note that if the root CA file contains invalid data, behavior is not
// guaranteed.  Currently (as of Go 1.5.1) only the valid certificates up to
// the bad data will be parsed and added the root CA pool.
func ConfigureClientTLS(opts *ClientTLSOpts) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       clientCipherSuites,
		ServerName:         opts.ServerName,
	}

	if opts.RootCAFile != "" {
		pool, err := poolFromFile(opts.RootCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	if opts.ClientCertFile != "" || opts.ClientKeyFile != "" {
		keypair, err := tls.LoadX509KeyPair(
			opts.ClientCertFile, opts.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{keypair}
	}

	return tlsConfig, nil
}
