package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/docker/notary/signer/client"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	Cert = "../../fixtures/notary-server.crt"
	Key  = "../../fixtures/notary-server.key"
	Root = "../../fixtures/root-ca.crt"
)

// initializes a viper object with test configuration
func configure(jsonConfig []byte) *viper.Viper {
	config := viper.New()
	config.SetConfigType("json")
	config.ReadConfig(bytes.NewBuffer(jsonConfig))
	return config
}

// If neither the cert nor the key are provided, a nil tls config is returned.
func TestServerTLSMissingCertAndKey(t *testing.T) {
	tlsConfig, err := serverTLS(configure([]byte(`{"server": {}}`)))
	assert.NoError(t, err)
	assert.Nil(t, tlsConfig)
}

// Cert and Key either both have to be empty or both have to be provided.
func TestServerTLSMissingCertAndOrKey(t *testing.T) {
	configs := []string{
		fmt.Sprintf(`{"tls_cert_file": "%s"}`, Cert),
		fmt.Sprintf(`{"tls_key_file": "%s"}`, Key),
	}
	for _, serverConfig := range configs {
		config := configure(
			[]byte(fmt.Sprintf(`{"server": %s}`, serverConfig)))
		tlsConfig, err := serverTLS(config)
		assert.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.True(t,
			strings.Contains(err.Error(), "Partial TLS configuration found."))
	}
}

// The rest of the functionality of serverTLS depends upon
// utils.ConfigureServerTLS, so this test just asserts that if successful,
// the correct tls.Config is returned based on all the configuration parameters
func TestServerTLSSuccess(t *testing.T) {
	keypair, err := tls.LoadX509KeyPair(Cert, Key)
	assert.NoError(t, err, "Unable to load cert and key for testing")

	config := fmt.Sprintf(
		`{"server": {"tls_cert_file": "%s", "tls_key_file": "%s"}}`,
		Cert, Key)
	tlsConfig, err := serverTLS(configure([]byte(config)))
	assert.NoError(t, err)
	assert.Equal(t, []tls.Certificate{keypair}, tlsConfig.Certificates)
}

// The rest of the functionality of serverTLS depends upon
// utils.ConfigureServerTLS, so this test just asserts that if it fails,
// the error is propogated.
func TestServerTLSFailure(t *testing.T) {
	config := fmt.Sprintf(
		`{"server": {"tls_cert_file": "non-exist", "tls_key_file": "%s"}}`,
		Key)
	tlsConfig, err := serverTLS(configure([]byte(config)))
	assert.Error(t, err)
	assert.Nil(t, tlsConfig)
	assert.True(t, strings.Contains(err.Error(), "Unable to set up TLS"))
}

// Various configurations that result in a local trust service being returned,
// with an ED22519 algorithm no matter what was specified.  No health function
// is configured.
func TestGetLocalTrustService(t *testing.T) {
	localConfigs := []string{
		`{"trust_service": {"type": "bruhaha", "key_algorithm": "rsa"}}`,
		`{"trust_service": {"type": "local", "key_algorithm": "rsa"}}`,
		`{}`,
	}
	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	for _, config := range localConfigs {
		trust, algo, err := getTrustService(configure([]byte(config)),
			client.NewNotarySigner, fakeRegister)
		assert.NoError(t, err)
		assert.IsType(t, &signed.Ed25519{}, trust)
		assert.Equal(t, data.ED25519Key, algo)
	}
	// no health function ever registered
	assert.Equal(t, 0, registerCalled)
}

// Various configurations that result in a local trust service being returned,
// with an ED22519 algorithm no matter what was specified.  No health function
// is configured.
func TestGetTrustServiceInvalidKeyAlgorithm(t *testing.T) {
	configTemplate := `
	{
		"trust_service": {
			"type": "remote",
			"hostname": "blah",
			"port": "1234",
			"key_algorithm": "%s"
		}
	}`
	badKeyAlgos := []string{
		fmt.Sprintf(configTemplate, ""),
		fmt.Sprintf(configTemplate, data.ECDSAx509Key),
		fmt.Sprintf(configTemplate, "random"),
	}
	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	for _, config := range badKeyAlgos {
		_, _, err := getTrustService(configure([]byte(config)),
			client.NewNotarySigner, fakeRegister)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key algorithm")
	}
	// no health function ever registered
	assert.Equal(t, 0, registerCalled)
}

// template to be used for testing TLS parsing with the trust service
var trustTLSConfigTemplate = `
	{
		"trust_service": {
			"type": "remote",
			"hostname": "notary-signer",
			"port": "1234",
			"key_algorithm": "ecdsa",
			%s
		}
	}`

// Client cert and Key either both have to be empty or both have to be
// provided.
func TestGetTrustServiceTLSMissingCertOrKey(t *testing.T) {
	configs := []string{
		fmt.Sprintf(`"tls_client_cert": "%s"`, Cert),
		fmt.Sprintf(`"tls_client_key": "%s"`, Key),
	}
	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	for _, clientTLSConfig := range configs {
		jsonConfig := fmt.Sprintf(trustTLSConfigTemplate, clientTLSConfig)
		config := configure([]byte(jsonConfig))
		_, _, err := getTrustService(config, client.NewNotarySigner,
			fakeRegister)
		assert.Error(t, err)
		assert.True(t,
			strings.Contains(err.Error(), "Partial TLS configuration found."))
	}
	// no health function ever registered
	assert.Equal(t, 0, registerCalled)
}

// If no TLS configuration is provided for the host server, a tls config with
// the provided serverName is still returned.
func TestGetTrustServiceNoTLSConfig(t *testing.T) {
	config := `{
		"trust_service": {
			"type": "remote",
			"hostname": "notary-signer",
			"port": "1234",
			"key_algorithm": "ecdsa"
		}
	}`
	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	var tlsConfig *tls.Config
	var fakeNewSigner = func(_, _ string, c *tls.Config) *client.NotarySigner {
		tlsConfig = c
		return &client.NotarySigner{}
	}

	trust, algo, err := getTrustService(configure([]byte(config)),
		fakeNewSigner, fakeRegister)
	assert.NoError(t, err)
	assert.IsType(t, &client.NotarySigner{}, trust)
	assert.Equal(t, "ecdsa", algo)
	assert.Equal(t, "notary-signer", tlsConfig.ServerName)
	assert.Nil(t, tlsConfig.RootCAs)
	assert.Nil(t, tlsConfig.Certificates)
	// health function registered
	assert.Equal(t, 1, registerCalled)
}

// The rest of the functionality of getTrustService depends upon
// utils.ConfigureClientTLS, so this test just asserts that if successful,
// the correct tls.Config is returned based on all the configuration parameters
func TestGetTrustServiceTLSSuccess(t *testing.T) {
	keypair, err := tls.LoadX509KeyPair(Cert, Key)
	assert.NoError(t, err, "Unable to load cert and key for testing")

	tlspart := fmt.Sprintf(`"tls_client_cert": "%s", "tls_client_key": "%s"`,
		Cert, Key)

	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	var tlsConfig *tls.Config
	var fakeNewSigner = func(_, _ string, c *tls.Config) *client.NotarySigner {
		tlsConfig = c
		return &client.NotarySigner{}
	}

	trust, algo, err := getTrustService(configure([]byte(
		fmt.Sprintf(trustTLSConfigTemplate, tlspart))),
		fakeNewSigner, fakeRegister)
	assert.NoError(t, err)
	assert.IsType(t, &client.NotarySigner{}, trust)
	assert.Equal(t, "ecdsa", algo)
	assert.Equal(t, "notary-signer", tlsConfig.ServerName)
	assert.Equal(t, []tls.Certificate{keypair}, tlsConfig.Certificates)
	// health function registered
	assert.Equal(t, 1, registerCalled)
}

// The rest of the functionality of getTrustService depends upon
// utils.ConfigureServerTLS, so this test just asserts that if it fails,
// the error is propogated.
func TestGetTrustServiceTLSFailure(t *testing.T) {
	tlspart := fmt.Sprintf(`"tls_client_cert": "none", "tls_client_key": "%s"`,
		Key)

	var registerCalled = 0
	var fakeRegister = func(_ string, _ func() error, _ time.Duration) {
		registerCalled++
	}

	_, _, err := getTrustService(configure([]byte(
		fmt.Sprintf(trustTLSConfigTemplate, tlspart))),
		client.NewNotarySigner, fakeRegister)

	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(),
		"Unable to configure TLS to the trust service"))

	// no health function ever registered
	assert.Equal(t, 0, registerCalled)
}
