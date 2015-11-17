package main

import (
	"crypto/tls"
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/bugsnag/bugsnag-go"
	"github.com/docker/distribution/health"
	_ "github.com/docker/distribution/registry/auth/htpasswd"
	_ "github.com/docker/distribution/registry/auth/token"
	"github.com/docker/notary/signer/client"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/net/context"

	bugsnag_hook "github.com/Sirupsen/logrus/hooks/bugsnag"
	"github.com/docker/notary/server"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/utils"
	"github.com/docker/notary/version"
	"github.com/spf13/viper"
)

// DebugAddress is the debug server address to listen on
const DebugAddress = "localhost:8080"

var (
	debug      bool
	configFile string
	mainViper  = viper.New()
)

func init() {
	// set default log level to Error
	mainViper.SetDefault("logging", map[string]interface{}{"level": 2})

	// Setup flags
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.BoolVar(&debug, "debug", false, "Enable the debugging server on localhost:8080")
}

// optionally sets up TLS for the server - if no TLS configuration is
// specified, TLS is not enabled.
func serverTLS(configuration *viper.Viper) (*tls.Config, error) {
	tlsCertFile := configuration.GetString("server.tls_cert_file")
	tlsKeyFile := configuration.GetString("server.tls_key_file")

	if tlsCertFile == "" && tlsKeyFile == "" {
		return nil, nil
	} else if tlsCertFile == "" || tlsKeyFile == "" {
		return nil, fmt.Errorf("Partial TLS configuration found. Either include both a cert and key file in the configuration, or include neither to disable TLS.")
	}

	tlsConfig, err := utils.ConfigureServerTLS(&utils.ServerTLSOpts{
		ServerCertFile: tlsCertFile,
		ServerKeyFile:  tlsKeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to set up TLS: %s", err.Error())
	}
	return tlsConfig, nil
}

// sets up TLS for the GRPC connection to notary-signer
func grpcTLS(configuration *viper.Viper) (*tls.Config, error) {
	rootCA := configuration.GetString("trust_service.tls_ca_file")
	serverName := configuration.GetString("trust_service.hostname")
	clientCert := configuration.GetString("trust_service.tls_client_cert")
	clientKey := configuration.GetString("trust_service.tls_client_key")

	if (clientCert == "" && clientKey != "") || (clientCert != "" && clientKey == "") {
		return nil, fmt.Errorf("Partial TLS configuration found. Either include both a client cert and client key file in the configuration, or include neither.")
	}

	tlsConfig, err := utils.ConfigureClientTLS(&utils.ClientTLSOpts{
		RootCAFile:     rootCA,
		ServerName:     serverName,
		ClientCertFile: clientCert,
		ClientKeyFile:  clientKey,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"Unable to configure TLS to the trust service: %s", err.Error())
	}
	return tlsConfig, nil
}

// parses the configuration and determines which trust service and key algorithm
// to return
func getTrustService(configuration *viper.Viper,
	signerFactory func(string, string, *tls.Config) *client.NotarySigner,
	healthRegister func(string, func() error, time.Duration)) (
	signed.CryptoService, string, error) {

	if configuration.GetString("trust_service.type") != "remote" {
		logrus.Info("Using local signing service")
		return signed.NewEd25519(), data.ED25519Key, nil
	}

	keyAlgo := configuration.GetString("trust_service.key_algorithm")
	if keyAlgo != data.ED25519Key && keyAlgo != data.ECDSAKey && keyAlgo != data.RSAKey {
		return nil, "", fmt.Errorf("invalid key algorithm configured: %s", keyAlgo)
	}

	clientTLS, err := grpcTLS(configuration)
	if err != nil {
		return nil, "", err
	}

	logrus.Info("Using remote signing service")

	notarySigner := signerFactory(
		configuration.GetString("trust_service.hostname"),
		configuration.GetString("trust_service.port"),
		clientTLS,
	)

	minute := 1 * time.Minute
	healthRegister(
		"Trust operational",
		// If the trust service fails, the server is degraded but not
		// exactly unheatlthy, so always return healthy and just log an
		// error.
		func() error {
			err := notarySigner.CheckHealth(minute)
			if err != nil {
				logrus.Error("Trust not fully operational: ", err.Error())
			}
			return nil
		},
		minute)
	return notarySigner, keyAlgo, nil
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if debug {
		go debugServer(DebugAddress)
	}

	// when the server starts print the version for debugging and issue logs later
	logrus.Infof("Version: %s, Git commit: %s", version.NotaryVersion, version.GitCommit)

	ctx := context.Background()

	filename := filepath.Base(configFile)
	ext := filepath.Ext(configFile)
	configPath := filepath.Dir(configFile)

	mainViper.SetConfigType(strings.TrimPrefix(ext, "."))
	mainViper.SetConfigName(strings.TrimSuffix(filename, ext))
	mainViper.AddConfigPath(configPath)

	// Automatically accept configuration options from the environment
	mainViper.SetEnvPrefix("NOTARY_SERVER")
	mainViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	mainViper.AutomaticEnv()

	err := mainViper.ReadInConfig()
	if err != nil {
		logrus.Error("Viper Error: ", err.Error())
		logrus.Error("Could not read config at ", configFile)
		os.Exit(1)
	}
	lvl, err := logrus.ParseLevel(mainViper.GetString("logging.level"))
	if err != nil {
		lvl = logrus.ErrorLevel
		logrus.Error("Could not parse log level from config. Defaulting to ErrorLevel")
	}
	logrus.SetLevel(lvl)

	// set up bugsnag and attach to logrus
	bugs := mainViper.GetString("reporting.bugsnag")
	if bugs != "" {
		apiKey := mainViper.GetString("reporting.bugsnag_api_key")
		releaseStage := mainViper.GetString("reporting.bugsnag_release_stage")
		bugsnag.Configure(bugsnag.Configuration{
			APIKey:       apiKey,
			ReleaseStage: releaseStage,
		})
		hook, err := bugsnag_hook.NewBugsnagHook()
		if err != nil {
			logrus.Error("Could not attach bugsnag to logrus: ", err.Error())
		} else {
			logrus.AddHook(hook)
		}
	}
	trust, keyAlgo, err := getTrustService(mainViper,
		client.NewNotarySigner, health.RegisterPeriodicFunc)
	if err != nil {
		logrus.Fatal(err.Error())
	}
	ctx = context.WithValue(ctx, "keyAlgorithm", keyAlgo)

	if mainViper.GetString("storage.backend") == "mysql" {
		logrus.Info("Using mysql backend")
		dbURL := mainViper.GetString("storage.db_url")
		store, err := storage.NewSQLStorage("mysql", dbURL)
		if err != nil {
			logrus.Fatal("Error starting DB driver: ", err.Error())
			return // not strictly needed but let's be explicit
		}
		health.RegisterPeriodicFunc(
			"DB operational", store.CheckHealth, time.Second*60)
		ctx = context.WithValue(ctx, "metaStore", store)
	} else {
		logrus.Debug("Using memory backend")
		ctx = context.WithValue(ctx, "metaStore", storage.NewMemStorage())
	}

	tlsConfig, err := serverTLS(mainViper)
	if err != nil {
		logrus.Fatal(err.Error())
	}

	logrus.Info("Starting Server")
	err = server.Run(
		ctx,
		mainViper.GetString("server.addr"),
		tlsConfig,
		trust,
		mainViper.GetString("auth.type"),
		mainViper.Get("auth.options"),
	)

	logrus.Error(err.Error())
	return
}

func usage() {
	fmt.Println("usage:", os.Args[0])
	flag.PrintDefaults()
}

// debugServer starts the debug server with pprof, expvar among other
// endpoints. The addr should not be exposed externally. For most of these to
// work, tls cannot be enabled on the endpoint, so it is generally separate.
func debugServer(addr string) {
	logrus.Info("Debug server listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logrus.Fatal("error listening on debug interface: ", err)
	}
}
