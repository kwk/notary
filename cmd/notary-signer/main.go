// +build pkcs11

package main

import (
	"crypto/tls"
	"database/sql"
	"errors"
	_ "expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/docker/distribution/health"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/signer"
	"github.com/docker/notary/signer/api"
	"github.com/docker/notary/signer/keydbstore"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/utils"
	"github.com/docker/notary/version"
	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/pkcs11"
	"github.com/spf13/viper"

	"github.com/Sirupsen/logrus"
	pb "github.com/docker/notary/proto"
)

const (
	debugAddr       = "localhost:8080"
	dbType          = "mysql"
	envPrefix       = "NOTARY_SIGNER"
	defaultAliasEnv = "DEFAULT_ALIAS"
	pinCode         = "PIN"
)

var (
	debug      bool
	configFile string
	mainViper  = viper.New()
)

func init() {
	// set default log level to Error
	mainViper.SetDefault("logging", map[string]interface{}{"level": 2})

	mainViper.SetEnvPrefix(envPrefix)
	mainViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	mainViper.AutomaticEnv()

	// Setup flags
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.BoolVar(&debug, "debug", false, "show the version and exit")
}

func passphraseRetriever(keyName, alias string, createNew bool, attempts int) (passphrase string, giveup bool, err error) {
	passphrase = mainViper.GetString(strings.ToUpper(alias))

	if passphrase == "" {
		return "", false, errors.New("expected env variable to not be empty: " + alias)
	}

	return passphrase, false, nil
}

// validates TLS configuration options and sets up the TLS for the signer
// http + grpc server
func signerTLS(tlsConfig *utils.ServerTLSOpts, printUsage bool) (*tls.Config, error) {
	if tlsConfig.ServerCertFile == "" || tlsConfig.ServerKeyFile == "" {
		if printUsage {
			usage()
		}
		return nil, fmt.Errorf("Certificate and key are mandatory")
	}

	tlsConfig, err := utils.ConfigureServerTLS(config)
	if err != nil {
		return nil, fmt.Errorf("Unable to set up TLS: %s", err.Error())
	}
	return tlsConfig, nil
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if debug {
		go debugServer(debugAddr)
	}

	// when the signer starts print the version for debugging and issue logs later
	logrus.Infof("Version: %s, Git commit: %s", version.NotaryVersion, version.GitCommit)

	filename := filepath.Base(configFile)
	ext := filepath.Ext(configFile)
	configPath := filepath.Dir(configFile)

	mainViper.SetConfigType(strings.TrimPrefix(ext, "."))
	mainViper.SetConfigName(strings.TrimSuffix(filename, ext))
	mainViper.AddConfigPath(configPath)
	// set default log level to Error
	mainViper.SetDefault("logging.level", "error")
	err := mainViper.ReadInConfig()
	if err != nil {
		logrus.Error("Viper Error: ", err.Error())
		logrus.Error("Could not read config at ", configFile)
		os.Exit(1)
	}

	var config util.ServerConfiguration
	err = mainViper.Unmarshal(&config)
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	if config.Logging.Level != nil {
		fmt.Println("LOGGING level", config.Logging.Level)
		logrus.SetLevel(config.Logging.Level.ToLogrus())
	}

	tlsConfig, err := signerTLS(mainViper, true)
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	cryptoServices := make(signer.CryptoServiceIndex)

	emptyStorage := utils.Storage{}
	if config.Storage == emptyStorage {
		usage()
		log.Fatalf("Must specify a MySQL backend.")
	}

	dbSQL, err := sql.Open(config.Storage.Backend, config.Storage.URL)
	if err != nil {
		log.Fatalf("failed to open the database: %s, %v", config.Storage.URL, err)
	}

	defaultAlias := mainViper.GetString(defaultAliasEnv)
	logrus.Debug("Default Alias: ", defaultAlias)
	keyStore, err := keydbstore.NewKeyDBStore(passphraseRetriever, defaultAlias, configDBType, dbSQL)
	if err != nil {
		log.Fatalf("failed to create a new keydbstore: %v", err)
	}

	health.RegisterPeriodicFunc(
		"DB operational", keyStore.HealthCheck, time.Second*60)

	cryptoService := cryptoservice.NewCryptoService("", keyStore)

	cryptoServices[data.ED25519Key] = cryptoService
	cryptoServices[data.ECDSAKey] = cryptoService

	//RPC server setup
	kms := &api.KeyManagementServer{CryptoServices: cryptoServices,
		HealthChecker: health.CheckStatus}
	ss := &api.SignerServer{CryptoServices: cryptoServices,
		HealthChecker: health.CheckStatus}

	rpcAddr := mainViper.GetString("server.grpc_addr")
	lis, err := net.Listen("tcp", rpcAddr)
	if err != nil {
		log.Fatalf("failed to listen %v", err)
	}
	creds := credentials.NewTLS(tlsConfig)
	opts := []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(opts...)

	pb.RegisterKeyManagementServer(grpcServer, kms)
	pb.RegisterSignerServer(grpcServer, ss)

	go grpcServer.Serve(lis)

	httpAddr := mainViper.GetString("server.http_addr")
	if httpAddr == "" {
		log.Fatalf("Server address is required")
	}
	//HTTP server setup
	server := http.Server{
		Addr:      httpAddr,
		Handler:   api.Handlers(cryptoServices),
		TLSConfig: tlsConfig,
	}

	if debug {
		log.Println("RPC server listening on", rpcAddr)
		log.Println("HTTP server listening on", httpAddr)
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("HTTPS server failed to start:", err)
	}
}

func usage() {
	log.Println("usage:", os.Args[0], "<config>")
	flag.PrintDefaults()
}

// debugServer starts the debug server with pprof, expvar among other
// endpoints. The addr should not be exposed externally. For most of these to
// work, tls cannot be enabled on the endpoint, so it is generally separate.
func debugServer(addr string) {
	log.Println("Debug server listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("error listening on debug interface: %v", err)
	}
}

// SetupHSMEnv is a method that depends on the existences
func SetupHSMEnv(libraryPath, pin string) (*pkcs11.Ctx, pkcs11.SessionHandle) {
	p := pkcs11.New(libraryPath)

	if p == nil {
		log.Fatalf("Failed to init library")
	}

	if err := p.Initialize(); err != nil {
		log.Fatalf("Initialize error %s\n", err.Error())
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatalf("Failed to list HSM slots %s", err)
	}
	// Check to see if we got any slots from the HSM.
	if len(slots) < 1 {
		log.Fatalln("No HSM Slots found")
	}

	// CKF_SERIAL_SESSION: TRUE if cryptographic functions are performed in serial with the application; FALSE if the functions may be performed in parallel with the application.
	// CKF_RW_SESSION: TRUE if the session is read/write; FALSE if the session is read-only
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("Failed to Start Session with HSM %s", err)
	}

	if err = p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		log.Fatalf("User PIN %s\n", err.Error())
	}

	return p, session
}

func cleanup(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) {
	ctx.Destroy()
	ctx.Finalize()
	ctx.CloseSession(session)
	ctx.Logout(session)
}
