<!--[metadata]>
+++
title = "Notary CLI"
description = "Description of the Notary CLI"
keywords = ["docker, notary, trust, image, signing, repository, cli"]
[menu.main]
parent="mn_notary"
+++
<![end-metadata]-->

# Notary Server

The notary repository comes with Dockerfiles and a docker-compose file
to facilitate development. Simply run the following commands to start
a notary server with a temporary MySQL database in containers:

```
$ docker-compose build
$ docker-compose up
```

If you are on Mac OSX with boot2docker or kitematic, you'll need to
update your hosts file such that the name `notary` is associated with
the IP address of your VM (for boot2docker, this can be determined
by running `boot2docker ip`, with kitematic, `echo $DOCKER_HOST` should
show the IP of the VM). If you are using the default Linux setup,
you need to add `127.0.0.1 notary` to your hosts file.

## Successfully connecting over TLS

By default notary-server runs with TLS with certificates signed by a local
CA. In order to be able to successfully connect to it using
either `curl` or `openssl`, you will have to use the root CA file in `fixtures/root-ca.crt`.

OpenSSL example:

`openssl s_client -connect notary-server:4443 -CAfile fixtures/root-ca.crt`

## Compiling Notary Server

Prerequisites:

- Go = 1.5.1
- [godep](https://github.com/tools/godep) installed
- libtool development headers installed

Install dependencies by running `godep restore`.

From the root of this git repository, run `make binaries`. This will
compile the `notary`, `notary-server`, and `notary-signer` applications and
place them in a `bin` directory at the root of the git repository (the `bin`
directory is ignored by the .gitignore file).

`notary-signer` depends upon `pkcs11`, which requires that libtool headers be installed (`libtool-dev` on Ubuntu, `libtool-ltdl-devel` on CentOS/RedHat). If you are using Mac OS, you can `brew install libtool`, and run `make binaries` with the following environment variables (assuming a standard installation of Homebrew):

```sh
export CPATH=/usr/local/include:${CPATH}
export LIBRARY_PATH=/usr/local/lib:${LIBRARY_PATH}
```

## Running Notary Server

The `notary-server` application has the following usage:

```
$ bin/notary-server --help
usage: bin/notary-serve
  -config="": Path to configuration file
  -debug=false: Enable the debugging server on localhost:8080
```

## Configuring Notary Server

The configuration file must be a json file with the following format:

```json
{
    "server": {
        "addr": ":4443",
        "tls_cert_file": "./fixtures/notary-server.crt",
        "tls_key_file": "./fixtures/notary-server.key"
    },
    "logging": {
        "level": 5
    }
}
```

The pem and key provided in fixtures are purely for local development and
testing. For production, you must create your own keypair and certificate,
either via the CA of your choice, or a self signed certificate.

If using the pem and key provided in fixtures, either:
- Add `fixtures/root-ca.crt` to your trusted root certificates
- Use the default configuration for notary client that loads the CA root for you by using the flag `-c ./cmd/notary/config.json`
- Disable TLS verification by adding the following option notary configuration file in `~/.notary/config.json`:

            "skipTLSVerify": true

Otherwise, you will see TLS errors or X509 errors upon initializing the
notary collection:

```
$ notary list diogomonica.com/openvpn
* fatal: Get https://notary-server:4443/v2/: x509: certificate signed by unknown authority
$ notary list diogomonica.com/openvpn -c cmd/notary/config.json
latest b1df2ad7cbc19f06f08b69b4bcd817649b509f3e5420cdd2245a85144288e26d 4056
```
