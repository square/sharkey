![say no to TOFU](sharkey.png)

# sharkey

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
![development status](https://img.shields.io/badge/status-alpha-orange.svg)
[![build status](https://travis-ci.org/square/sharkey.svg?branch=master)](https://travis-ci.org/square/sharkey)
[![report](https://goreportcard.com/badge/github.com/square/sharkey)](https://goreportcard.com/report/github.com/square/sharkey)

Sharkey is a service for managing certificates for use by OpenSSH.

![sharks](dancing-sharks.png)

Sharkey has a client component and a server component. The server is
responsible for issuing signed host certificates, the client is responsible for
installing host certificates on machines.

### Build

Check out the repository, and build client/server:

    go build -o sharkey-client ./client
    go build -o sharkey-server ./server

### Server

The server component accepts requests and issues short lived host certificates.

Clients send their public key to the server (via TLS with mutual
authentication) periodically. The server authenticates the client by checking
that its certificate is valid for the requested hostname. If everything looks
good, the server will take the public key in the request and issue an OpenSSH
host certificate for the requested hostname.

A log of all issued certificates is stored in a database. The server can
generate a `known_hosts` file from the issuance log if required.  

Usage:

    usage: sharkey-server --config=CONFIG [<flags>] <command> [<args> ...]
    
    Certificate issuer of the ssh-ca system.
    
    Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --config=CONFIG  Path to config file for server.
      --version        Show application version.
    
    Commands:
      help [<command>...]
        Show help.
    
      start
        Run the sharkey server.
    
      migrate [<flags>]
        Set up database/run migrations.

Configuration (example):

    # SQLite database
    # ---
    db:
      address: /path/to/sharkey.db
      type: sqlite

    # MySQL database
    # ---
    # db:
    #   username: root
    #   password: password
    #   address: hostname:port
    #   schema: ssh_ca
    #   type: mysql
    #   tls:                                       # MySQL TLS config (optional)
    #     ca: /path/to/mysql-ca-bundle.pem
    #     cert: /path/to/mysql-client-cert.pem     # MySQL client cert
    #     key: /path/to/mysql-client-cert-key.pem  # MySQL client cert key
    #     min_version: 1.2                         # Min. TLS version

    # Server listening address
    listen_addr: "0.0.0.0:8080"

    # TLS config for serving requests
    # ---
    tls:
      ca: /path/to/ca-bundle.pem
      cert: /path/to/server-certificate.pem 
      key: /path/to/server-certificate-key.pem
      min_version: 1.2                             # Min. TLS version (optional) 

    # Signing key (from ssh-keygen)
    signing_key: /path/to/ca-signing-key 

    # Lifetime/validity duration for generated host certificates
    cert_duration: 168h

    # Optional suffix to strip from client hostnames when generating certificates.
    # This is useful if all your machines have a common TLD/domain that you don't
    # want to include in generated certificates. Leave empty to disable.
    strip_suffix: ".squareup.com"

A signing key for generating host certificates can be generated with `ssh-keygen`.

#### Database

Sharkey supports both SQLite and MySQL. There is a built-in command in the
server binary to manage migrations (based on [goose][goose]).

To run migrations on a configured database:

    # SQLite
    ./sharkey-server --config=[CONFIG] migrate --migrations=db/sqlite

    # MySQL
    ./sharkey-server --config=[CONFIG] migrate --migrations=db/mysql

You can also manage migrations using the [goose][goose] command-line utility.
See the [goose][goose] documentation for more info.

[goose]: https://bitbucket.org/liamstask/goose

### Client

The client component periodically requests a new host certificate from the
server and installs it on the machine.

The client will use a TLS client certificate to make a connection to the server
and authenticate itself. This assumes that there is a long-lived certificate
and key installed on each machine that uses the client. We then periodically
read the host key for the locally running OpenSSH (`host_key`), send it to the
server, and retrieve a signed host certificate based on that key. The signed
host certificate is then installed on the machine (`signed_cert`).

Usage:

    usage: sharkey-client --config=CONFIG [<flags>]
    
    Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --config=CONFIG  Path to yaml config file for setup
      --version        Show application version.

Configuration (example):

    # Server address
    request_addr: "https://sharkey-server.example:8080"

    # TLS config for making requests
    # ---
    tls:
      ca: /path/to/ca-bundle.pem
      cert: /path/to/client-certificate.pem 
      key: /path/to/client-certificate-key.pem

    # OpenSSH host key (unsigned)
    host_key: /etc/ssh/ssh_host_rsa_key.pub

    # Where to install the signed host certificate
    signed_cert: /etc/ssh/ssh_host_rsa_key_signed.pub

    # Where to install the known_hosts file
    known_hosts: /etc/ssh/known_hosts

    # How often to refresh/request new certificate
    sleep: "24h"

    # Refresh/request new certificate on start
    ping_on_start: true

OpenSSH will have to be configured to read the signed host certificate (this is
with the `HostCertificate` config option in `sshd_config`). If the signed host
certificate is missing from disk, OpenSSH will fall back to TOFU with the
default host key. Therefore, it should always be safe to configure a host
certificate; even if the Sharkey client fails you can still SSH into your
machine. 
