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
installing host certificates on machines. Sharkey builds on the trust relationships
of your existing X.509 PKI to manage trusted SSH certificates. Existing X.509
certificates can be minted into SSH certificates, so you don't have to maintain
two separate PKI hierarchies. 

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

    # Server listening address
    listen_addr: "0.0.0.0:8080"

    # TLS config for serving requests
    # ---
    tls:
      ca: /path/to/ca-bundle.pem
      cert: /path/to/server-certificate.pem 
      key: /path/to/server-certificate-key.pem

    # Signing key (from ssh-keygen)
    signing_key: /path/to/ca-signing-key 

    # Lifetime/validity duration for generated host certificates
    cert_duration: 168h

    # Optional suffix to strip from client hostnames when generating certificates.
    # This is useful if all your machines have a common TLD/domain, and you want to
    # include an alias in the generated certificate that doesn't include that suffix.
    # Leave empty to disable
    strip_suffix: ".example.com"

    # Optional set of aliases for hosts. If a hostname matches an alias entry, the
    # listed principals will be added to its certificate. This is useful if you have
    # special hosts that are accessed via CNAME records.
    aliases:
      "host.example.com":
        - "alias1.example.com"
        - "alias2.example.com"

    # Optional set of extra entries to provide to clients when they fetch a known_hosts
    # file. This is useful if you have externally-managed servers in your infrastructure
    # that you want to tell clients about, of if you want to add CA entries to the
    # known_hosts file.
    extra_known_hosts:
      - "@cert-authority *.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBwhA8rKPESjDy4iqTlkBqUlBU2xjwtmFUHY6cutA9TYbB5H/mjxzUpnSNw/HyFWNpysjTSQtHWWBdJdJGU/0aDgFUwbduHeDFxviGVSkOxm2AYn7XJopzITZRqmAmsYXHUBa75RQb+UgIG7EpCoi8hF4ItJV+TT777j1irkXwlMmeDiJEaA+7bPNdUdGw8zRbk0CyeotYVD0griRtkXdfgnQAu+DvBwOuW/uiZaPz/rAVjt4b9fmp6pcFKI3RsBqqn5tQVhKCPVuSwqvIQ7CTVkMClYovlH1/zGe8PG1DHbM9irP98S5j3mVD9W5v3QILpsg24RIS14M8pLarlD6t root@authority"

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

    # List of host keys for OpenSSH server
    host_keys:
      # Here, 'key' is the public key, and 'cert' is where to install the signed cert
      - plain: "/etc/ssh/ssh_host_rsa_key.pub"
        signed: "/etc/ssh/ssh_host_rsa_key-cert.pub"
      # You can specify multiple host keys (e.g. if you have both RSA, ED25519 keys)
      - plain: "/etc/ssh/ssh_host_ed25519_key.pub"
        signed: "/etc/ssh/ssh_host_ed25519_key-cert.pub"

    # Where to install the known_hosts file
    known_hosts: /etc/ssh/known_hosts

    # If set to true, only install authorities in known_hosts file (ignore other machine's host keys).
    known_hosts_authorities_only: false

    # How often to refresh/request new certificate
    sleep: "24h"

    # Command to restart ssh daemon for the host
    ssh_reload: ["sudo", "service", "ssh", "restart"]

OpenSSH will have to be configured to read the signed host certificate (this is
with the `HostCertificate` config option in `sshd_config`). If the signed host
certificate is missing from disk, OpenSSH will fall back to TOFU with the
default host key. Therefore, it should always be safe to configure a host
certificate; even if the Sharkey client fails you can still SSH into your
machine. 
