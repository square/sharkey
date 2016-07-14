# sharkey

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)

Sharkey is a service for managing certificates for use by OpenSSH.

Sharkey has a client component and a server component. The server is
responsible for issuing signed host certificates, the client is responsible for
installing host certificates on machines.

### Build

Check out the repository, and build client/server:

    go build -o sharkey-client ./client
    go build -o sharkey-server ./server

### Server

The server component accepts requests and issues host certificates.

Clients send their public key to the server (via TLS with
mutual authentication) periodically. The server authenticates the client by
checking that its certificate is valid for the requested hostname. If
everything looks good, the server will take the public key in the request and
issue an OpenSSH host certificate for the requested hostname.

A log of all issued certificates is stored in a database. The server can
generate a `known_hosts` file from the issuance log if required. It is also
possible to have the server strip a suffix from all hostnames (e.g. if all your
servers have a common TLD/domain that you don't want in the certificate) via
the `--suffix` flag. 

Usage:

    usage: sharkey-server --config=CONFIG [<flags>]

    Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --config=CONFIG  Path to yaml config file for setup
      --suffix=SUFFIX  Suffix of hostnames that will be supplied to server.
      --version        Show application version.

Configuration (example):

    db:
      username: root
      address: test/test.db
      schema: ssh_ca
      type: sqlite
    # sample mysql config
    # db:
    #   username: root
    #   password: password
    #   address: ip:port
    #   schema: db_name
    #   type: mysql
    # sample mysql tls config
    # db:
    #   username: root
    #   address: ip:port
    #   type: mysql
    #   tls:
    #     ca: /path/to/mysql-ca-bundle.pem
    #     cert: /path/to/mysql-cert.pem
    #     key: /path/to/mysql-cert-key.pem
    #     min_version: 1.2 #(min version of tls supported by mysql)
    tls:
      ca: /path/to/ca-bundle.pem
      cert: /path/to/server-certificate.pem 
      key: /path/to/server-certificate-key.pem
    signing_key: /path/to/ca-signing-key 
    cert_duration: 168h
    listen_addr: "127.0.0.1:8080"

A signing key for generating host certificates can be generated with `ssh-keygen`.

### Client

The client component periodically requests a new host certificate from the
server and installs it on the machine.

The client will use a TLS client certificate to make a
connection to the server and authenticate itself. This assumes that there is a
long-lived certificate and key installed on each machine that uses the client. We
then periodically read the host key for the locally-running OpenSSH (`host_key`), send it
to the server, and retrieve a signed host certificate based on that key. The
signed host certificate is then installed on the machine (`signed_cert`).

Usage:

    usage: sharkey-client --config=CONFIG [<flags>]
    
    Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
      --config=CONFIG  Path to yaml config file for setup
      --version        Show application version.

Configuration (example):

    tls:
      ca: /path/to/ca-bundle.pem
      cert: /path/to/client-certificate.pem 
      key: /path/to/client-certificate-key.pem
    request_addr: "https://sharkey-server.example:8080"
    host_key: /etc/ssh/ssh_host_rsa_key.pub
    signed_cert: /etc/ssh/ssh_host_rsa_key_signed.pub
    known_hosts: /etc/ssh/known_hosts
    sleep: "600s"

OpenSSH will have to be configured to read the signed host certificate
(this is with the `HostCertificate` config option in `sshd_config`). If the signed host
certificate is missing from disk, OpenSSH will fall back to TOFU with the
default host key. Therefore, it should always be safe to configure a host
certificate; even if the Sharkey client fails you can still SSH into your
machine. 
