![say no to TOFU](sharkey.png)

# sharkey

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
![development status](https://img.shields.io/badge/status-alpha-orange.svg)
[![tests](https://github.com/square/sharkey/actions/workflows/tests.yml/badge.svg)](https://github.com/square/sharkey/actions/workflows/tests.yml)
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
    host_cert_duration: 168h

    # Lifetime/validity duration for generated user certificates
    user_cert_duration: 24h

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

    # User certs are issued to users who connect through an authenticating proxy
    # That user should connect with a user certificate and set the username
    # in a header.
    auth_proxy:
      # Hostname is validated against the incoming user certificate
      hostname: proxy.example.com
      # The HTTP header containing the username
      username_header: X-Forwarded-User

    # Optional settings related to SSH
    ssh:
      # List of extensions that should be set on the user certificate (default is no extensions)
      user_cert_extensions:
        - "permit-X11-forwarding"
        - "permit-agent-forwarding"
        - "permit-port-forwarding"
        - "permit-pty"
        - "permit-user-rc"

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

    # Path to sudo binary on client host
    # Uses sudo to write known_hosts and signed_cert.pub if this field specified
    sudo: "/usr/bin/sudo"

    # Command to restart ssh daemon for the host
    # If sudo is set as well, this command will be prefixed with 'sudo'
    ssh_reload: ["/usr/sbin/service", "ssh", "restart"]

OpenSSH will have to be configured to read the signed host certificate (this is
with the `HostCertificate` config option in `sshd_config`). If the signed host
certificate is missing from disk, OpenSSH will fall back to TOFU with the
default host key. Therefore, it should always be safe to configure a host
certificate; even if the Sharkey client fails you can still SSH into your
machine.

### User Certificates

For a user to SSH into an openssh server, they can present a certificate, which
should have a principal matching their username.
Sharkey outsources identifying users to an SSO proxy.  That proxy needs to
connect to sharkey over mTLS.  You can configure the DNS SAN that should appear
on the server's client cert (eg, proxy.example.com) and the HTTP header it sets
the username to (eg, X-Forwarded-User).  See example configs.

No client helper is included with Sharkey at this time, so you have to set up
a script yourself at this time to enroll the user.

Testing looks something like this:
   `curl --cert proxy.crt --key proxy.key https://localhost:8080/enroll_user -H "X-Forwarded-User: bob" -d @~/.ssh/bob.pub`

But in production use you'd expect it more like
   `curl <auth to your proxy> https://ssoproxy.example.com/enroll_user -d @~/.ssh/bob.pub`

### GitHub SSH CA Support

Sharkey supports issuing user certificates that are compatible with GitHub SSH CA format by:

- Mapping a GitHub username to a SAML identity
- Including appropriate GitHub username in each certificate

GitHub supports authentication using SSH certificates for Enterprise Cloud accounts. The only requirement is that certificates include GitHub usernames, so that they can be matched to a particular user.

Sharkey already requires SSO proxy for the user certificate feature. Additionally, the GitHub integration requires that the GitHub organization is configured with SSO (i.e. non-GitHub) access.

An example config with GitHub SSH CA Support enabled can be found in `test/git_server_config.yaml`.
A GitHub App with read/write access to `Organization:members` is required. 

Sharkey will periodically query GitHub for a mapping of SAML identities to GitHub usernames and store it in Sharkey's DB. 
When issuing a certificate, Sharkey will check the DB and if a mapping exists, attaches it to the certificate as an extension.

An example cert is shown below:
```
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT SHA256:Eabuov2aAPLhN1FscJ6P3Lle85N6Txhj4sy4ALTkG6M
        Signing CA: ED25519 SHA256:HYgRf1dHbVtWY/e3jjfnAlwvAPPBKYxdXz8SDfhlAws (using ssh-ed25519)
        Key ID: "alice"
        Serial: 1
        Valid: from 2020-07-31T16:10:25 to 2020-08-01T16:10:25
        Principals:
                alice
        Critical Options: (none)
        Extensions:
                login@github.com UNKNOWN OPTION (len 5)
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

### Telemetry
 
Sharkey supports sending DogStatsD metrics. Currently only metrics regarding GitHub SSH CA are being emitted.
Adding the following block to the server configuration will enable metrics:
```
telemetry:
  address: "127.0.0.1:8200"
``` 
Unix sockets are also supported.
