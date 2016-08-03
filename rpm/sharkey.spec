%global rev             %(git rev-parse HEAD)
%global shortrev        %(r=%{rev}; echo ${r:0:12})
%global _dwz_low_mem_die_limit 0
%define function gobuild { go build -a -ldflags "-B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')" -v -x "$@"; }

Name:       sharkey
Version:    0
Release:    0.1.git%{shortrev}%{?dist}
License:    ASL 2.0
Summary:    Sharkey is a service for managing certificates for use by OpenSSH
Url:        https://github.com/square/sharkey
Source0:    https://github.com/square/%{name}/archive/%{rev}.tar.gz#/%{name}-%{rev}.tar.gz
Requires:   openssh
Requires(pre):  shadow-utils

# e.g. el6 has ppc64 arch without gcc-go, so EA tag is required
ExclusiveArch:  %{?go_arches:%{go_arches}}%{!?go_arches:%{ix86} x86_64 %{arm}}
# If go_compiler is not set to 1, there is no virtual provide. Use golang instead.
BuildRequires:  %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}

%description
Sharkey is a service for managing certificates for use by OpenSSH.

%package server
Summary:    Sharkey is a service for managing certificates for use by OpenSSH.
Version:    %{version}
Group:      System Environment/Daemons
%description server
Sharkey-server is the server component to the Sharkey service for managing certificates for use by OpenSSH

%package client
Summary:    Sharkey is a service for managing certificates for use by OpenSSH.
Version:    %{version}
Group:      System Environment/Daemons
%description client
Sharkey-client is the client component to the Sharkey service for managing certificates for use by OpenSSH

%prep
%setup -q -n %{name}-%{rev}

%build
mkdir -p src/github.com/square
ln -s ../../../ src/github.com/square/sharkey

%install
export GOPATH=$(pwd):%{gopath}
# Server
%gobuild -o %{buildroot}%{_sbindir}/%{name}-server github.com/square/sharkey/server

install -d %{buildroot}%{_unitdir}
install -m 0644 rpm/sharkey-server.service %{buildroot}%{_unitdir}/%{name}-server.service
install -d %{buildroot}/%{_sysconfdir}/sysconfig
install -m 0644 rpm/sharkey-server.sysconfig %{buildroot}/%{_sysconfdir}/sysconfig/%{name}-server
install -d %{buildroot}%{_sysconfdir}/sharkey
install -m 0644 examples/server.yml %{buildroot}%{_sysconfdir}/%{name}/server.yml.example
cp -r db %{buildroot}%{_sysconfdir}/sharkey/

# Client
%gobuild -o %{buildroot}%{_sbindir}/%{name}-client github.com/square/sharkey/client
install -m 0644 rpm/sharkey-client.service %{buildroot}%{_unitdir}/%{name}-client.service
install -m 0644 rpm/sharkey-client.sysconfig %{buildroot}/%{_sysconfdir}/sysconfig/%{name}-client
install -m 0644 examples/client.yml %{buildroot}%{_sysconfdir}/%{name}/client.yml.example

%pre server
getent group sharkey >/dev/null || groupadd -r sharkey
getent passwd sharkey >/dev/null || \
    useradd --system --gid sharkey --shell /sbin/nologin --home-dir %{_sysconfdir}/%{name} \
    --comment "Sharkey server user" sharkey
exit 0

%pre client
getent group sharkey-client >/dev/null || groupadd -r sharkey-client
getent passwd sharkey-client >/dev/null || \
    useradd --system --gid sharkey-client --shell /sbin/nologin --home-dir %{_sysconfdir}/%{name} \
    --comment "Sharkey client user" sharkey-client
exit 0

%post server
/usr/bin/systemctl daemon-reload >/dev/null 2>&1

%post client
/usr/bin/systemctl daemon-reload >/dev/null 2>&1

%preun server
if [ $1 -eq 0 ] ; then
    /usr/bin/systemctl stop %{name}-server >/dev/null 2>&1
    /usr/bin/systemctl disable %{name}-server >/dev/null 2>&1
fi

%preun client
if [ $1 -eq 0 ] ; then
    /usr/bin/systemctl stop %{name}-client >/dev/null 2>&1
    /usr/bin/systemctl disable %{name}-client >/dev/null 2>&1
fi

%postun server
if [ "$1" -ge "1" ] ; then
   /usr/bin/systemctl try-restart %{name}-server >/dev/null 2>&1 || :
fi

%postun client
if [ "$1" -ge "1" ] ; then
   /usr/bin/systemctl try-restart %{name}-client >/dev/null 2>&1 || :
fi

%clean
rm -rf %{buildroot}

%files server
%defattr(-,root,root,-)
%{_sbindir}/%{name}-server
%{_unitdir}/%{name}-server.service
%config %{_sysconfdir}/sysconfig/%{name}-server
%{_sysconfdir}/%{name}/server.yml.example
%{_sysconfdir}/%{name}/db/mysql/migrations/*
%{_sysconfdir}/%{name}/db/sqlite/migrations/*

%files client
%defattr(-,root,root,-)
%{_sbindir}/%{name}-client
%{_unitdir}/%{name}-client.service
%config %{_sysconfdir}/sysconfig/%{name}-client
%{_sysconfdir}/%{name}/client.yml.example

%changelog
* Tue Aug 02 2016 Ben Allen <bsallen@alcf.anl.gov> - 0-0.1.gita6ec80f356d3
- Initial RPM release

