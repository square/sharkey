%global rev             %(git show-ref -s HEAD)
%global shortrev        %(r=%{rev}; echo ${r:0:12})
%global _dwz_low_mem_die_limit 0
%define function gobuild { go build -a -ldflags "-B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n')" -v -x "$@"; }

Name:		sharkey
Version:    0
Release:    0.0.git%{shortrev}%{?dist}
License:	Apache
Summary:	Sharkey is a service for managing certificates for use by OpenSSH
Url:		https://github.com/square/sharkey
Group:		System/Security
Source0:	https://github.com/square/%{name}/archive/%{rev}.tar.gz#/%{name}-%{rev}.tar.gz
Requires:	openssh

# e.g. el6 has ppc64 arch without gcc-go, so EA tag is required
ExclusiveArch:  %{?go_arches:%{go_arches}}%{!?go_arches:%{ix86} x86_64 %{arm}}
# If go_compiler is not set to 1, there is no virtual provide. Use golang instead.
BuildRequires:  %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}

%description
Sharkey is a service for managing certificates for use by OpenSSH.

%package server
Summary:	Sharkey is a service for managing certificates for use by OpenSSH.
Version:    %{version}
Group:      System/Security
%description server
Sharkey-server is the server component to the Sharkey service for managing certificates for use by OpenSSH

%package client
Summary:    Sharkey is a service for managing certificates for use by OpenSSH.
Version:    %{version}
Group:      System/Security
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
%gobuild -o %{buildroot}%{_sbindir}/sharkey-server github.com/square/sharkey/server

install -d %{buildroot}%{_unitdir}
install -m 0644 rpm/%{name}-server.service %{buildroot}%{_unitdir}/%{name}-server.service
install -d %{buildroot}/%{_sysconfdir}/sysconfig
install -m 0644 rpm/%{name}-server.sysconfig %{buildroot}/%{_sysconfdir}/sysconfig/%{name}-server
install -d %{buildroot}%{_sysconfdir}/sharkey
install -m 0644 examples/server.yml %{buildroot}%{_sysconfdir}/sharkey/server.yml.example
cp -r db %{buildroot}%{_sysconfdir}/sharkey/

# Client
%gobuild -o %{buildroot}%{_sbindir}/sharkey-client github.com/square/sharkey/client
install -m 0644 rpm/%{name}-client.service %{buildroot}%{_unitdir}/%{name}-client.service
install -m 0644 rpm/%{name}-client.sysconfig %{buildroot}/%{_sysconfdir}/sysconfig/%{name}-client
install -m 0644 examples/client.yml %{buildroot}%{_sysconfdir}/sharkey/client.yml.example

%pre server
if ! /usr/bin/getent passwd sharkey &>/dev/null
then
    useradd --system --shell /sbin/nologin --home-dir %{_sysconfdir}/sharkey --user-group --comment "Sharkey user" --no-create-home sharkey
fi

%pre client
if ! /usr/bin/getent passwd sharkey &>/dev/null
then
    useradd --system --shell /sbin/nologin --home-dir %{_sysconfdir}/sharkey --user-group --comment "Sharkey user" --no-create-home sharkey
fi

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
%{_sysconfdir}/sharkey/server.yml.example
%{_sysconfdir}/sharkey/db/mysql/migrations/*
%{_sysconfdir}/sharkey/db/sqlite/migrations/*

%files client
%defattr(-,root,root,-)
%{_sbindir}/%{name}-client
%{_unitdir}/%{name}-client.service
%config %{_sysconfdir}/sysconfig/%{name}-client
%{_sysconfdir}/sharkey/client.yml.example

%changelog
* Wed Aug 01 2016 Ben Allen <bsallen@alcf.anl.gov> 
- Initial release

