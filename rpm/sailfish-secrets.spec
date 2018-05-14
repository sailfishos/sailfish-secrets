%global secretsdaemon sailfishsecretsdaemon
%global user_unitdir %{_libdir}/systemd/user

Name:       sailfish-secrets
Summary:    Sailfish OS framework for secrets storage and cryptographic operations
Version:    0.1.6
Release:    1
Group:      System/Libraries
License:    BSD-3-Clause
URL:        https://github.com/sailfishos/sailfish-secrets
Source0:    %{name}-%{version}.tar.bz2

%description
%{summary}.

%package -n libsailfishsecrets
Summary:    Sailfish OS secrets storage system functionality client library
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(Qt5DBus)

%description -n libsailfishsecrets
%{summary}.

%package -n libsailfishsecrets-devel
Summary:    Development package for Sailfish OS Secrets Library.
Group:      System/Libraries
Requires:   libsailfishsecrets = %{version}-%{release}

%description -n libsailfishsecrets-devel
%{summary}.

%package -n libsailfishsecrets-doc
Summary: Documentation for Sailfish OS Secrets Library
BuildRequires:  mer-qdoc-template
BuildRequires:  qt5-qttools-qthelp-devel
BuildRequires:  qt5-tools

%description -n libsailfishsecrets-doc
%{summary}.

%package -n libsailfishsecrets-tests
Summary:    Unit tests for the Sailfish OS Secrets Library.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5QuickTest)
BuildRequires:  pkgconfig(libcrypto)
Requires: qt5-qtdeclarative-import-qttest
Requires: qt5-qtdeclarative-devel-tools
Requires: openssl
Requires:   libsailfishsecrets = %{version}-%{release}

%description -n libsailfishsecrets-tests
%{summary}.

%package   ts-devel
Summary:   Translation source for Sailfish Secrets
Group:     System/Applications

%description ts-devel

%package -n libsailfishsecretspluginapi
Summary:    Library providing Sailfish OS Secrets Library plugin abstract base classes
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:   libsailfishsecrets = %{version}-%{release}

%description -n libsailfishsecretspluginapi
%{summary}.

%package -n libsailfishsecretspluginapi-devel
Summary:    Library providing Sailfish OS Secrets Library plugin abstract base class development headers
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:   libsailfishsecrets = %{version}-%{release}
Requires:   libsailfishsecretspluginapi = %{version}-%{release}

%description -n libsailfishsecretspluginapi-devel
%{summary}.

%package -n libsailfishsecretsplugin
Summary:    QML plugin providing types for applications using libsailfishsecrets.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Gui)
Requires:   libsailfishsecrets = %{version}-%{release}

%description -n libsailfishsecretsplugin
%{summary}.

%package -n libsailfishcrypto
Summary:    Sailfish OS cryptographic operations system functionality client library
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(Qt5DBus)

%description -n libsailfishcrypto
%{summary}.

%package -n libsailfishcrypto-devel
Summary:    Development package for Sailfish OS Crypto Library
Group:      System/Libraries
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcrypto-devel
%{summary}.

%package -n libsailfishcrypto-doc
Summary: Documentation for Sailfish OS Crypto Library
BuildRequires:  mer-qdoc-template
BuildRequires:  qt5-qttools-qthelp-devel
BuildRequires:  qt5-tools

%description -n libsailfishcrypto-doc
%{summary}.

%package -n libsailfishcrypto-tests
Summary:    Unit tests for the libsailfishcrypto library.
Group:      System/Libraries
BuildRequires: pkgconfig(Qt5QuickTest)
BuildRequires: pkgconfig(libcrypto)
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcrypto-tests
%{summary}.

%package -n libsailfishcryptopluginapi
Summary:    Library providing Sailfish OS Crypto Library plugin abstract base classes
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:   libsailfishsecrets = %{version}-%{release}
Requires:   libsailfishsecretspluginapi = %{version}-%{release}

%description -n libsailfishcryptopluginapi
%{summary}.

%package -n libsailfishcryptopluginapi-devel
Summary:    Library providing Sailfish OS Crypto Library plugin abstract base class development headers
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:   libsailfishsecrets = %{version}-%{release}
Requires:   libsailfishcryptopluginapi = %{version}-%{release}
Requires:   libsailfishsecretspluginapi-devel = %{version}-%{release}

%description -n libsailfishcryptopluginapi-devel
%{summary}.

%package -n libsailfishcryptoplugin
Summary:    QML plugin providing types for applications using libsailfishcrypto.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Qml)
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcryptoplugin
%{summary}.

%package -n %{secretsdaemon}
Summary:    Sailfish OS secrets daemon.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(Qt5Concurrent)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(qt5-boostable)
BuildRequires:  qt5-qttools-linguist
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:         libsailfishsecrets = %{version}-%{release}
Requires:         systemd
Requires(preun):  systemd
Requires(postun): systemd
Requires(post):   systemd
Requires:         mapplauncherd
Requires:         libsailfishcrypto = %{version}-%{release}
Requires:         qt5-plugin-sqldriver-sqlcipher

%description -n %{secretsdaemon}
Provides a secrets storage and cryptographic operations system daemon service,
which exposes functionality provided by libsailfishsecrets and libsailfishcrypto to clients via DBus.

%package -n %{secretsdaemon}-secretsplugins-default
Summary:    Sailfish OS secrets daemon plugins.
Group:      Applications/System
Provides: %{secretsdaemon}-secretsplugins
Provides: %{secretsdaemon}-secretsplugin-ssl
Provides: %{secretsdaemon}-secretsplugin-sql
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   qt5-plugin-sqldriver-sqlcipher
Requires:   libsailfishsecretspluginapi = %{version}-%{release}
Requires:   %{secretsdaemon} = %{version}-%{release}
Requires:   %{secretsdaemon}-secretsplugin-common = %{version}-%{release}

%description -n %{secretsdaemon}-secretsplugins-default
%{summary}.

%package -n %{secretsdaemon}-secretsplugin-common
Summary:    Sailfish OS secrets daemon plugins that are mandatory for all platforms.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:  qt5-plugin-sqldriver-sqlite
Requires:  qt5-plugin-sqldriver-sqlcipher
Requires:  libsailfishsecretspluginapi = %{version}-%{release}
Requires:  %{secretsdaemon} = %{version}-%{release}

%description -n %{secretsdaemon}-secretsplugin-common
%{summary}.

%package -n %{secretsdaemon}-cryptoplugins-default
Summary:    Sailfish OS crypto daemon plugins.
Group:      Applications/System
Provides: %{secretsdaemon}-cryptoplugins
Provides: %{secretsdaemon}-cryptoplugin-ssl
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   %{secretsdaemon} = %{version}-%{release}
Requires:   libsailfishcrypto = %{version}-%{release}
Requires:   libsailfishcryptopluginapi = %{version}-%{release}

%description -n %{secretsdaemon}-cryptoplugins-default
%{summary}.


%package -n sailfishsecrets-tool
Summary:    Command line tool to interact with the Sailfish OS Secrets and Crypto service
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
Requires:   libsailfishcrypto = %{version}-%{release}
Requires:   libsailfishsecrets = %{version}-%{release}

%description -n sailfishsecrets-tool
%{summary}.


%package -n qt5-plugin-sqldriver-sqlcipher
Summary:    QtSql driver plugin using SQLCipher.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(sqlcipher)

%description -n qt5-plugin-sqldriver-sqlcipher
%{summary}.


%prep
%setup -q -n %{name}-%{version}

%build
%qmake5 "VERSION=%{version}"
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%qmake5_install

mkdir -p %{buildroot}/%{_docdir}/Sailfish/Secrets/
mkdir -p %{buildroot}/%{_docdir}/Sailfish/Crypto/
mkdir -p %{buildroot}/%{user_unitdir}/user-session.target.wants/
mkdir -p %{buildroot}/%{_datadir}/dbus-1/services/
mkdir -p %{buildroot}/%{_datadir}/mapplauncherd/privileges.d/

cp -R lib/Secrets/doc/html/* %{buildroot}/%{_docdir}/Sailfish/Secrets/
cp -R lib/Crypto/doc/html/* %{buildroot}/%{_docdir}/Sailfish/Crypto/
install -m 0644 daemon/sailfish-secretsd.service %{buildroot}/%{user_unitdir}
install -m 0644 daemon/sailfish-secretsd.privileges %{buildroot}/%{_datadir}/mapplauncherd/privileges.d/
install -m 0644 daemon/org.sailfishos.secrets.daemon.discovery.service %{buildroot}/%{_datadir}/dbus-1/services/

ln -s ../sailfish-secretsd.service %{buildroot}/%{user_unitdir}/user-session.target.wants/sailfish-secretsd.service

%files -n libsailfishsecrets
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so.*

%files -n libsailfishsecrets-devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so
%{_libdir}/pkgconfig/sailfishsecrets.pc
%exclude %{_includedir}/Sailfish/Secrets/extensionplugins.h
%{_includedir}/Sailfish/Secrets/*

%files -n libsailfishsecrets-doc
%defattr(-,root,root,-)
%{_docdir}/Sailfish/Secrets/*

%files -n libsailfishsecrets-tests
%defattr(-,root,root,-)
/opt/tests/Sailfish/Secrets/authentication-client
/opt/tests/Sailfish/Secrets/tst_secrets
/opt/tests/Sailfish/Secrets/tst_secrets.qml
/opt/tests/Sailfish/Secrets/tst_secretsrequests
/opt/tests/Sailfish/Secrets/tst_secretsrequests.qml
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testexampleusbtoken.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testinappauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testpasswordagentauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testopenssl.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testsqlcipher.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testsqlite.so

%files ts-devel
%defattr(-,root,root,-)
%{_datadir}/translations/source/sailfish-secrets.ts

%files -n libsailfishsecretspluginapi
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecretspluginapi.so.*

%files -n libsailfishsecretspluginapi-devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecretspluginapi.so
%{_libdir}/pkgconfig/sailfishsecretspluginapi.pc
%{_includedir}/Sailfish/Secrets/extensionplugins.h

%files -n libsailfishsecretsplugin
%defattr(-,root,root,-)
%{_libdir}/qt5/qml/Sailfish/Secrets/libsailfishsecretsplugin.so
%{_libdir}/qt5/qml/Sailfish/Secrets/qmldir
%{_libdir}/qt5/qml/Sailfish/Secrets/InteractionView.qml

%files -n libsailfishcrypto
%defattr(-,root,root,-)
%{_libdir}/libsailfishcrypto.so.*

%files -n libsailfishcrypto-devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishcrypto.so
%{_libdir}/pkgconfig/sailfishcrypto.pc
%exclude %{_includedir}/Sailfish/Crypto/extensionplugins.h
%{_includedir}/Sailfish/Crypto/*

%files -n libsailfishcrypto-doc
%defattr(-,root,root,-)
%{_docdir}/Sailfish/Crypto/*

%files -n libsailfishcrypto-tests
%defattr(-,root,root,-)
/opt/tests/Sailfish/Crypto/tst_crypto
/opt/tests/Sailfish/Crypto/tst_cryptorequests
/opt/tests/Sailfish/Crypto/tst_cryptosecrets
/opt/tests/Sailfish/Crypto/tst_evp
/opt/tests/Sailfish/Crypto/tst_qml_signing
/opt/tests/Sailfish/Crypto/tst_qml_signing.qml
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-testopenssl.so

%files -n libsailfishcryptopluginapi
%defattr(-,root,root,-)
%{_libdir}/libsailfishcryptopluginapi.so.*

%files -n libsailfishcryptopluginapi-devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishcryptopluginapi.so
%{_libdir}/pkgconfig/sailfishcryptopluginapi.pc
%{_includedir}/Sailfish/Crypto/extensionplugins.h

%files -n libsailfishcryptoplugin
%defattr(-,root,root,-)
%{_libdir}/qt5/qml/Sailfish/Crypto/libsailfishcryptoplugin.so
%{_libdir}/qt5/qml/Sailfish/Crypto/qmldir

%files -n %{secretsdaemon}
%defattr(-,root,root,-)
%{_bindir}/sailfishsecretsd
%{_datadir}/translations/sailfish-secrets_eng_en.qm
%{_datadir}/mapplauncherd/privileges.d/sailfish-secretsd.privileges
%{user_unitdir}/sailfish-secretsd.service
%{user_unitdir}/user-session.target.wants/sailfish-secretsd.service
%{_datadir}/dbus-1/services/org.sailfishos.secrets.daemon.discovery.service

%files -n %{secretsdaemon}-secretsplugins-default
%defattr(-,root,root,-)
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-openssl.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-sqlite.so

%files -n %{secretsdaemon}-secretsplugin-common
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-inappauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-passwordagentauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-sqlcipher.so
%{_datadir}/polkit-1/actions/org.sailfishos.secrets.policy

%files -n %{secretsdaemon}-cryptoplugins-default
%defattr(-,root,root,-)
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-openssl.so

%files -n sailfishsecrets-tool
%defattr(-,root,root,-)
%{_bindir}/secrets-tool

%files -n qt5-plugin-sqldriver-sqlcipher
%defattr(-,root,root,-)
%{_libdir}/qt5/plugins/sqldrivers/libqsqlcipher.so

%post
/sbin/ldconfig || :

%postun
/sbin/ldconfig || :

%post -n libsailfishsecretspluginapi
/sbin/ldconfig || :

%postun -n libsailfishsecretspluginapi
/sbin/ldconfig || :

%post -n libsailfishcrypto
/sbin/ldconfig || :

%postun -n libsailfishcrypto
/sbin/ldconfig || :

%post -n libsailfishcryptopluginapi
/sbin/ldconfig || :

%postun -n libsailfishcryptopluginapi
/sbin/ldconfig || :

%post -n libsailfishsecretsplugin
/sbin/ldconfig || :

%postun -n libsailfishsecretsplugin
/sbin/ldconfig || :

%post -n libsailfishcryptoplugin
/sbin/ldconfig || :

%postun -n libsailfishcryptoplugin
/sbin/ldconfig || :

%post -n %{secretsdaemon}
systemctl-user daemon-reload || :
systemctl-user reload-or-try-restart sailfish-secretsd || :

%preun -n %{secretsdaemon}
if [ "$1" -eq 0 ]; then
    systemctl stop sailfish-secretsd || :
fi

%postun -n %{secretsdaemon}
systemctl daemon-reload || :
