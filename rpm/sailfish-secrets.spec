%global secretsdaemon sailfishsecretsdaemon
%global secretsdaemonservice sailfish-secretsd.service

Name:       libsailfishsecrets
Summary:    Sailfish OS secrets storage system functionality client library
Version:    0.0.4
Release:    1
Group:      System/Libraries
License:    Proprietary
URL:        https://bitbucket.org/jolla/base-sailfish-secrets/
Source0:    %{name}-%{version}.tar.bz2
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(Qt5DBus)

%description
%{summary}.

%package devel
Summary:    Development package for Sailfish OS Secrets Library.
Group:      System/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.

%package doc
Summary: Documentation for Sailfish OS Secrets Library
BuildRequires:  mer-qdoc-template
BuildRequires:  qt5-qttools-qthelp-devel
BuildRequires:  qt5-tools

%description doc
%{summary}.

%package tests
Summary:    Unit tests for the Sailfish OS Secrets Library.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Test)
Requires:   %{name} = %{version}-%{release}

%description tests
%{summary}.

%package -n libsailfishsecretsplugin
Summary:    QML plugin providing types for applications using libsailfishsecrets.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Gui)
Requires:   %{name} = %{version}-%{release}

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
BuildRequires:  pkgconfig(Qt5Test)
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcrypto-tests
%{summary}.

%package -n libsailfishcryptoplugin
Summary:    QML plugin providing types for applications using libsailfishcrypto.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Qml)
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcryptoplugin
%{summary}.

%package -n %{secretsdaemon}
Summary:    Sailfish OS secrets daemon (example).
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libshadowutils)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:         %{name} = %{version}-%{release}
Requires:         systemd
Requires(preun):  systemd
Requires(postun): systemd
Requires(post):   systemd
Requires:         libsailfishcrypto = %{version}-%{release}
Requires:         qt5-plugin-sqldriver-sqlcipher

%description -n %{secretsdaemon}
Provides an example secrets storage and cryptographic operations system daemon service,
which exposes functionality provided by libsailfishsecrets and libsailfishcrypto to clients via DBus.

%package -n %{secretsdaemon}plugins
Summary:    Sailfish OS secrets daemon (example) plugins.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   qt5-plugin-sqldriver-sqlcipher
Requires:   %{secretsdaemon} = %{version}-%{release}

%description -n %{secretsdaemon}plugins
Provides a set of example secrets daemon plugins.

%package -n sailfishcryptodaemonplugins
Summary:    Sailfish OS crypto daemon (example) plugins.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   %{secretsdaemon} = %{version}-%{release}
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n sailfishcryptodaemonplugins
Provides a set of example crypto daemon plugins.


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
mkdir -p %{buildroot}/%{_unitdir}/multi-user.target.wants/

cp -R lib/Secrets/doc/html/* %{buildroot}/%{_docdir}/Sailfish/Secrets/
cp -R lib/Crypto/doc/html/* %{buildroot}/%{_docdir}/Sailfish/Crypto/
install -m 0644 daemon/%{secretsdaemonservice} %{buildroot}%{_unitdir}

ln -s ../%{secretsdaemonservice} %{buildroot}/%{_unitdir}/multi-user.target.wants/%{secretsdaemonservice}

%files
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so
%{_libdir}/pkgconfig/sailfishsecrets.pc
%{_includedir}/Sailfish/Secrets/*

%files doc
%defattr(-,root,root,-)
%{_docdir}/Sailfish/Secrets/*

%files tests
%defattr(-,root,root,-)
/opt/tests/Sailfish/Secrets/tst_secrets
/opt/tests/Sailfish/Secrets/tst_secrets.qml
/opt/tests/Sailfish/Secrets/tst_secretsrequests
/opt/tests/Sailfish/Secrets/tst_secretsrequests.qml
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testinappauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testopenssl.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testsqlcipher.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-testsqlite.so

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
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-testopenssl.so

%files -n libsailfishcryptoplugin
%defattr(-,root,root,-)
%{_libdir}/qt5/qml/Sailfish/Crypto/libsailfishcryptoplugin.so
%{_libdir}/qt5/qml/Sailfish/Crypto/qmldir

%files -n %{secretsdaemon}
%defattr(-,root,root,-)
%{_bindir}/sailfishsecretsd
%{_unitdir}/%{secretsdaemonservice}
%{_unitdir}/multi-user.target.wants/%{secretsdaemonservice}

%files -n %{secretsdaemon}plugins
%defattr(-,root,root,-)
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-inappauth.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-openssl.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-sqlcipher.so
%{_libdir}/Sailfish/Secrets/libsailfishsecrets-sqlite.so

%files -n sailfishcryptodaemonplugins
%defattr(-,root,root,-)
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-openssl.so

%files -n qt5-plugin-sqldriver-sqlcipher
%defattr(-,root,root,-)
%{_libdir}/qt5/plugins/sqldrivers/libqsqlcipher.so

%post
/sbin/ldconfig || :

%postun
/sbin/ldconfig || :

%post -n libsailfishcrypto
/sbin/ldconfig || :

%postun -n libsailfishcrypto
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
systemctl daemon-reload || :
systemctl reload-or-try-restart %{secretsdaemonservice} || :

%preun -n %{secretsdaemon}
if [ "$1" -eq 0 ]; then
    systemctl stop %{secretsdaemonservice} || :
fi

%postun -n %{secretsdaemon}
systemctl daemon-reload || :
