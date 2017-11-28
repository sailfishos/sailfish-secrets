Name:       libsailfishsecrets
Summary:    Sailfish OS secrets storage system functionality library
Version:    0.0.1
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
Summary:    Development package for Sailfish OS secrets storage library.
Group:      System/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.

%package -n libsailfishsecretsplugin
Summary:    QML plugin providing types for clients of libsailfishsecrets.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Gui)
Requires:   %{name} = %{version}-%{release}

%description -n libsailfishsecretsplugin
%{summary}.

%package -n sailfishsecretsdaemon
Summary:    Sailfish OS secrets daemon (example).
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   %{name} = %{version}-%{release}

%description -n sailfishsecretsdaemon
Provides an example secrets storage daemon service, which exposes functionality provided by libsailfishsecrets to clients via DBus.

%package -n sailfishsecretsdaemonplugins
Summary:    Sailfish OS secrets daemon (example) plugins.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   sailfishsecretsdaemon = %{version}-%{release}

%description -n sailfishsecretsdaemonplugins
Provides a set of example secrets daemon plugins.

%package tests
Summary:    Unit tests for the libsailfishsecrets library.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Test)
Requires:   %{name} = %{version}-%{release}

%description tests
%{summary}.

%package -n libsailfishcrypto
Summary:    Sailfish OS cryptographic operations library
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(Qt5DBus)

%description -n libsailfishcrypto
%{summary}.

%package -n libsailfishcrypto-devel
Summary:    Development package for Sailfish OS cryptographic operations library
Group:      System/Libraries
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcrypto-devel
%{summary}.

%package -n libsailfishcrypto-tests
Summary:    Unit tests for the libsailfishcrypto library.
Group:      System/Libraries
BuildRequires:  pkgconfig(Qt5Test)
Requires:   libsailfishcrypto = %{version}-%{release}

%description -n libsailfishcrypto-tests
%{summary}.

%package -n sailfishcryptodaemonplugins
Summary:    Sailfish OS crypto daemon (example) plugins.
Group:      Applications/System
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  qt5-plugin-sqldriver-sqlite
Requires:   sailfishsecretsdaemon = %{version}-%{release}
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

%files
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so.*

%files -n libsailfishcrypto
%defattr(-,root,root,-)
%{_libdir}/libsailfishcrypto.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishsecrets.so
%{_libdir}/pkgconfig/sailfishsecrets.pc
%{_includedir}/libsailfishsecrets/*

%files -n libsailfishcrypto-devel
%defattr(-,root,root,-)
%{_libdir}/libsailfishcrypto.so
%{_libdir}/pkgconfig/sailfishcrypto.pc
%{_includedir}/libsailfishcrypto/*

%files -n libsailfishsecretsplugin
%defattr(-,root,root,-)
%{_libdir}/qt5/qml/org/sailfishos/secrets/libsailfishsecretsplugin.so
%{_libdir}/qt5/qml/org/sailfishos/secrets/qmldir
%{_libdir}/qt5/qml/org/sailfishos/secrets/UiView.qml

%files -n sailfishsecretsdaemon
%defattr(-,root,root,-)
%{_bindir}/sailfishsecretsd

%files -n sailfishsecretsdaemonplugins
%defattr(-,root,root,-)
%{_libdir}/sailfishsecrets/libsailfishsecrets-inappauth.so
%{_libdir}/sailfishsecrets/libsailfishsecrets-openssl.so
%{_libdir}/sailfishsecrets/libsailfishsecrets-sqlcipher.so
%{_libdir}/sailfishsecrets/libsailfishsecrets-sqlite.so

%files -n sailfishcryptodaemonplugins
%defattr(-,root,root,-)
%{_libdir}/sailfishcrypto/libsailfishcrypto-openssl.so

%files tests
%defattr(-,root,root,-)
/opt/tests/Sailfish/Secrets/tst_secrets
/opt/tests/Sailfish/Secrets/tst_secrets.qml
%{_libdir}/sailfishsecrets/libsailfishsecrets-testinappauth.so
%{_libdir}/sailfishsecrets/libsailfishsecrets-testopenssl.so
%{_libdir}/sailfishsecrets/libsailfishsecrets-testsqlite.so

%files -n libsailfishcrypto-tests
%defattr(-,root,root,-)
/opt/tests/Sailfish/Crypto/tst_crypto
/opt/tests/Sailfish/Crypto/tst_cryptosecrets
%{_libdir}/sailfishcrypto/libsailfishcrypto-testopenssl.so

%files -n qt5-plugin-sqldriver-sqlcipher
%defattr(-,root,root,-)
%{_libdir}/qt5/plugins/sqldrivers/libqsqlcipher.so

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post -n libsailfishcrypto
/sbin/ldconfig

%postun -n libsailfishcrypto
/sbin/ldconfig

%post -n libsailfishsecretsplugin
/sbin/ldconfig

%postun -n libsailfishsecretsplugin
/sbin/ldconfig

