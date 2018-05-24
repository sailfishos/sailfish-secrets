Name:       sailfishcrypto-examplecryptoplugin
Summary:    Example Sailfish OS Crypto Framework plugin
Version:    0.0.1
Release:    1
Group:      System/Libraries
License:    BSD-3-Clause
URL:        https://github.com/sailfishos/sailfish-secrets
Source0:    %{name}-%{version}.tar.bz2
BuildRequires:  pkgconfig(sailfishcryptopluginapi)

%description
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
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-examplecryptoplugin.so

%post
/sbin/ldconfig || :

%postun
/sbin/ldconfig || :
