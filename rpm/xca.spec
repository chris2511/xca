Summary: A GUI for handling X509 certificates, RSA keys, and PKCS#10 Requests.
Name: xca
Version: 0.2.4
Release: 1
Copyright: BSD
Group: X11
Source: http://www.hohnstaedt.de/xca-0.2.4.tar.gz

%description
This program is intended as a little CA for signing Requests,
creating self signed Certificates and RSA keys.
They can be exported and imported in several formats
like PKCS#12, PKCS#10 or PKCS#8

%prep
%setup

%build
./configure
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
export DESTDIR=$RPM_BUILD_ROOT
make install

%clean
make clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
%doc README COPYRIGHT CHANGELOG

/usr/local/bin/xca
/usr/local/share/xca/*.png

%changelog

