Summary: A GUI for handling X509 certificates, RSA keys, PKCS#10 Requests and RSA keys.
Name: xca
Version: VERSION
Release: 1
Copyright: BSD
Group: X11
Source: http://www.hohnstaedt.de/xca/src/xca-VERSION.tar.gz

%description
The Program uses a Berkeley db for storage and supports RSA keys,
Certificate signing requests (PKCS#10) and Certificates (X509v3)
The signing of requests, and the creation of selfsigned certificates
is supported. Both can use templates for simplicity.
The PKI structures can be imported and exported in several formats
like PKCS#12, PEM, DER, PKCS#8.


%prep
%setup

%build
./configure --prefix=/usr
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
%doc AUTHORS README COPYRIGHT debian/changelog

/usr/bin/xca
/usr/share/xca/*.png
/usr/share/xca/xca_??.qm

%changelog
