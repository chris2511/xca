Summary: A GUI for handling X509 certificates, RSA keys, PKCS#10 Requests and RSA keys.
Name: xca
Version: VERSION
Release: 1
Copyright: BSD
Group: X11
Source: http://www.hohnstaedt.de/xca/src/xca-VERSION.tar.gz
BuildPreReq: qt-devel
BuildRoot: %{_tmppath}/%{name}-root


%description
The Program uses a Berkeley db for storage and supports RSA keys,
Certificate signing requests (PKCS#10) and Certificates (X509v3)
The signing of requests, and the creation of selfsigned certificates
is supported. Both can use templates for simplicity.
The PKI structures can be imported and exported in several formats
like PKCS#7, PKCS#12, PEM, DER, PKCS#8.


%prep
%setup

# Patch Makefile for non-root build-install step
cat <<END | patch Makefile.in
@@ -80,10 +80,10 @@

 install: xca
       strip xca
-      install -m 755 -o root -d \$(prefix)@prefix@/share/xca \$(prefix)@prefix@/bin
-      install -m 755 -o root xca \$(prefix)@prefix@/bin
-      install -m 644 -o root img/*.png \$(prefix)@prefix@/share/xca
-      install -m 644 -o root xca_??.qm \$(prefix)@prefix@/share/xca
+      install -m 755 -d \$(prefix)@prefix@/share/xca \$(prefix)@prefix@/bin
+      install -m 755 xca \$(prefix)@prefix@/bin
+      install -m 644 img/*.png \$(prefix)@prefix@/share/xca
+      install -m 644 xca_??.qm \$(prefix)@prefix@/share/xca


 moc_%.cpp: %.h %.cpp
END


%build
./configure --prefix=/usr --disable-printf-debug
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT install

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
