Summary: A GUI for handling X509 certificates, RSA keys, and PKCS#10 Requests.
Name: xca
Version: 0.2.1
Release: 1
Copyright: GPL
Group: System Environment/Base
Source: http://www.hohnstaedt.de/xca-0.2.1.tar.gz

%description
The eject program allows the user to eject removable media
(typically CD-ROMs, floppy disks or Iomega Jaz or Zip disks)
using software control. Eject can also control some multi-
disk CD changers and even some devices' auto-eject features.

Install eject if you'd like to eject removable media using
software control.

%prep
%setup

%build
cp ../Makefile.rh Makefile
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
%doc README COPYING CHANGELOG

/usr/local/bin/xca
/usr/local/share/xca/*.png

%changelog
* Sun Mar 21 1999 Cristian Gafton <gafton@redhat.com> 
- auto rebuild in the new build environment (release 3)

* Wed Feb 24 1999 Preston Brown <pbrown@redhat.com> 
- Injected new description and group.

