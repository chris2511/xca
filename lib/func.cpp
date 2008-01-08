/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "func.h"
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include <openssl/objects.h>
#include <openssl/asn1.h>

#include <qdir.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qmessagebox.h>
#include <qapplication.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#else
/* for htons() */
#include <netinet/in.h>
#endif

#ifdef Q_WS_MAC
/* for CFBundle API */
#include <CoreFoundation/CoreFoundation.h>
/* for Folder Manager */
#include <CoreServices/CoreServices.h>
#endif

QPixmap *loadImg(const char *name )
{
	return new QPixmap(QString(":") + name);
}

/* returns e.g. /usr/local/share/xca for unix systems
 * or HKEY_LOCAL_MACHINE->Software->xca for WIN32
 * (e.g. c:\Program Files\xca )
 */

QString getPrefix()
{
#ifdef WIN32
	static char inst_dir[100] = "";
	char *p;
	ULONG dwLength = 100;
	LONG lRc;
	HKEY hKey;

	if (inst_dir[0] != '\0') {
		/* if we already once discovered the directory just return it */
		return QString(inst_dir);
	}
	// fallback: directory of xca.exe
	GetModuleFileName(0, inst_dir, dwLength - 1);
	p = strrchr(inst_dir, '\\');
	if (p) {
		*p = '\0';
		return QString(inst_dir);
	}
	p = inst_dir;
	*p = '\0';
	QMessageBox::information(NULL, XCA_TITLE, QString(inst_dir), "OK");
	lRc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca", 0, KEY_READ, &hKey);
	if (lRc != ERROR_SUCCESS) {
		QMessageBox::warning(NULL,XCA_TITLE,
				"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
		return QString(inst_dir);
	}
	lRc = RegQueryValueEx(hKey, "Install_Dir", NULL, NULL,
			(unsigned char *)inst_dir, &dwLength);
	if (lRc != ERROR_SUCCESS){
		QMessageBox::warning(NULL, XCA_TITLE, "Registry Key: "
				"'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
	}
	lRc = RegCloseKey(hKey);
	return QString(inst_dir);

#elif defined(Q_WS_MAC)
	// since this is platform-specific anyway, this is a more robust way to get the bundle directory
	CFURLRef bundle = CFBundleCopyBundleURL(CFBundleGetMainBundle());
	CFStringRef bundlePath = CFURLCopyFileSystemPath(bundle,kCFURLPOSIXPathStyle);
	QString ret(CFStringGetCStringPtr(bundlePath,CFStringGetSystemEncoding()));
	CFRelease(bundle);
	CFRelease(bundlePath);
	ret += "/Contents/Resources";
	return ret;
#else

	QString ret = PREFIX;
	ret += "/share/xca";
	return ret;
#endif

}

QString getHomeDir()
{
	QString hd;
#ifdef WIN32
	LPITEMIDLIST pidl = NULL;
	TCHAR buf[255] = "";
	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_PERSONAL, &pidl))) {
		SHGetPathFromIDList(pidl, buf);
	}
	hd = buf;
#elif defined(Q_WS_MAC)
	// selecting a sensible starting point for opening and saving files.
	// The user's documents folder is generally a good starting point.
	FSRef docsLoc;
	OSErr err = FSFindFolder(kUserDomain, kDocumentsFolderType, kDontCreateFolder, &docsLoc);
	if(err == noErr) {
		CFURLRef docsURL = CFURLCreateFromFSRef(kCFAllocatorSystemDefault, &docsLoc);
		if(docsURL) {
			CFStringRef docsPath = CFURLCopyFileSystemPath(docsURL,kCFURLPOSIXPathStyle);
			if(docsPath) {
				hd = CFStringGetCStringPtr(docsPath,CFStringGetSystemEncoding());
				CFRelease(docsPath);
			}
			CFRelease(docsURL);
		}
	}
	if(hd.isEmpty()) {
		// if the folder manager didn't give anything, just let Qt decide
		hd = QDir::homePath();
	}
#else
#ifdef BASEDIR
	hd = BASEDIR;
#else
	hd = QDir::homePath();
#endif
#endif
	return hd;
}

// The intent of this function is to return the proper location for
// user-controlled settings on the current platform
// i.e. PROFILE\Application Data\xca on windows, HOME/.xca on UNIX,
// ~/Library/Preferences/xca on Mac OS X
QString getUserSettingsDir()
{
	QString rv;
#ifdef WIN32
	/* not called on WIN32 platforms */
	QMessageBox::warning(NULL, XCA_TITLE, "No not to be called");
#elif defined(Q_WS_MAC)
	FSRef prefsLoc;
	OSErr err = FSFindFolder(kUserDomain, kPreferencesFolderType, kDontCreateFolder, &prefsLoc);
	if(err == noErr) {
		CFURLRef prefsURL = CFURLCreateFromFSRef(kCFAllocatorSystemDefault, &prefsLoc);
		if(prefsURL) {
			CFStringRef prefsPath = CFURLCopyFileSystemPath(prefsURL,kCFURLPOSIXPathStyle);
			if(prefsPath) {
				rv = CFStringGetCStringPtr(prefsPath,CFStringGetSystemEncoding());
				CFRelease(prefsPath);
				rv += QDir::separator();
				rv += "xca";
			}
			CFRelease(prefsURL);
		}
	}
#else
	rv = QDir::homePath();
	rv += QDir::separator();
	rv += ".xca";
#endif
	return rv;
}

// Qt's open and save dialogs result in some undesirable quirks on Mac OS X. This function makes sure that a filename has the
// user-selected extension on a mac, and just returns the file name passed in on other platforms where, presumably
// these quirks don't pose the same issues.
QString getFullFilename(const QString & filename, const QString & selectedFilter)
{
	QString rv = filename;
#if !defined(Q_WS_MAC)
	return rv;
#else
	if(!selectedFilter.isEmpty() && !filename.endsWith(selectedFilter)) {
		int dot = selectedFilter.indexOf('.');
		if(dot > 0){
			int extLen = selectedFilter.lastIndexOf(')') - dot - 1;
			rv += selectedFilter.mid(dot,extLen);
		}
	}
	// make sure it wasn't a wildcard filter... this seems a little backwards,
	// but it's the easiest I see way not to worry about languages here.
	if(rv.endsWith('*')) rv = filename;
	return rv;
#endif
}

void applyTD(QWidget *parent, int number, int range, bool mnc,
		Validity *nb, Validity *na)
{
#define d_fac (60 * 60 * 24)
    int faktor[] = { 1, 30, 365 }, midnight, delta;
    a1time a;
    time_t t;

    midnight = mnc? 1:0;

    if (range>2 || range<0) range = 0;
    time(&t);
    delta = faktor[range] * number;

	// one day less if we go from 0:00:00 to 23:59:59
	if (mnc) delta -=1;

    t /= d_fac;
    if (delta + t > 24850){
        QMessageBox::warning(parent, XCA_TITLE,
            "Time difference too big\nYou must set it manually." );
        return;
    }
    nb->setDate(a.now(), midnight);
    na->setDate(a.now(delta * d_fac), midnight* (-1));
}

QString asn1ToQString(const ASN1_STRING *str)
{
	QString qs;
	unsigned short *bmp;
	int i;

	if (!str)
		return qs;

	switch (str->type) {
		case V_ASN1_BMPSTRING:
			bmp = (unsigned short*)str->data;
			for (i = 0; i < str->length/2; i++)
				qs += QChar(ntohs(bmp[i]));
			break;
		case V_ASN1_UTF8STRING:
			qs = QString::fromUtf8((const char*)str->data, str->length);
			break;
		case V_ASN1_T61STRING:
			qs = QString::fromLocal8Bit((const char*)str->data, str->length);
			break;
		default:
			qs = QString::fromLatin1((const char*)str->data, str->length);
	}
	//printf("Convert %s string to '%s'\n", ASN1_tag2str(str->type),CCHAR(qs));
	return qs;
}

/* returns an encoded ASN1 string from QString for a special nid*/
ASN1_STRING *QStringToAsn1(const QString s, int nid)
{
	const unsigned char *utf8 = (const unsigned char *)s.toUtf8().constData();
	return ASN1_STRING_set_by_NID(NULL, utf8, -1, MBSTRING_UTF8, nid);
}

