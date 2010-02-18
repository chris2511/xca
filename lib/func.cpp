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
#include <qfile.h>
#include <qstringlist.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#else
/* for htons() */
#include <netinet/in.h>
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
	// since this is platform-specific anyway,
	// this is a more robust way to get the bundle directory
	QDir bundleDir(qApp->applicationDirPath());
	bundleDir.cdUp();
	bundleDir.cdUp();
	ret += "/Contents/Resources";
	return bundleDir.absolutePath() + "/Contents/Resources";
#else
	return QString(PREFIX) + "/share/xca";
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
#else
	hd = QDir::homePath();
#endif
	return hd;
}

QString getDocDir()
{
#if defined(WIN32) || defined (Q_WS_MAC)
	return getPrefix();
#else
	return QString(DOCDIR);
#endif
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
	rv = QDesktopServices::storageLocation(QDesktopServices::DataLocation);
	rv.insert(rv.count() - QCoreApplication::applicationName().count(),
		QCoreApplication::organizationName() + "/");
#else
	rv = QDir::homePath();
	rv += QDir::separator();
	rv += ".xca";
#endif
	return rv;
}

// Qt's open and save dialogs result in some undesirable quirks.
// This function makes sure that a filename has the user-selected extension.
QString getFullFilename(const QString & filename, const QString & selectedFilter)
{
	QString rv = filename.trimmed(), ext;
	QRegExp rx(".* \\( ?\\*(.[a-z]{1,3}) ?\\)");
	rx.indexIn(selectedFilter);
	ext = rx.cap(1);
	if (!ext.isEmpty() && !rv.endsWith(ext)) {
		rv += ext;
	}
	return rv;
}

QByteArray filename2bytearray(const QString &fname)
{
#ifdef WIN32
	return fname.toLocal8Bit();
#else
	return fname.toUtf8();
#endif
}

QString filename2QString(const char *fname)
{
#ifdef WIN32
	return QString::fromLocal8Bit(fname);
#else
	return QString::fromUtf8(fname);
#endif
}

void applyTD(QWidget *parent, int number, int range, bool mnc,
		Validity *nb, Validity *na)
{
	int faktor[] = { 1, 30, 365 }, midnight, delta;
	a1time a;
	time_t t;

	midnight = mnc ? 1:0;

	if (range>2 || range<0)
		range = 0;
	time(&t);
	delta = faktor[range] * number;

	// one day less if we go from 0:00:00 to 23:59:59
	if (mnc)
		delta -=1;

	t /= SECONDS_PER_DAY;
	if (delta + t > 24850) {
		QMessageBox::warning(parent, XCA_TITLE,
			"Time difference too big\nYou must set it manually." );
		return;
	}
	nb->setDate(a.now(), midnight);
	na->setDate(a.now(delta * SECONDS_PER_DAY), midnight* (-1));
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
			for (i = 0; i < str->length/2; i++) {
				unsigned short s = ntohs(bmp[i]);
				qs += QString::fromUtf16(&s, 1);
			}
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
#if 0
	printf("Convert %s (%d %d) string to '%s' len %d:", ASN1_tag2str(str->type), str->type, V_ASN1_UTF8STRING, CCHAR(qs), str->length);
	for (int i=0; i< str->length; i++)
		printf(" %02x", str->data[i]);
	printf("\n");
#endif
	return qs;
}

/* returns an encoded ASN1 string from QString for a special nid*/
ASN1_STRING *QStringToAsn1(const QString s, int nid)
{
	QByteArray ba = s.toUtf8();
	const unsigned char *utf8 = (const unsigned char *)ba.constData();
	return ASN1_STRING_set_by_NID(NULL, utf8, -1, MBSTRING_UTF8, nid);
}

const char *OBJ_ln2sn(const char *ln)
{
	return OBJ_nid2sn(OBJ_ln2nid(ln));
}

const char *OBJ_sn2ln(const char *sn)
{
	return OBJ_nid2ln(OBJ_sn2nid(sn));
}

QString changeFilenameSuffix(QString fn, const QStringList &suffixlist,
				int selected)
{
	if (selected <0 || selected >= suffixlist.size())
		return fn;

	foreach(QString suffix, suffixlist) {
		if (fn.endsWith(QString(".") +suffix)) {
			return fn.left(fn.length() -suffix.length()) +
				suffixlist[selected];
		}
	}
	return fn;
}

bool mayWriteFile(const QString &fname)
{
        if (QFile::exists(fname)) {
		if (QMessageBox::information(NULL, XCA_TITLE,
			QObject::tr("The file: ") + fname +
			QObject::tr(" already exists"),
			QObject::tr("Do not overwrite"),
			QObject::tr("Overwrite")) != 1)
	        {
			return false;
	        }
	}
	return true;
}
