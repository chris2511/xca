/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include <unistd.h>
#include "func.h"
#include "exception.h"
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include "widgets/XcaWarning.h"
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#if defined(Q_OS_MAC)
#include <IOKit/IOKitLib.h>
  #if QT_VERSION < 0x050000
#include <QDesktopServices>
  #else
#include <QStandardPaths>
  #endif
#endif
#include <QDir>
#include <QFile>
#include <QStringList>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QMessageBox>
#include <QApplication>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QDebug>

#if defined(Q_OS_WIN32)
#include <shlobj.h>
#endif

QString currentDB;

QPixmap *loadImg(const char *name )
{
	return new QPixmap(QString(":") + name);
}

QStringList getLibExtensions()
{
	QStringList l;
#if defined(Q_OS_WIN32)
	l << QString("*.dll") << QString("*.DLL");
#elif defined(Q_OS_MAC)
	l << QString("*.dylib") << QString("*.so");
#else
	l << QString("*.so");
#endif
	return l;
}

int portable_app()
{
	static int portable = -1;
	if (portable == -1) {
#if defined(Q_OS_WIN32)
		HKEY hKey;
		portable = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca", 0,
			KEY_WOW64_32KEY|KEY_READ, &hKey) != ERROR_SUCCESS;
#else
		const char *p = getenv("XCA_PORTABLE");
		portable = p && *p;
#endif
	}
	return portable;
}

/* returns e.g. /usr/local/share/xca for unix systems
 * or HKEY_LOCAL_MACHINE->Software->xca for WIN32
 * (e.g. c:\Program Files\xca )
 */

QString getPrefix()
{
#if defined(Q_OS_WIN32)
	static char inst_dir[100] = "";
	char *p;
	ULONG dwLength = 100;
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
	if (portable_app())
		return QString(inst_dir);
	p = inst_dir;
	*p = '\0';
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca", 0,
		KEY_WOW64_32KEY|KEY_READ, &hKey) != ERROR_SUCCESS)
	{
		XCA_WARN("Registry Key: 'HKEY_LOCAL_MACHINE\\Software\\xca' not found");
		return QString(inst_dir);
	}
	if (RegQueryValueEx(hKey, "Install_Dir", NULL, NULL,
			(unsigned char *)inst_dir, &dwLength) != ERROR_SUCCESS)
	{
		XCA_WARN("Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
	}
	RegCloseKey(hKey);
	return QString(inst_dir);

#elif defined(Q_OS_MAC)
	// since this is platform-specific anyway,
	// this is a more robust way to get the bundle directory
	QDir bundleDir(qApp->applicationDirPath());
	bundleDir.cdUp();
        return bundleDir.canonicalPath() + "/Resources";
#else
#ifndef XCA_PREFIX
#define XCA_PREFIX PREFIX "/share/xca"
#endif
	return QString(XCA_PREFIX);
#endif

}

QString getHomeDir()
{
	QString hd;
#if defined(Q_OS_WIN32)
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

QString getLibDir()
{
	QString hd;
#if defined(Q_OS_WIN32)
	LPITEMIDLIST pidl = NULL;
	TCHAR buf[255] = "";
		if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_SYSTEM, &pidl))) {
		SHGetPathFromIDList(pidl, buf);
	}
	hd = buf;
#else
	hd = QString("/usr/lib");
#endif
	return hd;
}

QString getDocDir()
{
#if defined(Q_OS_WIN32) || defined (Q_OS_MAC)
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
#if defined(Q_OS_WIN32)
	LPITEMIDLIST pidl = NULL;
	TCHAR buf[255] = "";
	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_APPDATA, &pidl))) {
	SHGetPathFromIDList(pidl, buf);
	}
	rv = buf;
	rv += QDir::separator();
	rv += "xca";
#elif defined(Q_OS_MAC)
  #if QT_VERSION < 0x050000
	rv = QDesktopServices::storageLocation(QDesktopServices::DataLocation);
	rv.insert(rv.count() - QCoreApplication::applicationName().count(),
		QCoreApplication::organizationName());
  #else
	rv = QStandardPaths::writableLocation(
			QStandardPaths::GenericDataLocation) + "/data/" +
		QCoreApplication::organizationName() + "/" +
		QCoreApplication::applicationName();
  #endif
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
#if defined(Q_OS_WIN32)
	return fname.toLocal8Bit();
#else
	return fname.toUtf8();
#endif
}

QString filename2QString(const char *fname)
{
#if defined(Q_OS_WIN32)
	return QString::fromLocal8Bit(fname);
#else
	return QString::fromUtf8(fname);
#endif
}

QString hostId()
{
	static QString id;
	unsigned char guid[100] = "", md[SHA_DIGEST_LENGTH];

	if (!id.isEmpty())
		return id;

#if defined(Q_OS_WIN32)
#define REG_CRYPTO "SOFTWARE\\Microsoft\\Cryptography"
#define REG_GUID "MachineGuid"
	ULONG dwGuid = sizeof guid;
	HKEY hKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_CRYPTO, 0,
			KEY_WOW64_64KEY|KEY_READ, &hKey) != ERROR_SUCCESS) {
		XCA_WARN("Registry Key: '" REG_CRYPTO "' not found");
	} else {
		if (RegQueryValueEx(hKey, REG_GUID, NULL, NULL,
			guid, &dwGuid) != ERROR_SUCCESS) {
			XCA_WARN("Registry Key: '" REG_CRYPTO "\\" REG_GUID
				"' not found");
		}
	}
	RegCloseKey(hKey);

#elif defined(Q_OS_MAC)
	io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(
				kIOMasterPortDefault, "IOService:/");
	CFStringRef uuidCf = (CFStringRef)IORegistryEntryCreateCFProperty(
				ioRegistryRoot, CFSTR(kIOPlatformUUIDKey),
				kCFAllocatorDefault, 0);

	snprintf((char*)guid, sizeof guid, "%s", CCHAR(
		QString::fromUtf16(CFStringGetCharactersPtr(uuidCf))
	));

	IOObjectRelease(ioRegistryRoot);
	CFRelease(uuidCf);

#else
	QString mach_id;
	QStringList dirs; dirs <<
			"/etc" << "/var/lib/dbus" << "/var/db/dbus";
	foreach(QString dir, dirs) {
		QFile file(dir + "/machine-id");
		if (file.open(QIODevice::ReadOnly)) {
			QTextStream in(&file);
			mach_id = in.readLine().trimmed();
			file.close();
		}
		qDebug() << "ID:" << mach_id;
		if (!mach_id.isEmpty()) {
			snprintf((char*)guid, sizeof guid, "%s", CCHAR(mach_id));
			break;
		}
	}
	if (mach_id.isEmpty())
		sprintf((char*)guid, "%ld", gethostid());
#endif
	guid[sizeof guid -1] = 0;
	SHA1(guid, strlen((char*)guid), md);
	id = QByteArray((char*)md, (int)sizeof md).toBase64().mid(0, 8);

	qDebug() << "GUID:" << guid << "ID:" << id;

	return id;
}

QString compressFilename(QString filename, int maxlen)
{
	if (filename.length() < maxlen)
		return filename;

	QString fn = filename.replace("\\", "/");
	int len, lastslash = fn.lastIndexOf('/');
	QString base = filename.mid(lastslash);
	len = base.length();
	len = maxlen - len -3;
	if (len < 0)
		return QString("...") + base.right(maxlen -3);
	fn = fn.left(len);
	lastslash = fn.lastIndexOf('/');

	return filename.left(lastslash+1) + "..." + base;
}

QString asn1ToQString(const ASN1_STRING *str, bool quote)
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
				unsigned short s = xntohs(bmp[i]);
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
	QString s;
	qDebug("Convert %s (%d %d) string to '%s' len %d:",
		ASN1_tag2str(str->type), str->type,
		V_ASN1_UTF8STRING, CCHAR(qs), str->length);
	for (int i=0; i< str->length; i++)
		s += QString(" %1").arg(str->data[i], 2, 16);
	qDebug() << s;
#endif
	if (quote)
		qs.replace('\n', "\\n\\");
	return qs;
}

/* returns an encoded ASN1 string from QString for a special nid*/
ASN1_STRING *QStringToAsn1(const QString s, int nid)
{
	QByteArray ba = s.toUtf8();
	const unsigned char *utf8 = (const unsigned char *)ba.constData();
	unsigned long global_mask = ASN1_STRING_get_default_mask();
	unsigned long mask = DIRSTRING_TYPE & global_mask;
	ASN1_STRING *out = NULL;
	ASN1_STRING_TABLE *tbl;

	tbl = ASN1_STRING_TABLE_get(nid);
	if (tbl) {
		mask = tbl->mask;
		if (!(tbl->flags & STABLE_NO_MASK))
			mask &= global_mask;
	}
	ASN1_mbstring_copy(&out, utf8, -1, MBSTRING_UTF8, mask);
	openssl_error(QString("'%1' (%2)").arg(s).arg(OBJ_nid2ln(nid)));
	return out;
}

const char *OBJ_ln2sn(const char *ln)
{
	return OBJ_nid2sn(OBJ_ln2nid(ln));
}

const char *OBJ_sn2ln(const char *sn)
{
	return OBJ_nid2ln(OBJ_sn2nid(sn));
}

const char *OBJ_obj2sn(ASN1_OBJECT *a)
{
	OBJ_obj2nid(a);
	openssl_error();
	return OBJ_nid2sn(OBJ_obj2nid(a));
}

QString OBJ_obj2QString(const ASN1_OBJECT *a, int no_name)
{
	char buf[512];
	int len;

	len = OBJ_obj2txt(buf, sizeof buf, a, no_name);
	openssl_error();
	return QString::fromLatin1(buf, len);
}

QByteArray i2d_bytearray(int(*i2d)(const void*, unsigned char **),
		const void *data)
{
	QByteArray ba;

	ba.resize(i2d(data, NULL));
	unsigned char *p = (unsigned char*)ba.data();
	i2d(data, &p);
	openssl_error();
	return ba;
}

void *d2i_bytearray(void *(*d2i)(void *, unsigned char **, long),
		QByteArray &ba)
{
	unsigned char *p, *p1;
	void *ret;
	p = p1 = (unsigned char *)ba.constData();
	ret = d2i(NULL, &p1, ba.count());
	ba = ba.mid(p1-p);
	openssl_error();
	return ret;
}

void _openssl_error(const QString txt, const char *file, int line)
{
	QString error;

	while (int i = ERR_get_error() ) {
		error += QString(ERR_error_string(i, NULL)) + "\n";
		fputs(CCHAR(QString("OpenSSL error (%1:%2) : %3\n").
			arg(file).arg(line).arg(ERR_error_string(i, NULL))),
			stderr);
	}
	if (!error.isEmpty()) {
		if (!txt.isEmpty())
			error = txt + "\n" + error + "\n" +
				QString("(%1:%2)").arg(file).arg(line);
		throw errorEx(error);
	}
}

#undef PRINT_IGNORED_ANYWAY
bool _ign_openssl_error(const QString txt, const char *file, int line)
{
	// ignore openssl errors
	QString errtxt;
#if PRINT_IGNORED_ANYWAY
	if (!txt.isEmpty() && ERR_peek_error())
		qDebug() << txt;
#else
	(void)txt;
	(void)file;
	(void)line;
#endif
	while (int i = ERR_get_error() ) {
		errtxt = ERR_error_string(i, NULL);
#if PRINT_IGNORED_ANYWAY
		qDebug() << QString("IGNORED (%1:%2) : %3\n")
				.arg(file).arg(line).arg(errtxt);
#endif
	}
	return !errtxt.isEmpty();
}

QString formatHash(const unsigned char *md, unsigned size, bool colon)
{
	QString s, t;
	for (unsigned j = 0; j < size; j++)
		s += t.sprintf("%02X%s", md[j],
				(j+1 == size) || !colon ? "" : ":");
	return s;
}

void inc_progress_bar(int, int, void *p)
{
	QProgressBar *bar = (QProgressBar *)p;
	int value = bar->value();

	if (value == bar->maximum()) {
		bar->reset();
	} else {
		bar->setValue(value +1);
	}
}

QMap<int, QString> dn_translations;

void dn_translations_setup()
{
#define TRANS(nid, text) dn_translations[(nid)] = QObject::tr(text)
	TRANS(NID_countryName, "Country code");
	TRANS(NID_stateOrProvinceName, "State or Province");
	TRANS(NID_localityName, "Locality");
	TRANS(NID_organizationName, "Organisation");
	TRANS(NID_organizationalUnitName, "Organisational unit");
	TRANS(NID_commonName, "Common name");
	TRANS(NID_pkcs9_emailAddress, "E-Mail address");
	TRANS(NID_serialNumber, "Serial number");
	TRANS(NID_givenName, "Given name");
	TRANS(NID_surname, "Surname");
	TRANS(NID_title, "Title");
	TRANS(NID_initials, "Initials");
	TRANS(NID_description, "Description");
	TRANS(NID_role, "Role");
	TRANS(NID_pseudonym, "Pseudonym");
	TRANS(NID_generationQualifier, "Generation Qualifier");
	TRANS(NID_x500UniqueIdentifier, "x500 Unique Identifier");
	TRANS(NID_name, "Name");
	TRANS(NID_dnQualifier, "DN Qualifier");
	TRANS(NID_pkcs9_unstructuredName, "Unstructured name");
	TRANS(NID_pkcs9_challengePassword, "Challenge password");

	TRANS(NID_basic_constraints, "Basic Constraints");
	TRANS(NID_subject_alt_name, "Subject alternative name");
	TRANS(NID_issuer_alt_name, "issuer alternative name");
	TRANS(NID_subject_key_identifier, "Subject key identifier");
	TRANS(NID_authority_key_identifier, "Authority key identifier");
	TRANS(NID_key_usage, "Key usage");
	TRANS(NID_ext_key_usage, "Extended key usage");
	TRANS(NID_crl_distribution_points, "CRL distribution points");
	TRANS(NID_info_access, "Authority information access");
	TRANS(NID_netscape_cert_type, "Certificate type");
	TRANS(NID_netscape_base_url, "Base URL");
	TRANS(NID_netscape_revocation_url, "Revocation URL");
	TRANS(NID_netscape_ca_revocation_url, "CA Revocation URL");
	TRANS(NID_netscape_renewal_url, "Certificate renewal URL");
	TRANS(NID_netscape_ca_policy_url, "CA policy URL");
	TRANS(NID_netscape_ssl_server_name, "SSL server name");
	TRANS(NID_netscape_comment, "Comment");
}

QString appendXcaComment(QString current, QString msg)
{
	if (!current.endsWith("\n") && !current.isEmpty())
		current += "\n";
	return current + QString("(%1)\n").arg(msg);
}
