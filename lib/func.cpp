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
#include "lib/settings.h"
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
#include <QFileInfo>
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
#include <stdarg.h>

#if defined(Q_OS_WIN32)
#include <shlobj.h>
#include <conio.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x04
#endif
#else
#include <termios.h>
#define getch() getchar()
#endif

int console_write(FILE *fp, const QByteArray &ba)
{
	if (ba.size() == 0)
		return 0;
#if defined(Q_OS_WIN32)
	HANDLE con = GetStdHandle(fp == stderr ? STD_ERROR_HANDLE :
						 STD_OUTPUT_HANDLE);
	if (con != INVALID_HANDLE_VALUE) {
		QString string = QString::fromUtf8(ba);
		WriteConsoleW(con, string.utf16(), string.size(), NULL, NULL);
		//return 0;
	}
#endif
	fputs(ba.constData(), fp);
	fflush(fp);
	return 0;
}

Passwd readPass()
{
	Passwd pw;
#if !defined(Q_OS_WIN32)
	struct termios t, back;
	if (tcgetattr(0, &t))
		throw errorEx(strerror(errno));
	back = t;
	t.c_lflag &= ~(ECHO | ICANON);
	if (tcsetattr(0, TCSAFLUSH, &t))
		throw errorEx(strerror(errno));
#else
	qFatal("Password input not supported");
#endif
	while(1) {
		char p = getch();
		if (p == '\n' || p == '\r')
			break;
		if (p == 0x7f)
			pw.chop(1);
		else
			pw += p;
	}
	fputc('\n', stdout);
#if !defined(Q_OS_WIN32)
	if (tcsetattr(0, TCSAFLUSH, &back))
		throw errorEx(strerror(errno));
#endif
	return pw;
}

QPixmap *loadImg(const char *name )
{
	return new QPixmap(QString(":") + name);
}

const QStringList getLibExtensions()
{
	return QStringList {
#if defined(Q_OS_WIN32)
		QString("*.dll"), QString("*.DLL"),
#elif defined(Q_OS_MAC)
		QString("*.dylib"), QString("*.so"),
#else
		QString("*.so"),
#endif
	};
}

#if defined(Q_OS_WIN32)
static QString xcaExeDir()
{
	QString dir;
	wchar_t inst_dir[2048];
	ULONG dwLength = ARRAY_SIZE(inst_dir);

	dwLength = GetModuleFileNameW(0, inst_dir, dwLength - 1);
	dir = QString::fromWCharArray(inst_dir, dwLength);
	int bslash = dir.lastIndexOf("\\");
	if (bslash > 0)
		dir = dir.mid(0, bslash);
	return QFileInfo(dir).canonicalFilePath();
}

static QString registryInstallDir()
{
	QString dir;
	wchar_t inst_dir[2048] = L"";
	ULONG len = sizeof inst_dir;

	if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\xca",
			L"Install_Dir64", RRF_RT_REG_SZ, NULL,
			inst_dir, &len) != ERROR_SUCCESS)
		return dir;

	/* "len" is in octets */
	len /= sizeof inst_dir[0];
	/* "len" includes the trailing \0\0 */
	dir = QString::fromWCharArray(inst_dir, len -1);
	return QFileInfo(dir).canonicalFilePath();
}
#endif

int portable_app()
{
	static int portable = -1;
	QString f1, f2;
	if (portable == -1) {
#if defined(Q_OS_WIN32)
		f1 = registryInstallDir();
		f2 = xcaExeDir();
		/* f1 == f2 Registry entry of install dir exists and matches
		 * path of this xca.exe -> Installed. Not the portable app
		 */
		portable = f1 == f2 ? 0 : 1;
		qDebug() << "Portable:" << f1 << " != " << f2;
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

const QString getPrefix()
{
#if defined(Q_OS_WIN32)
	static QString inst_dir;
	QString reg_dir;

	if (!inst_dir.isEmpty()) {
		/* if we already once discovered the directory just return it */
		return inst_dir;
	}
	inst_dir = xcaExeDir();

	if (portable_app())
		return QString(inst_dir);

	reg_dir = registryInstallDir();
	if (reg_dir.isEmpty())
		XCA_WARN("Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
	else
		inst_dir = reg_dir;
	return inst_dir;

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

#if defined(Q_OS_WIN32)
static QString specialFolder(int csidl)
{
	LPITEMIDLIST pidl = NULL;
	wchar_t buf[MAX_PATH] = L"";

	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, csidl, &pidl)))
		SHGetPathFromIDListW(pidl, buf);

	QString f = QString::fromWCharArray(buf);
	qDebug() << "Special Folder" << csidl << f;
	return QFileInfo(f).canonicalFilePath();
}
#endif

const QString getHomeDir()
{
#if defined(Q_OS_WIN32)
	return portable_app() ? getPrefix() : specialFolder(CSIDL_PERSONAL);
#else
	return QDir::homePath();
#endif
}

/* For portable APP remove leading file name if it is
 * the app directory.
 */
QString relativePath(QString path)
{
	QFileInfo fi_path(path);
	QFileInfo fi_home(getHomeDir());

	QString prefix = fi_home.absoluteFilePath();
	path = fi_path.absoluteFilePath();

	if (portable_app()) {
		if (path.startsWith(prefix))
			path = path.mid(prefix.length()+1);
	}
	return path;
}

const QString getLibDir()
{
#if defined(Q_OS_WIN32)
	return specialFolder(CSIDL_SYSTEM);
#else
	QString ulib = "/usr/lib/";
	QString lib = "/lib/";
	QString multi;
	QString hd = ulib;

	QFile f(ulib + "pkg-config.multiarch");
	if (f.open(QIODevice::ReadOnly)) {
		QTextStream in(&f);
		multi = in.readLine();
		if (!multi.isEmpty())
			multi += "/";
	}
	QStringList dirs; dirs
		<< ulib + multi + "pkcs11/"
		<< lib + multi + "pkcs11/"
		<< ulib + "pkcs11/"
		<< lib + "pkcs11/"
		<< ulib + multi
		<< lib + multi
		<< ulib
		<< lib;
	foreach(QString dir, dirs) {
		if (QDir(dir).exists()) {
			hd = dir;
			break;
		}
	}
	return QFileInfo(hd).canonicalFilePath();
#endif
}

const QString getDocDir()
{
#if defined(Q_OS_WIN32)
	return getPrefix() + "\\html";
#elif defined (Q_OS_MAC)
	return getPrefix();
#else
	return QString(DOCDIR);
#endif
}

// The intent of this function is to return the proper location for
// user-controlled settings on the current platform
// i.e. PROFILE\Application Data\xca on windows, HOME/.xca on UNIX,
// ~/Library/Preferences/xca on Mac OS X
const QString getUserSettingsDir()
{
	QString rv;
#if defined(Q_OS_WIN32)
	rv = portable_app() ? getPrefix() + "/settings" :
				specialFolder(CSIDL_APPDATA) + "/xca";
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
	rv = QDir::homePath() + "/.xca";
#endif
	return rv;
}

const QString getI18nDir()
{
#if defined(Q_OS_WIN32)
	return getPrefix() + "\\i18n";
#else
	return getPrefix();
#endif
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

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_CRYPTO, 0,
			KEY_READ, &hKey) != ERROR_SUCCESS) {
		XCA_WARN("Registry Key: '" REG_CRYPTO "' not found");
	} else {
		if (RegQueryValueExA(hKey, REG_GUID, NULL, NULL,
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

QString compressFilename(const QString &filename, int maxlen)
{
	QString fn = filename;
	if (fn.length() >= maxlen) {
		fn.replace("\\", "/");
		int len, lastslash = fn.lastIndexOf('/');
		QString base = filename.mid(lastslash);
		len = maxlen - base.length() - 3;
		if (len < 0) {
			fn = "..." + base.right(maxlen -3);
		} else {
			fn = fn.left(len);
			lastslash = fn.lastIndexOf('/');
			fn = filename.left(lastslash + 1) + "..." + base;
		}
	}
	return nativeSeparator(fn);
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

void _openssl_error(const QString &txt, const char *file, int line)
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
bool _ign_openssl_error(const QString &txt, const char *file, int line)
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

QString formatHash(const QByteArray &data, QString sep, int width)
{
	return QString(data.toHex()).toUpper()
			.replace(QRegExp(QString("(.{%1})(?=.)").arg(width)),
				 QString("\\1") + sep);
}

QByteArray Digest(const QByteArray &data, const EVP_MD *type)
{
	unsigned int n;
	unsigned char m[EVP_MAX_MD_SIZE];

	EVP_Digest(data.constData(), data.size(), m, &n, type, NULL);
	openssl_error();
	return QByteArray((char*)m, (int)n);
}

QString fingerprint(const QByteArray &data, const EVP_MD *type)
{
	return formatHash(Digest(data, type),
			Settings["fp_separator"], Settings["fp_digits"]);
}

void update_workingdir(const QString &file)
{
	Settings["workingdir"] = QFileInfo(file).absolutePath();
}

QMap<int, QString> dn_translations;

void dn_translations_setup()
{
QMap<int, QString> D;
D[NID_countryName] = QObject::tr("Country code");
D[NID_stateOrProvinceName] = QObject::tr("State or Province");
D[NID_localityName] = QObject::tr("Locality");
D[NID_organizationName] = QObject::tr("Organisation");
D[NID_organizationalUnitName] = QObject::tr("Organisational unit");
D[NID_commonName] = QObject::tr("Common name");
D[NID_pkcs9_emailAddress] = QObject::tr("E-Mail address");
D[NID_serialNumber] = QObject::tr("Serial number");
D[NID_givenName] = QObject::tr("Given name");
D[NID_surname] = QObject::tr("Surname");
D[NID_title] = QObject::tr("Title");
D[NID_initials] = QObject::tr("Initials");
D[NID_description] = QObject::tr("Description");
D[NID_role] = QObject::tr("Role");
D[NID_pseudonym] = QObject::tr("Pseudonym");
D[NID_generationQualifier] = QObject::tr("Generation Qualifier");
D[NID_x500UniqueIdentifier] = QObject::tr("x500 Unique Identifier");
D[NID_name] = QObject::tr("Name");
D[NID_dnQualifier] = QObject::tr("DN Qualifier");
D[NID_pkcs9_unstructuredName] = QObject::tr("Unstructured name");
D[NID_pkcs9_challengePassword] = QObject::tr("Challenge password");

D[NID_basic_constraints] = QObject::tr("Basic Constraints");
D[NID_subject_alt_name] = QObject::tr("Subject alternative name");
D[NID_issuer_alt_name] = QObject::tr("issuer alternative name");
D[NID_subject_key_identifier] = QObject::tr("Subject key identifier");
D[NID_authority_key_identifier] = QObject::tr("Authority key identifier");
D[NID_key_usage] = QObject::tr("Key usage");
D[NID_ext_key_usage] = QObject::tr("Extended key usage");
D[NID_crl_distribution_points] = QObject::tr("CRL distribution points");
D[NID_info_access] = QObject::tr("Authority information access");
D[NID_netscape_cert_type] = QObject::tr("Certificate type");
D[NID_netscape_base_url] = QObject::tr("Base URL");
D[NID_netscape_revocation_url] = QObject::tr("Revocation URL");
D[NID_netscape_ca_revocation_url] = QObject::tr("CA Revocation URL");
D[NID_netscape_renewal_url] = QObject::tr("Certificate renewal URL");
D[NID_netscape_ca_policy_url] = QObject::tr("CA policy URL");
D[NID_netscape_ssl_server_name] = QObject::tr("SSL server name");
D[NID_netscape_comment] = QObject::tr("Comment");

dn_translations = D;
}

QString appendXcaComment(QString current, QString msg)
{
	if (!current.endsWith("\n") && !current.isEmpty())
		current += "\n";
	return current + QString("(%1)\n").arg(msg);
}
