/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "func.h"
#include "exception.h"
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#if defined(Q_WS_MAC)
#include <QDesktopServices>
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

QStringList getLibExtensions()
{
	QStringList l;
#if defined(_WIN32) || defined(USE_CYGWIN)
	l << QString("*.dll") << QString("*.DLL");
#elif defined(Q_WS_MAC)
	l << QString("*.dylib") << QString("*.so");
#else
	l << QString("*.so");
#endif
	return l;
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
	lRc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca", 0, KEY_READ, &hKey);
	if (lRc != ERROR_SUCCESS) {
		XCA_WARN("Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
		return QString(inst_dir);
	}
	lRc = RegQueryValueEx(hKey, "Install_Dir", NULL, NULL,
			(unsigned char *)inst_dir, &dwLength);
	if (lRc != ERROR_SUCCESS){
		XCA_WARN("Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");
	}
	lRc = RegCloseKey(hKey);
	return QString(inst_dir);

#elif defined(Q_WS_MAC)
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

QString getLibDir()
{
	QString hd;
#ifdef WIN32
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
	LPITEMIDLIST pidl = NULL;
	TCHAR buf[255] = "";
	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_APPDATA, &pidl))) {
	SHGetPathFromIDList(pidl, buf);
	}
	rv = buf;
	rv += QDir::separator();
	rv += "xca";
#elif defined(Q_WS_MAC)
	rv = QDesktopServices::storageLocation(QDesktopServices::DataLocation);
	rv.insert(rv.count() - QCoreApplication::applicationName().count(),
		QCoreApplication::organizationName());
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

	len = OBJ_obj2txt(buf, 256, a, no_name);
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
		fprintf(stderr, "%s\n", CCHAR(txt));
#else
	(void)txt;
	(void)file;
	(void)line;
#endif
	while (int i = ERR_get_error() ) {
		errtxt = ERR_error_string(i, NULL);
#if PRINT_IGNORED_ANYWAY
		fprintf(stderr, CCHAR(QString("IGNORED (%1:%2) : %3\n").
			arg(file).arg(line).arg(errtxt)));
#endif
	}
	return !errtxt.isEmpty();
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

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	BUF_MEM *bm = (BUF_MEM *)b->ptr;
	if (!bm->data || !(b->flags & BIO_FLAGS_MEM_RDONLY))
		return BIO_s_mem()->ctrl(b, cmd, num, ptr);

	switch (cmd) {
	case BIO_C_FILE_SEEK:
		if (num > (long)bm->max)
			num = bm->max;
		bm->data -= (bm->max - bm->length) - num;
		bm->length = bm->max - num;
	case BIO_C_FILE_TELL:
		return bm->max - bm->length;
	}
	return BIO_s_mem()->ctrl(b, cmd, num, ptr);
}

void BIO_seekable_romem(BIO *b)
{
	static BIO_METHOD *mymeth = NULL;
	static BIO_METHOD _meth;

	if (!(b->flags & BIO_FLAGS_MEM_RDONLY) ||
	     (b->method->type != BIO_TYPE_MEM))
	{
		return;
	}
	if (!mymeth) {
		_meth = *BIO_s_mem();
		_meth.ctrl = mem_ctrl;
		mymeth = &_meth;
	}
	b->method = mymeth;
}

BIO *BIO_QBA_mem_buf(QByteArray &a)
{
	BIO *b = BIO_new_mem_buf(a.data(), a.size());
	BIO_seekable_romem(b);
	return b;
}

bool translate_dn = false;
QMap<int, QString> dn_translations;

void dn_translations_setup()
{
	dn_translations[NID_countryName] = QObject::tr("Country code");
	dn_translations[NID_stateOrProvinceName] = QObject::tr("State or Province");
	dn_translations[NID_localityName] = QObject::tr("Locality");
	dn_translations[NID_organizationName] = QObject::tr("Organisation");
	dn_translations[NID_organizationalUnitName] = QObject::tr("Organisational unit");
	dn_translations[NID_commonName] = QObject::tr("Common name");
	dn_translations[NID_pkcs9_emailAddress] = QObject::tr("E-Mail address");
	dn_translations[NID_serialNumber] = QObject::tr("Serial number");
	dn_translations[NID_givenName] = QObject::tr("Given name");
	dn_translations[NID_surname] = QObject::tr("Surname");
	dn_translations[NID_title] = QObject::tr("Title");
	dn_translations[NID_initials] = QObject::tr("Initials");
	dn_translations[NID_description] = QObject::tr("Description");
	dn_translations[NID_role] = QObject::tr("Role");
	dn_translations[NID_pseudonym] = QObject::tr("Pseudonym");
	dn_translations[NID_generationQualifier] = QObject::tr("Generation Qualifier");
	dn_translations[NID_x500UniqueIdentifier] = QObject::tr("x500 Unique Identifier");
	dn_translations[NID_name] = QObject::tr("Name");
	dn_translations[NID_dnQualifier] = QObject::tr("DN Qualifier");
	dn_translations[NID_pkcs9_unstructuredName] = QObject::tr("Unstructured name");
	dn_translations[NID_pkcs9_challengePassword] = QObject::tr("Challenge password");

	dn_translations[NID_basic_constraints] = QObject::tr("Basic Constraints");
	dn_translations[NID_subject_alt_name] = QObject::tr("subject alternative name");
	dn_translations[NID_issuer_alt_name] = QObject::tr("issuer alternative name");
	dn_translations[NID_subject_key_identifier] = QObject::tr("Subject key identifier");
	dn_translations[NID_authority_key_identifier] = QObject::tr("Authority key identifier");
	dn_translations[NID_key_usage] = QObject::tr("Key usage");
	dn_translations[NID_ext_key_usage] = QObject::tr("Extended key usage");
	dn_translations[NID_crl_distribution_points] = QObject::tr("CRL distribution points");
	dn_translations[NID_info_access] = QObject::tr("Authority information access");
	dn_translations[NID_netscape_cert_type] = QObject::tr("Certificate type");
	dn_translations[NID_netscape_base_url] = QObject::tr("Base URL");
	dn_translations[NID_netscape_revocation_url] = QObject::tr("Revocation URL");
	dn_translations[NID_netscape_ca_revocation_url] = QObject::tr("CA Revocation URL");
	dn_translations[NID_netscape_renewal_url] = QObject::tr("Certificate renewal URL");
	dn_translations[NID_netscape_ca_policy_url] = QObject::tr("CA policy URL");
	dn_translations[NID_netscape_ssl_server_name] = QObject::tr("SSL server name");
	dn_translations[NID_netscape_comment] = QObject::tr("Comment");
}
