/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "func_base.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <QDir>
#include <QStringList>
#include <QDebug>
#include <QRegularExpression>

#include "exception.h"

bool is_gui_app = false;

const QStringList getLibExtensions()
{
	return QStringList {
#if defined(Q_OS_WIN32)
		QString("*.dll"), QString("*.DLL"),
#elif defined(Q_OS_MACOS)
		QString("*.dylib"), QString("*.so"),
#else
		QString("*.so"),
#endif
	};
}

// Qt's open and save dialogs result in some undesirable quirks.
// This function makes sure that a filename has the user-selected extension.
QString getFullFilename(const QString & filename, const QString & selectedFilter)
{
	QString rv = filename.trimmed(), ext;
	auto match = QRegularExpression(".* \\( ?\\*(.[a-z]{1,3}) ?\\)")
					.match(selectedFilter);

	ext = match.captured(1);
	if (ext.isEmpty() || rv.endsWith(ext))
		return rv;

	return rv + ext;
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
	unsigned char *out = NULL;
	int len;
	QString utf8;

	len = ASN1_STRING_to_UTF8(&out, str);
	if (len != -1) {
		utf8 = QString::fromUtf8((const char*)out, len);
		OPENSSL_free(out);
	}
	if (quote)
		utf8.replace('\n', "\\n\\");
	return utf8;
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
	openssl_error_msg(QString("'%1' (%2)").arg(s).arg(OBJ_nid2ln(nid)));
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
	ret = d2i(NULL, &p1, ba.size());
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
			.replace(QRegularExpression(QString("(.{%1})(?=.)").arg(width)),
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
