/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_export.h"
#include <QDebug>

pki_export::pki_export(int i, enum pki_type p, const QString &e,
			const QString &d, int f, const QString &h)
	: id(i), pki_type(p), extension(e), flags(f), desc(d), help(h)
{
}

bool pki_export::match_all(int match_flags) const
{
	return (flags & match_flags) == match_flags;
}

QList<const pki_export*>
pki_export::select(enum pki_type pki_type, int disable)
{
	QList<const pki_export*> ret;

	foreach(const pki_export *exp, elements) {
		if (exp->pki_type == pki_type)
			qDebug() << exp->id << QString("Disable %1 %2").arg(disable, 0, 16).arg(disable & exp->flags, 0, 16);
		if (exp->pki_type == pki_type && (disable & exp->flags) == 0)
			ret << exp;
	}
	return ret;
}

const pki_export *pki_export::by_id(int id)
{
	foreach(const pki_export *exp, elements) {
		if (exp->id == id)
			return exp;
	}
	return NULL;
}

void pki_export::free_elements()
{
#ifndef QT_NO_DEBUG
	QList<int> ids;
	foreach(pki_export *e, elements) {
		Q_ASSERT(!ids.contains(e->id));
		ids << e->id;
	}
#endif
	qDeleteAll(elements);
	elements.clear();
}

QList<pki_export*> pki_export::elements;
void pki_export::init_elements()
{
	free_elements();
	elements = QList<pki_export*> {

new pki_export( 1, x509, "crt", "PEM",               F_PEM | F_USUAL | F_SINGLE,             tr("PEM Text format with headers")),
new pki_export( 3, x509, "pem", "PEM",               F_PEM | F_MULTI,                        tr("Concatenated list of all selected items in one PEM text file")),
new pki_export( 2, x509, "pem", tr("PEM chain"),     F_PEM | F_USUAL | F_CHAIN | F_SINGLE,   tr("Concatenated text format of the complete certificate chain in one PEM file")),
new pki_export( 4, x509, "ovpn","OpenVPN",           F_PEM | F_OVPN | F_CHAIN | F_PRIVATE | F_SINGLE, tr("The complete certificate chain and the private key of the selected certificate with tags usable in OpenVPN configuration files")),
new pki_export( 6, x509, "pem", tr("PEM + key"),     F_PEM | F_PRIVATE| F_SINGLE,            tr("Concatenation of the certificate and the unencrypted private key in one PEM file")),
new pki_export( 7, x509, "pem",    "PEM + PKCS#8",   F_PEM | F_PKCS8 | F_PRIVATE | F_CRYPT,  tr("Concatenation of the certificate and the encrypted private key in PKCS#8 format in one file")),
new pki_export( 8, x509, "p7b",    "PKCS #7",        F_PKCS7 | F_USUAL | F_SINGLE,           tr("PKCS#7 encoded single certificate")),
new pki_export(10, x509, "p7b",    "PKCS #7",        F_PKCS7 | F_USUAL | F_MULTI,            tr("All selected certificates encoded in one PKCS#7 file")),
new pki_export(12, x509, "p7b", tr("PKCS #7 chain"), F_PKCS7 | F_USUAL | F_CHAIN | F_SINGLE, tr("PKCS#7 encoded complete certificate chain")),
new pki_export(13, x509, "cer",    "DER",            F_DER | F_SINGLE,                       tr("Binary DER encoded certificate")),
new pki_export(14, x509, "pfx", tr("PKCS #12 chain"),F_PKCS12 | F_USUAL | F_CHAIN | F_CRYPT | F_PRIVATE | F_SINGLE, tr("The complete certificate chain and the private key as encrypted PKCS#12 file")),
new pki_export(15, x509, "pfx", tr("PKCS #12"),      F_PKCS12 | F_USUAL | F_CRYPT | F_PRIVATE | F_SINGLE,           tr("The certificate and the private key as encrypted PKCS#12 file")),
new pki_export(16, x509, "txt", tr("Certificate Index file"), F_INDEX | F_CA,                tr("OpenSSL specific Certificate Index file as created by the 'ca' command and required by the OCSP tool")),
new pki_export(17, x509, "ics", tr("vCalendar"),     F_CAL,                                  tr("vCalendar expiry reminder for the selected items")),
new pki_export(18, x509, "ics", tr("CA vCalendar"),  F_CAL | F_CA,                           tr("vCalendar expiry reminder containing all issued, valid certificates, the CA itself and the latest CRL")),
new pki_export(38, x509, "conf", tr("OpenSSL config"), F_SINGLE | F_CONFIG,                  tr("OpenSSL configuration file to create a certificate or request with the openssl commandline tool")),
new pki_export(39, x509, "key", tr("OpenVPN tls-auth key"), F_SINGLE | F_TAKEY,              tr("The OpenVPN tls-auth key is a secret key shared between endpoints")),

new pki_export(19, asym_key, "pem", tr("PEM public"),    F_PEM | F_CLIPBOARD,                            tr("Text format of the public key in one PEM file")),
new pki_export(20, asym_key, "pem", tr("PEM private"),   F_PEM | F_PRIVATE | F_USUAL | F_CLIPBOARD,      tr("Unencrypted private key in text format")),
new pki_export(21, asym_key, "pem", tr("PEM encrypted"), F_PEM | F_PRIVATE | F_CRYPT | F_SINGLE,         tr("OpenSSL specific encrypted private key in text format")),
new pki_export(22, asym_key, "priv",tr("SSH2 private"),  F_PEM | F_PRIVATE | F_SSH2 | F_SINGLE,           tr("Unencrypted private key in text format")),
new pki_export(23, asym_key, "pub" ,tr("SSH2 public"),   F_SSH2,                                         tr("The public key encoded in SSH2 format")),
new pki_export(24, asym_key, "der", tr("DER public"),    F_DER | F_SINGLE,                               tr("Binary DER format of the public key")),
new pki_export(25, asym_key, "der", tr("DER private"),   F_DER | F_PRIVATE | F_SINGLE,                   tr("Unencrypted private key in binary DER format")),
new pki_export(26, asym_key, "pvk", tr("PVK private"),   F_PVK | F_PRIVATE | F_SINGLE,                   tr("Private key in Microsoft PVK format not encrypted")),
new pki_export(27, asym_key, "pvk", tr("PVK encrypted"), F_PVK | F_PRIVATE | F_CRYPT | F_SINGLE,         tr("Encrypted private key in Microsoft PVK format")),
new pki_export(28, asym_key, "pk8", tr("PKCS #8 encrypted"), F_PKCS8 | F_PRIVATE | F_CRYPT | F_USUAL | F_SINGLE, tr("Encrypted private key in PKCS#8 text format")),
new pki_export(29, asym_key, "pk8", tr("PKCS #8"),       F_PKCS8 | F_PRIVATE | F_CLIPBOARD | F_SINGLE,  tr("Unencrypted private key in PKCS#8 text format")),

new pki_export(30, x509_req, "csr", "PEM",  F_PEM,                       tr("PEM Text format with headers")),
new pki_export(31, x509_req, "der", "DER",  F_DER | F_SINGLE,            tr("Binary DER format of the certificate request")),
new pki_export(37, x509_req, "conf", tr("OpenSSL config"), F_SINGLE | F_CONFIG, tr("OpenSSL configuration file to create a certificate or request with the openssl commandline tool")),

new pki_export(32, revocation, "crl", "PEM",  F_PEM,                     tr("PEM Text format with headers")),
new pki_export(33, revocation, "der", "DER",  F_DER | F_SINGLE,          tr("Binary DER format of the revocation list")),
new pki_export(34, revocation, "ics", tr("vCalendar"), F_CAL,            tr("vCalendar reminder for the CRL expiry date")),

new pki_export(35, tmpl, "xca", "PEM", F_PEM | F_SINGLE,                 tr("XCA template in PEM-like format")),
new pki_export(36, tmpl, "pem", "PEM", F_PEM | F_MULTI,                  tr("All selected XCA templates in PEM-like format")),
	};
}
