/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs12.h"
#include "pki_evp.h"
#include "pki_x509.h"

#include "pass_info.h"
#include "exception.h"
#include "func.h"
#include "PwDialogCore.h"
#include "XcaWarningCore.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/stack.h>

pki_pkcs12::pki_pkcs12(const QString &d, pki_x509 *acert, pki_key *akey)
	:pki_multi(d), cert(acert), key(akey)
{
	append_item(key);
	append_item(cert);
}

pki_pkcs12::pki_pkcs12(const QString &fname)
	:pki_multi(fname)
{
	Passwd pass;
	EVP_PKEY *mykey = NULL;
	X509 *mycert = NULL;
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the PKCS#12 file:\n%1").arg(compressFilename(fname)));
	const X509_ALGOR *macalgid = NULL;
	const ASN1_INTEGER *maciter = NULL;
	const ASN1_OBJECT *macobj = NULL;

	setFilename(fname);
	XFile file(fname);
	file.open_read();
	BioByteArray b(file.readAll());

	PKCS12 *pkcs12 = d2i_PKCS12_bio(b.ro(), NULL);
	if (pki_ign_openssl_error()) {
		if (pkcs12)
			PKCS12_free(pkcs12);
		throw errorEx(tr("Unable to load the PKCS#12 (pfx) file %1.")
				.arg(fname));
	}
	PKCS12_get0_mac(NULL, &macalgid, NULL, &maciter, pkcs12);
	if (macalgid)
		X509_ALGOR_get0(&macobj, NULL, NULL, macalgid);
	if (macobj) {
		algorithm = OBJ_obj2QString(macobj);
		if (maciter)
			algorithm += QString(", iteration %1").arg(a1int(maciter).toDec());
	}
	while (!PKCS12_verify_mac(pkcs12, pass.constData(), pass.size())) {
		if (pass.size() > 0)
			XCA_PASSWD_ERROR();
		enum open_result result = PwDialogCore::execute(&p, &pass);
		if (result != pw_ok) {
			/* cancel pressed */
			PKCS12_free(pkcs12);
			failed_files << fname;
			throw result;
		}
	}
	STACK_OF(X509) *certstack = sk_X509_new_null();
	PKCS12_parse(pkcs12, pass.constData(), &mykey, &mycert, &certstack);
	int error = ERR_peek_error();
	if (ERR_GET_REASON(error) == PKCS12_R_MAC_VERIFY_FAILURE) {
		pki_ign_openssl_error();
		PKCS12_free(pkcs12);
		sk_X509_free(certstack);
		failed_files << fname;

		throw errorEx(getClassName(),
			 tr("The supplied password was wrong (%1)")
				.arg(ERR_reason_error_string(error)));
	}
	pki_ign_openssl_error();
	if (mycert) {
		unsigned char *str = X509_alias_get0(mycert, NULL);
		if (str)
			alias = QString::fromUtf8((const char *)str);
		alias = QString::fromUtf8(alias.toLatin1());
		cert = new pki_x509(mycert);
		Q_CHECK_PTR(cert);
		if (alias.isEmpty()) {
			cert->autoIntName(fname);
			alias = cert->getIntName();
		} else {
			cert->setIntName(alias);
		}
		cert->pkiSource = imported;
		inheritFilename(cert);
		append_item(cert);
	}
	if (mykey) {
		key = new pki_evp(mykey);
		Q_CHECK_PTR(key);
		key->setIntName(alias + "_key");
		key->pkiSource = imported;
		inheritFilename(key);
		append_item(key);
	}
	for (int i = 0; i < sk_X509_num(certstack); ++i) {
		X509 *crt = sk_X509_value(certstack, i);
		if (!crt)
			continue;
		pki_x509 *cacert = new pki_x509(crt);
		Q_CHECK_PTR(cacert);
		if (alias.isEmpty()) {
			cacert->autoIntName(QString());
		} else {
			cacert->setIntName(QString(alias + "_ca_%1").arg(i));
		}
		cacert->pkiSource = imported;
		inheritFilename(cacert);
		append_item(cacert);
	}
	sk_X509_free(certstack);
	PKCS12_free(pkcs12);
	pki_openssl_error();
}

void pki_pkcs12::writePKCS12(XFile &file, encAlgo &encAlgo) const
{
	Passwd pass;
	PKCS12 *pkcs12;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to encrypt the PKCS#12 file"));

	if (cert == NULL || key == NULL)
		my_error(tr("No key or no Cert and no pkcs12"));

	if (PwDialogCore::execute(&p, &pass, true) != 1)
		return;

	STACK_OF(X509) *certstack = sk_X509_new_null();
	foreach(pki_base *pki, multi) {
		pki_x509 *x = dynamic_cast<pki_x509*>(pki);
		if (x && x != cert)
			sk_X509_push(certstack, x->getCert());
	}
	int certAlgoNid, keyAlgoNid;
	certAlgoNid = keyAlgoNid = encAlgo.getEncAlgoNid();

	// The very ancient 40BitRC2_CBC algorithm at least can
	// be combined with TripleDES_CBC for the keys.
	if (keyAlgoNid == NID_pbe_WithSHA1And40BitRC2_CBC)
		keyAlgoNid = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;

	pkcs12 = PKCS12_create(pass.data(), getIntName().toUtf8().data(),
				key->decryptKey(), cert->getCert(), certstack,
				keyAlgoNid, certAlgoNid, 0, 0, 0);
	pki_openssl_error();
	Q_CHECK_PTR(pkcs12);

	if (encAlgo.legacy())
		PKCS12_set_mac(pkcs12, pass.data(), -1, NULL, 0, 1, EVP_sha1());

	BioByteArray b;
	i2d_PKCS12_bio(b, pkcs12);
	sk_X509_free(certstack);
	pki_openssl_error();
	PKCS12_free(pkcs12);
	file.write(b);
}

void pki_pkcs12::collect_properties(QMap<QString, QString> &prp) const
{
	if (!algorithm.isEmpty())
		prp["Algorithm"] = algorithm;
	if (!alias.isEmpty())
		prp["Friendly Name"] = alias;
}

// see https://www.rfc-editor.org/rfc/rfc8018 Appendix B.2 for possible encryption schemes
const QList<int> encAlgo::all_encAlgos(
{
	NID_pbe_WithSHA1And40BitRC2_CBC,
	NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
	NID_aes_256_cbc
});

int encAlgo::default_encAlgo(NID_pbe_WithSHA1And3_Key_TripleDES_CBC);

encAlgo::encAlgo(int nid) : encAlgo_nid(nid)
{
}

encAlgo::encAlgo(const QString &name) : encAlgo_nid(default_encAlgo)
{
	QString s(name);
	encAlgo_nid = OBJ_txt2nid(CCHAR(s.remove(QChar(' '))));
	ign_openssl_error();
}

QString encAlgo::name() const
{
	return QString(encAlgo_nid == NID_undef ? "" : OBJ_nid2sn(encAlgo_nid));
}

QString encAlgo::displayName() const
{
	QString n = name();
	if (legacy())
		n += QString(" (%1)").arg(QObject::tr("insecure"));
	return n;
}

int encAlgo::getEncAlgoNid() const
{
	return encAlgo_nid;
}

const encAlgo encAlgo::getDefault()
{
	return encAlgo(default_encAlgo);
}

void encAlgo::setDefault(const QString &def)
{
	default_encAlgo = encAlgo(def).encAlgo_nid;
}
