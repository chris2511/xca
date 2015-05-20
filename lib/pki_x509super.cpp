/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "func.h"
#include "oid.h"
#include "pki_x509super.h"

pki_x509super::pki_x509super(const QString name)
	: pki_x509name(name)
{
	privkey = NULL;
}

pki_x509super::~pki_x509super()
{
	if (privkey)
		privkey->decUcount();
	privkey = NULL;
}

pki_key *pki_x509super::getRefKey() const
{
	return privkey;
}

void pki_x509super::setRefKey(pki_key *ref)
{
	if (ref == NULL || privkey != NULL )
		return;
	pki_key *mk = getPubKey();
	if (mk == NULL)
		return;
	if (ref->compare(mk)) {
		// this is our key
		privkey = ref;
		ref->incUcount();
	}
	delete mk;
}

void pki_x509super::delRefKey(pki_key *ref)
{
	if (ref != privkey || ref == NULL)
		return;
	ref->decUcount();
	privkey = NULL;
}

QString pki_x509super::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(sigAlg()));
	pki_openssl_error();
	return alg;
}

const EVP_MD *pki_x509super::getDigest()
{
	return EVP_get_digestbyobj(sigAlg());
}

QVariant pki_x509super::column_data(dbheader *hd)
{
	if (hd->id == HD_x509key_name) {
		if (!privkey)
			return QVariant("");
		return QVariant(privkey->getIntName());
	}
	if (hd->id == HD_x509_sigalg) {
		return QVariant(getSigAlg());
	}
	if (hd->type == dbheader::hd_v3ext || hd->type == dbheader::hd_v3ext_ns) {
		extList el = getV3ext();
		int idx = el.idxByNid(hd->id);
		if (idx == -1)
			return QVariant("");
		return QVariant(el[idx].getValue(false));
	}
	return pki_x509name::column_data(hd);
}

static QString oid_sect()
{
	QString ret;
	int i, max = OBJ_new_nid(0);

	for (i=first_additional_oid; i < max; i++) {
		const char *sn = OBJ_nid2sn(i);
		if (!sn)
			break;
		ret += QString("%1 = %2\n").
			arg(OBJ_nid2sn(i)).
			arg(OBJ_obj2QString(OBJ_nid2obj(i), 1));
	}

	if (!ret.isEmpty()) {
		ret = QString("oid_section = xca_oids\n\n"
			"[ xca_oids ]\n") + ret + "\n";
	}
	return ret;
}

void pki_x509super::opensslConf(QString fname)
{
	QString extensions;
	extList el = getV3ext();
	x509name n = getSubject();
	el.genGenericConf(&extensions);

	QString name = n.taggedValues();
	QString final = oid_sect();
	final += QString("[ req ]\n"
		"default_bits = 1024\n"
		"default_keyfile = privkey.pem\n"
		"distinguished_name = xca_dn\n"
		"x509_extensions = xca_extensions\n"
		"req_extensions = xca_extensions\n"
		"string_mask = MASK:0x%3\n"
		"utf8 = yes\n"
		"prompt = no\n\n"
		"[ xca_dn ]\n"
		"%1\n"
		"[ xca_extensions ]\n"
		"%2").arg(name).arg(extensions).
			arg(ASN1_STRING_get_default_mask(), 0, 16);

	FILE *fp = fopen_write(fname);
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	QByteArray ba = final.toUtf8();
	fwrite_ba(fp, ba, fname);
	fclose(fp);
}

bool pki_x509super::visible()
{
	if (pki_x509name::visible())
		return true;
	if (getSigAlg().contains(limitPattern))
		return true;
	return getV3ext().search(limitPattern);
}

// Start class  pki_x509name

pki_x509name::pki_x509name(const QString name)
	: pki_base(name)
{
}

void pki_x509name::autoIntName()
{
	x509name subject = getSubject();
	setIntName(subject.getMostPopular());
}

QVariant pki_x509name::column_data(dbheader *hd)
{
	switch (hd->id) {
	case HD_subject_name:
		return QVariant(getSubject().oneLine(
				XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB));
	case HD_subject_hash:
		return  QVariant(getSubject().hash());
	default:
		if (hd->type == dbheader::hd_x509name)
			return QVariant(getSubject().getEntryByNid(hd->id));
	}
	return pki_base::column_data(hd);
}

bool pki_x509name::visible()
{
	if (pki_base::visible())
		return true;
	return getSubject().search(limitPattern);
}
