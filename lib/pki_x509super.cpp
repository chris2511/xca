/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

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

QVariant pki_x509super::column_data(int id)
{
	switch (id) {
	case HD_x509key_name:
		if (!privkey)
			return QVariant("");
		return QVariant(privkey->getIntName());
	}
	return pki_x509name::column_data(id);
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

QVariant pki_x509name::column_data(int id)
{
	switch (id) {
	case HD_subject_name:
		return QVariant(getSubject().oneLine(
				XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB));
	case HD_subject_hash:
		return  QVariant(getSubject().hash());
	default:
		if (dbheader::isNid(id))
			return QVariant(getSubject().getEntryByNid(id));
	}
	return pki_base::column_data(id);
}
