/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_x509super.h"

pki_x509super::pki_x509super(const QString name)
	: pki_base(name)
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
	if (ref == NULL || ref->isPubKey() || privkey != NULL )
		return;
	pki_key *mk = getPubKey();
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

void pki_x509super::autoIntName()
{
	x509name subject = getSubject();
	setIntName(subject.getMostPopular());
}
