/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509super.h"
#include "widgets/MainWindow.h"

db_x509super::db_x509super(QString db, MainWindow *mw)
	:db_base(db, mw)
{
}

void db_x509super::delKey(pki_key *delkey)
{
	FOR_ALL_pki(pki, pki_x509super) { pki->delRefKey(delkey); }
}

void db_x509super::newKey(pki_key *newkey)
{
	 FOR_ALL_pki(pki,pki_x509super) { pki->setRefKey(newkey); }
}

pki_key *db_x509super::findKey(pki_x509super *ref)
{
	pki_key *key, *refkey;
	if (!ref)
		return NULL;
	if ((key = ref->getRefKey()) != NULL )
		return key;
	refkey = ref->getPubKey();
	if (!refkey)
		return NULL;
	key = (pki_key *)mainwin->keys->getByReference(refkey);
	if (key && key->isPubKey()) {
		key = NULL;
	} else {
		ref->setRefKey(key);
	}
	if (refkey)
		delete(refkey);
	return key;
}

void db_x509super::inToCont(pki_base *pki)
{
	db_base::inToCont(pki);
	findKey((pki_x509super *)pki);
}

