/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           

#include "db_x509super.h"

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

void db_x509super::preprocess()
{
	 FOR_ALL_pki(pki,pki_x509super) { findKey(pki); }
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
	}
	else {
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

