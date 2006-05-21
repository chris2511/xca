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
 *	written by Eric Young (eay@cryptsoft.com)"
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

x509name pki_x509super::getSubject() const
{
	x509name x;
	printf("ERROR VIRTUAL getSubject() %s\n", class_name);
	openssl_error();
	return x;
}


int pki_x509super::verify()
{
	 return -1;
}

pki_key *pki_x509super::getPubKey() const
{
	 printf("ERROR VIRTUAL getPubKey() %s\n", class_name);
	 return NULL;
}

pki_key *pki_x509super::getRefKey() const
{
	return privkey;
}

void pki_x509super::setRefKey(pki_key *ref)
{
	if (ref == NULL || ref->isPubKey() || privkey != NULL ) return;
	pki_key *mk = getPubKey();
	if (ref->compare(mk)) {
		// this is our key
		privkey = ref;
		ref->incUcount();
		//updateView();
	}
	delete mk;
}

void pki_x509super::delRefKey(pki_key *ref)
{
	if (ref != privkey || ref == NULL) return;
	ref->decUcount();
	privkey = NULL;
	//updateView();
}

void pki_x509super::autoIntName()
{
	setIntName(getSubject().getEntryByNid(NID_commonName));
}
