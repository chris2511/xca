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
 *	http://www.sleepycat.com
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


#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, QListView *l)
	:db_base(dbe, DBfile, "keydb")
{
	listView = l;
	loadContainer();
	keyicon[0] = loadImg("key.png");
	keyicon[1] = loadImg("halfkey.png");
	listView->addColumn(tr("Keysize"));
	listView->addColumn(tr("Use count"));
	updateView();
}

pki_base *db_key::newPKI(){
	return new pki_key("");
}


QStringList db_key::getPrivateDesc()
{
	pki_key *pki;
	QStringList x;
	x.clear();
	for ( pki = (pki_key *)container.first(); pki != 0; pki = (pki_key *)container.next() )	{
		if (pki->isPrivKey()) {
			x.append(pki->getDescription().c_str());	
		}
	}
	return x;
}

void db_key::remFromCont(pki_base *pki)
{
	db_base::remFromCont(pki);
	emit delKey((pki_key *)pki);
}

void db_key::inToCont(pki_base *pki) 
{
	db_base::inToCont(pki);
	emit newKey((pki_key *)pki);
}


void db_key::updateViewPKI(pki_base *pki)
{
        db_base::updateViewPKI(pki);
        if (! pki) return;
        int pixnum = 0;
        QListViewItem *current = (QListViewItem *)pki->getPointer();
        if (!current) return;
	if (((pki_key *)pki)->isPubKey()) pixnum += 1;	
	current->setPixmap(0, *keyicon[pixnum]);
	current->setText(1, ((pki_key *)pki)->length().c_str());
	current->setText(2, QString::number(((pki_key *)pki)->getUcount()));
}
