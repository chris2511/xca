/* vi: set sw=4 ts=4: */
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
#include <qmessagebox.h>
#include "exception.h"

#define FOR_container for (pki_key *pki = (pki_key *)container.first(); \
                        pki != 0; pki = (pki_key *)container.next() ) 
			

db_key::db_key(DbEnv *dbe, QString DBfile, DbTxn *tid, XcaListView *lvi)
	:db_base(dbe, DBfile, "keydb",tid, lvi)
{
	loadContainer();
}

pki_base *db_key::newPKI(){
	return new pki_key("");
}


QStringList db_key::getPrivateDesc()
{
	QStringList x;
	x.clear();
	FOR_container
		if (pki->isPrivKey())
			x.append(pki->getIntName());	
	return x;
}

QStringList db_key::get0PrivateDesc()
{
	QStringList x;
	x.clear();
	FOR_container
		if (pki->isPrivKey() && pki->getUcount() == 0) 
			x.append(pki->getIntName());	
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

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = (pki_key *)item;
	pki_key *oldkey;

	oldkey = (pki_key *)getByReference(lkey);
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			QMessageBox::information(NULL, tr(XCA_TITLE),
			tr("The key is already in the database as") +":\n'" +
			oldkey->getIntName() +
			"'\n" + tr("and is not going to be imported"), "OK");
			delete(lkey);
			return oldkey; 
		}
		else {
			QMessageBox::information(NULL,tr(XCA_TITLE),
			tr("The database already contains the public part of the imported key as") +":\n'" +
			oldkey->getIntName() +
			"'\n" + tr("and will be completed by the new, private part of the key"), "OK");
			deletePKI(oldkey);
			lkey->setIntName(oldkey->getIntName());
			delete(oldkey);
		}
	}
	insertPKI(lkey);
	
	return lkey;
}

#undef FOR_container
