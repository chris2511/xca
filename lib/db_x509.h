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


#include <qlistview.h>
#include <qpixmap.h>
#include "db_key.h"
#include "pki_x509.h"
#include "pki_crl.h"

#ifndef DB_X509_H
#define DB_X509_H


class db_x509: public db_base
{
	Q_OBJECT
    protected:
	db_key *keylist;
	QPixmap *certicon[4];
    public:
	int viewState;
	db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl, DbTxn *tid);
	pki_base *newPKI();
	pki_x509 *findSigner(pki_x509 *client);
	bool updateView();
	void insertPKI(pki_base *pki);
	void updateViewAll();
	void updateViewPKI(pki_base *pki);
	void remFromCont(pki_base *pki);
	void preprocess();
	QStringList getPrivateDesc();
	QStringList getSignerDesc();
	pki_key * findKey(pki_x509 *cert);
	void calcEffTrust();
	QList<pki_x509> db_x509::getIssuedCerts(pki_x509 *issuer);
	int searchSerial(pki_x509 *signer);
	void writeAllCerts(QString fname, bool onlyTrusted);
    public slots:
	void delKey(pki_key *delkey);
    	void newKey(pki_key *newKey);
};

#endif
