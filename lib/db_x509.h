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


#ifndef DB_X509_H
#define DB_X509_H

#include <Qt/qlistview.h>
#include <Qt/qobject.h>
#include <Qt/qpixmap.h>
#include "db_key.h"
#include "db_x509super.h"
#include "pki_x509.h"
#include "pki_crl.h"


class db_x509: public db_x509super
{
	Q_OBJECT
    
	protected:
	QPixmap *certicon[4];
	
    public:
	db_x509(QString DBfile, MainWindow *mw);
	pki_base *newPKI();
	pki_x509 *findSigner(pki_x509 *client);
	bool updateView();
	void updateViewAll();
	void updateViewPKI(pki_base *pki);
	void remFromCont(QModelIndex &idx);
	void preprocess();
	QStringList getPrivateDesc();
	QStringList getSignerDesc();
	void calcEffTrust();
	QList<pki_x509*> getIssuedCerts(const pki_x509 *issuer);
	QList<pki_x509*> getCerts(bool onlyTrusted);
	a1int searchSerial(pki_x509 *signer);
	void writeAllCerts(const QString fname, bool onlyTrusted);
	pki_x509 *getByIssSerial(const pki_x509 *issuer, const a1int &a);
	pki_x509 *getBySubject(const x509name &xname, pki_x509 *last = NULL);
	pki_base *insert(pki_base *item);
	void newCert(NewX509 *dlg);
	void writePKCS12(pki_x509 *cert, QString s, bool chain);
    void writePKCS7(pki_x509 *cert, QString s, int type);
	void showContextMenu(QContextMenuEvent *e, const QModelIndex &index);
	void inToCont(pki_base *pki);
		

    public slots:
	void load(void);
	void newItem(void);
	void revokeCert(const x509rev &revok, const pki_x509 *issuer);
	void store();
	void showItem();
};

#endif
