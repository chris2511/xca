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


#include "NewX509_UI.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"

#ifndef NEWX509_H
#define NEWX509_H

class MainWindow;

class NewX509: public NewX509_UI
{
	Q_OBJECT
   private:
	db_x509req *reqs;
	db_x509 *certs;
	db_key *keys;
	db_temp *temps;
	pki_temp *fixtemp;
	QString startText, endText, tText;
	
   public:	
	NewX509(QWidget *parent, const char *name, db_key *key, db_x509req *req, db_x509 *cert, db_temp *temp, QPixmap *image, QPixmap *ns);
	~NewX509();
	void setRequest(); // reduce to request form 	
	void setTemp(pki_temp *temp); // reduce to template form 	
	void setCert(); // reduce to certificate form 	
	void setup();
	void showPage(QWidget *page);
	void toTemplate(pki_temp *temp);
	void fromTemplate(pki_temp *temp);
	void defineTemplate(pki_temp *temp);
	void defineRequest(pki_x509req *req);
	void defineCert(pki_x509 *defcert);
	int lb2int(QListBox *lb);
	void int2lb(QListBox *lb, int x);
	void templateChanged(pki_temp *templ);
	void templateChanged(QString templatename);
	pki_key *getSelectedKey();
	x509name getX509name();
	a1time getNotBefore();
	a1time getNotAfter();
   public slots:
	void toggleFromRequest();
   	void newKey();
	void dataChangeP2();
	void newKeyDone(QString name);
	void switchExtended();
	void templateChanged();
	void signerChanged();
	void helpClicked();
	
   signals:
	void genKey();  
};

#endif
