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


#include "NewX509.h"

NewX509::NewX509(QWidget *parent , const char *name, db_key *key, db_x509req *req)
	:NewX509_UI(parent, name, true, 0)
{
	connect( this, SIGNAL(genKey()), parent, SLOT(newKey()) );
	connect( parent, SIGNAL(keyDone(QString)), this, SLOT(newKeyDone(QString)) );
	keys = key;
	reqs = req;
	QStringList strings = keys->getPrivateDesc();
	// are there any useable private keys  ?
	if (strings.isEmpty()) {
		newKey();
	}
	else {
		keyList->insertStringList(strings);
	}
	// any PKCS#10 requests to be used ?
	strings = reqs->getDesc();
	if (strings.isEmpty()) {
		fromReqRB->setDisabled(true);
	}
	else {
		reqList->insertStringList(strings);
	}
	fromDataRB->setChecked(true);
	setFinishEnabled(page4,true);
	setNextEnabled(page1,false);
}
	
void NewX509::dataChangeP1()
{
	if (description->text() != "" || fromReqRB->isChecked()) {
		setNextEnabled(page1,true);
	}
	else {
		setNextEnabled(page1,false);
	}
}

void NewX509::showPage(QWidget *page)
{
	
	if ( page == page1 ) {
		dataChangeP1();
	}
	else if ( page == page2 ) {
		if (!selfSignRB->isChecked() && !foreignSignRB->isChecked()) {
			if (fromDataRB->isChecked()) {
				selfSignRB->setChecked(true);
				serialNr->setText("00");
			}
			else {
				foreignSignRB->setChecked(true);
			}
		}
	}
	else if (page == page4) {
	}
	QWizard::showPage(page);

}
		    
void NewX509::setDisabled(int state)
{
   if (state == 2) {
	inputFrame->setDisabled(false);
	reqList->setDisabled(true);
   }
   else if (state == 0) {
	inputFrame->setDisabled(true);
	reqList->setDisabled(false);
   }
}

void NewX509::newKey()
{
	emit genKey();
}

void NewX509::newKeyDone(QString name)
{
	keyList->insertItem(name,0);
	keyList->setCurrentItem(0);
}
