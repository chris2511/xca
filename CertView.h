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


#ifndef CERTVIEW_H
#define CERTVIEW_H

#include "XcaListView.h"
#include "lib/pki_x509.h"
#include "lib/pki_pkcs12.h"
#include <qlistview.h>
#include "NewX509.h"

class CertView : public XcaListView
{
   Q_OBJECT

   private:
	QPixmap *certicon[4];
	int viewState;
	bool mkDir(QString dir);
   public:
	CertView(QWidget * parent = 0, const char * name = 0, WFlags f = 0);
	void showItem(pki_base *item, bool import);
	void newItem();
	void deleteItem();
	void updateViewItem(pki_base *);
	void load();
	pki_base* loadItem(QString fname);
	pki_base* insert(pki_base *item);
	void store();
	void popupMenu(QListViewItem *item, const QPoint &pt, int x);
	void newCert();
	void newCert(NewX509 *dlg);
	void extendCert();
	void loadPKCS12();
	void insertP12(pki_pkcs12 *pk12);
	void loadPKCS7();
	void writePKCS12(QString s, bool chain);
	void writePKCS7(QString s, int type);	
   public slots:
	void signP7();
	void encryptP7();
	void setTrust();
	void toRequest();
	void revoke();
	void unRevoke();
	void setSerial();
	void setCrlDays();
	void setTemplate();
	void changeView();
	void toTinyCA();
	bool updateView();
	void updateViewAll();
   signals:
	void init_database();

};	

#endif
