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


#include "ReqView.h"
#include "widgets/ReqDetail.h"
#include "widgets/KeyDetail.h"
#include <openssl/evp.h>
#include <qpopupmenu.h>
#include <qmessagebox.h>
#include <qfiledialog.h>
#include <qdir.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qpushbutton.h>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"


ReqView::ReqView(QWidget * parent, const char * name, WFlags f)
	:XcaListView(parent, name, f)
{
	addColumn(tr("Internal name"));
	addColumn(tr("Common Name"));
}

void ReqView::newItem()
{
	newItem(NULL);
}

void ReqView::newItem(pki_temp *temp)
{
	CHECK_DB 
	pki_x509req *req;
	NewX509 *dlg = new NewX509(this,0,true);
	emit connNewX509(dlg);

	if (temp) {
		dlg->defineTemplate(temp);
	}
	dlg->setRequest();
	if (! dlg->exec()){
		delete dlg;
		return;
	}
	try {
		const EVP_MD *hashAlgo = dlg->getHashAlgo();
		pki_key *key = dlg->getSelectedKey();
		x509name xn = dlg->getX509name();
		req = new pki_x509req();
		
		req->setIntName(dlg->description->text());
		if (key->getType() == EVP_PKEY_DSA)
			hashAlgo = EVP_dss1();
		
		req->createReq(key, xn, hashAlgo);
		db->insert(req);
	}
	catch (errorEx &err) {
		delete req;
		Error(err);
	}
}



void ReqView::showItem(pki_base *item, bool import)
{
	if (!item) return;
	ReqDetail *dlg = NULL; 
    try {
		dlg = new ReqDetail(this,0,true);
		dlg->setReq((pki_x509req *)item);
		connect(dlg->privKey, SIGNAL(doubleClicked(QString)),
			this, SLOT(showKey(QString)));	
		dlg->exec();
    }
    catch (errorEx &err) {
	    Error(err);
    }
	if (dlg)
		delete dlg;
}

void ReqView::deleteItem()
{
	deleteItem_default(tr("The Certificate signing request"),
		tr("is going to be deleted"));
}

void ReqView::load()
{
	load_req l;
	load_default(l);
}

void ReqView::writeReq_pem() { store(true); }
void ReqView::writeReq_der() { store(false); }

void ReqView::store(bool pem)
{
	pki_x509req *req;
	try {
		req = (pki_x509req *)getSelected();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}

	if (!req) return;
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der *.csr )"); 
	filt.append("All Files ( *.* )");
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Export Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( req->getIntName() + ".csr" );
	dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		s = dlg->selectedFile();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	if (s.isEmpty()) return;
	s=QDir::convertSeparators(s);
	try {
		req->writeReq(s, pem);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void ReqView::signReq()
{
	pki_x509req *req;
	try {
		req = (pki_x509req *)getSelected();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}
	newCert(req);
}

void ReqView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	int itemExport;
	
	if (!item) {
		menu->insertItem(tr("New Request"), this, SLOT(newItem()));
		menu->insertItem(tr("Import"), this, SLOT(load()));
	}
	else {
		CHECK_DB
		pki_x509req *req = (pki_x509req *)db->getByName(item->text(0));
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Show Details"), this, SLOT(showItem()));
		menu->insertItem(tr("Sign"), this, SLOT(signReq()));
		itemExport = menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("PEM"), this, SLOT(writeReq_pem()));
		subExport->insertItem(tr("DER"), this, SLOT(writeReq_der()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
		menu->setItemEnabled(itemExport, ! req->isSpki());
	}
	menu->exec(pt);
	delete menu;
	delete subExport;
	return;
}

void ReqView::showKey(QString name)
{
	pki_key *key = (pki_key *)MainWindow::keys->getByName(name);
	showKey(key);
}

void ReqView::showKey(pki_key *key)
{
	KeyDetail *dlg = NULL;
	if (!key) return;
	try {   
		dlg = new KeyDetail(this, 0, true, 0 );
		dlg->setKey(key);
		dlg->exec();
	} 
	catch (errorEx &err) {
		Error(err);
	}
	if (dlg)
		delete dlg;
}
