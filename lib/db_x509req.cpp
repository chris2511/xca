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


#include "db_x509req.h"
#include "pki_x509req.h"
#include "widgets/ReqDetail.h"
#include <Qt/qmessagebox.h>
#include <Qt/qevent.h>
#include <Qt/qaction.h>


db_x509req::db_x509req(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{
	delete rootItem;
	rootItem = newPKI();
	headertext << "Name" << "Subject" << "Serial" ;
	delete_txt = tr("Delete the request(s)");
	loadContainer();
}

pki_base *db_x509req::newPKI()
{
	return new pki_x509req();
}

pki_base *db_x509req::insert(pki_base *item)
{
	pki_x509req *oldreq, *req;
	req = (pki_x509req *)item;
	oldreq = (pki_x509req *)getByReference(req);
	if (oldreq) {
		QMessageBox::information(NULL,tr(XCA_TITLE),
		tr("The certificate signing request already exists in the database as") +":\n'" +
		oldreq->getIntName() +
		"'\n" + tr("and thus was not stored"), "OK");
		delete(req);
		return oldreq;
	}
	insertPKI(req);
	return req;
}

void db_x509req::newItem()
{
	pki_x509req *req;
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);

//	if (temp) {
//		dlg->defineTemplate(temp);
//	}
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

		dlg->initCtx(NULL, NULL, req);
		req->createReq(key, xn, hashAlgo, dlg->getAllExt());
		insert(req);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		delete req;
	}
}

void db_x509req::load(void)
{
	load_req l;
	load_default(l);
}

void db_x509req::showItem(pki_x509req *req)
{
	if (!req)
		return;

	ReqDetail *dlg;
	dlg = new ReqDetail(mainwin);
	if (dlg) {
		dlg->setReq(req);
		dlg->exec();
		delete dlg;
	}
}

void db_x509req::showItem()
{
	if (!currentIdx.isValid())
		return;

	pki_x509req *req = static_cast<pki_x509req*>(currentIdx.internalPointer());
	showItem(req);
}

void db_x509req::showItem(QString descr)
{
	pki_x509req *req = (pki_x509req*)getByName(descr);
	showItem(req);
}

void db_x509req::store(bool pem)
{
	if (!currentIdx.isValid())
		return;

	pki_x509req *req = static_cast<pki_x509req*>(currentIdx.internalPointer());

	req->writeReq(req->getIntName(), pem);
}

void db_x509req::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport;
	currentIdx = index;

	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());

	menu->addAction(tr("New Request"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		menu->addAction(tr("Sign"), this, SLOT(signReq()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("PEM"), this, SLOT(store_pem()));
		subExport->addAction(tr("DER"), this, SLOT(store_der()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
		subExport->setEnabled(! req->isSpki());
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}
