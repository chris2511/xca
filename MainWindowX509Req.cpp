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


#include "MainWindow.h"


void MainWindow::newReq(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(this, 0, keys, NULL, NULL, temps, csrImg, nsImg);
	if (temp) {
		dlg->defineTemplate(temp);
	}
	dlg->setRequest();
	//dlg->image->setPixmap(*csrImg);
	if (! dlg->exec()) return;
	pki_key *key = (pki_key *)keys->getSelectedPKI(dlg->keyList->currentText().latin1());
	string cn = dlg->commonName->text().latin1();
	string c = dlg->countryName->text().latin1();
	string l = dlg->localityName->text().latin1();
	string st = dlg->stateOrProvinceName->text().latin1();
	string o = dlg->organisationName->text().latin1();
	string ou = dlg->organisationalUnitName->text().latin1();
	string email = dlg->emailAddress->text().latin1();
	string desc = dlg->description->text().latin1();
	pki_x509req *req = new pki_x509req(key, cn,c,l,st,o,ou,email,desc, "");
	insertReq(req);
}


void MainWindow::showDetailsReq()
{
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	showDetailsReq(req);
}
void MainWindow::showDetailsReq(QListViewItem *item)
{
	string req = item->text(0).latin1();
	showDetailsReq((pki_x509req *)reqs->getSelectedPKI(req));
}


void MainWindow::showDetailsReq(pki_x509req *req)
{
	if (!req) return;
	if (opensslError(req)) return;
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	dlg->descr->setText(req->getDescription().c_str());
	if ( req->verify() ) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	pki_key *key =req->getKey();
	if (key)
	    if(key->isPrivKey()) {
		dlg->privKey->setText(key->getDescription().c_str());
		dlg->privKey->setDisabled(false);
	}
	string land = req->getDN( NID_countryName) + " / " 
		+ req->getDN(NID_stateOrProvinceName);
	dlg->dnCN->setText(req->getDN(NID_commonName).c_str() );
	dlg->dnC->setText(land.c_str());
	dlg->dnL->setText(req->getDN(NID_localityName).c_str());
	dlg->dnO->setText(req->getDN(NID_organizationName).c_str());
	dlg->dnOU->setText(req->getDN(NID_organizationalUnitName).c_str());
	dlg->dnEmail->setText(req->getDN(NID_pkcs9_emailAddress).c_str());
	dlg->image->setPixmap(*csrImg);
	if ( !dlg->exec()) return;
	string ndesc = dlg->descr->text().latin1();
	if (ndesc != req->getDescription()) {
		reqs->renamePKI(req, ndesc);
	}
}

void MainWindow::deleteReq()
{
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (!req) return;
	if (opensslError(req)) return;
	if (QMessageBox::information(this,tr("Delete Certificate signing request"),
			tr("Really want to delete the Certificate signing request") +":\n'" + 
			QString::fromLatin1(req->getDescription().c_str()) +
			"'\n", "Delete", "Cancel")
	) return;
	reqs->deletePKI(req);
}

void MainWindow::loadReq()
{
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der )"); 
	filt.append("All Files ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = new pki_x509req(s);
	if (opensslError(req)) return;
	insertReq(req);
}

void MainWindow::writeReq()
{
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der )"); 
	filt.append("All Files ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Export Certificate signing request");
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (opensslError(req)) return;
	req->writeReq(s,true);
	if (opensslError(req)) return;
}

void MainWindow::insertReq(pki_x509req *req)
{
	if (opensslError(req)) return;
	pki_x509 *oldreq = (pki_x509 *)reqs->findPKI(req);
	if (oldreq) {
	   QMessageBox::information(this,tr("Certificate signing request"),
		tr("The certificate signing request already exists in the database as") +":\n'" +
		QString::fromLatin1(oldreq->getDescription().c_str()) + 
		"'\n" + tr("and thus was not stored"), "OK");
	   delete(req);
	   return;
	}
	reqs->findKey(req);
	reqs->insertPKI(req);
}


void MainWindow::showPopupReq(QListViewItem *item, const QPoint &pt, int x) {
	CERR << "hallo popup Req" << endl;
	QPopupMenu *menu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Request"), this, SLOT(newReq()));
		menu->insertItem(tr("Import"), this, SLOT(loadReq()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameReq()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsReq()));
		menu->insertItem(tr("Export"), this, SLOT(writeReq()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteReq()));
	}
	menu->exec(pt);
	return;
}

void MainWindow::renameReq(QListViewItem *item, int col, const QString &text)
{
	pki_base *pki = reqs->getSelectedPKI(item);
	string txt =  text.latin1();
	reqs->renamePKI(pki, txt);
}


void MainWindow::startRenameReq()
{
#ifdef qt3
	pki_base *pki = reqs->getSelectedPKI();
	if (!pki) return;
	QListViewItem *item = (QListViewItem *)pki->getPointer();
	item->startRename(0);
#else
	renamePKI(reqs);
#endif
}
