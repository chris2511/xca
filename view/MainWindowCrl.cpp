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


#include "MainWindow.h"

	
void MainWindow::showDetailsCrl()
{
	pki_crl *crl = (pki_crl *)crls->getSelectedPKI();
        showDetailsCrl(crl);
}

void MainWindow::showDetailsCrl(QListViewItem *item)
{
	string crl = item->text(0).latin1();
        showDetailsCrl((pki_crl *)crls->getSelectedPKI(crl));
}


bool MainWindow::showDetailsCrl(pki_crl *crl, bool import)
{
	if (!crl) return false;
	if (opensslError(crl)) return false;
	char buf[20];
	bool ret;
	int numc, i;
	pki_x509 *iss, *rev;
	QListViewItem *current;
    try {
	CrlDetail_UI *dlg = new CrlDetail_UI(this,0,true);
	dlg->image->setPixmap(*revImg);
	dlg->descr->setText(crl->getDescription().c_str());
	dlg->setCaption(tr(XCA_TITLE));
	iss = certs->getBySubject(crl->getIssuerX509_NAME());	
	numc = crl->numRev();
	dlg->certList->clear();
	dlg->certList->addColumn(tr("Name"));
	dlg->certList->addColumn(tr("Serial"));
	dlg->certList->addColumn(tr("Revokation"));
	CERR("NUMBER:" << numc);
	for (i=0; i<numc; i++) {
		CERR("SERIAL: "<<  crl->getSerial(i));
		rev = certs->getByIssSerial(iss, crl->getSerial(i));
		if (rev != NULL) {
			CERR(rev->getDescription());
			current = new QListViewItem(dlg->certList, 
					rev->getDescription().c_str());
		}
		else {
			current = new QListViewItem(dlg->certList, "Unknown certificate" );
		}
		current->setText(1, QString::number(crl->getSerial(i)) );
		current->setText(2, pki_x509::asn1TimeToSortable(crl->getRevDate(i)).c_str());
	}
	dlg->v3Extensions->setText(crl->printV3ext().c_str());
	dlg->issuer->setText(iss->getDescription().c_str());
	if (crl->verify(iss->getKey()) == 0) {
		dlg->signCheck->setText(tr("Success"));
	}
	sprintf(buf, "%d", ASN1_INTEGER_get(crl->crl->crl->version)+1);
	/* yeah, this is really oo programming :-( */
	dlg->lUpdate->setText(pki_x509::asn1TimeToSortable(crl->crl->crl->lastUpdate).c_str());
	dlg->nUpdate->setText(pki_x509::asn1TimeToSortable(crl->crl->crl->nextUpdate).c_str());
	dlg->version->setText(buf);
	connect( dlg->certList, SIGNAL( doubleClicked(QListViewItem*) ), 
		this, SLOT( showDetailsCert(QListViewItem *) ));
	string odesc = crl->getDescription();
	ret = dlg->exec();
	string ndesc = dlg->descr->text().latin1();
	delete dlg;
	if (!ret && import) {
                delete crl;
        }
	if (!ret) return false;
	if (crls == NULL) {
                init_database();
        }
	if (import) {
                crl = insertCrl(crl);
        }
	
	if (ndesc != odesc) {
		crls->renamePKI(crl, ndesc);
	}
		
	
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return false;
}

void MainWindow::deleteCrl()
{
    try {
	pki_crl *crl = (pki_crl *)crls->getSelectedPKI();
	if (!crl) return;
	if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("Really want to delete the Revokation list") +":\n'" + 
			QString::fromLatin1(crl->getDescription().c_str()) + "'\n" ,
			tr("Delete"), tr("Cancel") )
	) return;
	crls->deletePKI(crl);
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void MainWindow::loadCrl()
{
	QStringList filt;
	filt.append(tr("Revokation lists ( *.pem *.crl )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
	setPath(dlg);
	MARK
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		newPath(dlg);
	}
	delete dlg;
	MARK	
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		MARK
		try {
			pki_crl *crl = new pki_crl(s.latin1());
			MARK
			insertCrl(crl);
			MARK
		}
		catch (errorEx &err) {
			Error(err);
		}
	}

		
}


pki_crl *MainWindow::insertCrl(pki_crl *crl)
{
    try {
	MARK
	pki_crl *oldcrl = (pki_crl *)crls->findPKI(crl);
	MARK
	if (oldcrl) {
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The revokation list already exists in the database as") +":\n'" +
		QString::fromLatin1(oldcrl->getDescription().c_str()) + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(crl);
	   return oldcrl;
	}
	CERR( "insertCrl: inserting" );
	crls->insertPKI(crl);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return crl;
}

void MainWindow::writeCrl_pem()
{
	writeCrl(true);
}	
void MainWindow::writeCrl_der()
{
	writeCrl(false);
}	
	
void MainWindow::writeCrl(bool pem)
	{
	pki_crl *crl;
	try {
                crl = (pki_crl *)crls->getSelectedPKI();
        }
	catch (errorEx &err) {
		Error(err);
		return;
	}
	
	if (!crl) return;
	QStringList filt;
	filt.append("Revokation Lists ( *.crl *.pem)");
	filt.append("All Files ( *.* )");
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Export Certificate revokation list"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( (crl->getDescription() + ".crl").c_str() );
	setPath(dlg);
	if (dlg->exec()) {
		s = dlg->selectedFile();
		newPath(dlg);
	}
	delete dlg;
	if (s.isEmpty()) return;
	s=QDir::convertSeparators(s);
	try {
		crl->writeCrl(s.latin1(), pem);
	}
	catch (errorEx &err) {
                Error(err);
        }
		
}


void MainWindow::showPopupCrl(QListViewItem *item, const QPoint &pt, int x) {
	CERR( "popup Crl");
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	
	if (!item) {
		menu->insertItem(tr("Import"), this, SLOT(loadCrl()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameCrl()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsCrl()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("PEM"), this, SLOT(writeCrl_pem()));
		subExport->insertItem(tr("DER"), this, SLOT(writeCrl_der()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteCrl()));
	}
	menu->exec(pt);
	delete menu;
	delete subExport;
	
	return;
}

void MainWindow::renameCrl(QListViewItem *item, int col, const QString &text)
{
	if (col != 0) return;
	try {
		pki_base *pki = crls->getSelectedPKI(item);
		string txt =  text.latin1();
		crls->renamePKI(pki, txt);
	}
	catch (errorEx &err) {
		Error(err);
	}
}
void MainWindow::genCrl() 
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	if (cert->getKey()->isPubKey()) return;
	pki_crl *crl = genCrl(cert);
	crls->insertPKI(crl);
}

pki_crl *MainWindow::genCrl(pki_x509 *cert)
{
	QList<pki_x509> list;
	pki_x509 *issuedcert = NULL;
	pki_crl *crl = NULL;
	try {	
		crl = new pki_crl(cert->getDescription(), cert);

		list = certs->getIssuedCerts(cert);
		if (!list.isEmpty()) {
	       		for ( issuedcert = list.first(); issuedcert != NULL; issuedcert = list.next() ) {
				if (issuedcert->isRevoked() ) {
					crl->addRevoked(issuedcert);
				}
			}
		}
		crl->addV3ext(NID_authority_key_identifier,"keyid,issuer");
		crl->addV3ext(NID_issuer_alt_name,"issuer:copy");
		crl->sign(cert->getKey());
		cert->setLastCrl(crl->getDate());
		certs->updatePKI(cert);
		CERR( "CRL done, completely");
	}
	catch (errorEx &err) {
		Error(err);
	}
	return crl;
}
			
void MainWindow::startRenameCrl()
{
	try {
#ifdef qt3
		pki_base *pki = crls->getSelectedPKI();
		if (!pki) return;
		QListViewItem *item = (QListViewItem *)pki->getPointer();
		item->startRename(0);
#else
		renamePKI(crls);
#endif
	}
	catch (errorEx &err) {
		Error(err);
	}
}
