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


#include "CrlView.h"
#include <qpopupmenu.h>
#include <qmessagebox.h>
#include <qlineedit.h>
#include "widgets/CrlDetail.h"
#include "widgets/KeyDetail.h"
#include "widgets/CertDetail.h"
#include "lib/pki_crl.h"
#include "widgets/MainWindow.h"
#include "widgets/clicklabel.h"

CrlView::CrlView(QWidget * parent, const char * name, WFlags f)
	:XcaListView(parent, name, f)
{
	addColumn(tr("Internal Name"));
	addColumn(tr("Issuer Common Name"));
	addColumn(tr("Revoked"));
}


void CrlView::showCert(QListViewItem *i)
{
	showCert(i->text(0));
}					 

void CrlView::showCert(QString name)
{
	pki_base *item = MainWindow::certs->getByName(name);
	if (!item) return; 
	CertDetail *dlg=NULL;
	CHECK_DB
    try {
		dlg = new CertDetail(this,0,true);
		dlg->setCert((pki_x509 *)item);
		connect( dlg->privKey, SIGNAL( doubleClicked(QString) ), 
			this, SLOT( showKey(QString) ));
		connect( dlg->signCert, SIGNAL( doubleClicked(QString) ), 
			this, SLOT( showCert(QString) ));

		dlg->exec();
    }
    catch (errorEx &err) {
	    Error(err);
    }
	if (dlg)
		delete dlg;
    return ;
}

void CrlView::showKey(QString name)
{
	pki_key *key = (pki_key *)MainWindow::keys->getByName(name);
	KeyDetail *dlg = NULL;
	if (!key) return;
	CHECK_DB
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

void CrlView::showItem(pki_base *item, bool import)
{
	if (!item) return;
    CrlDetail *dlg;
	CHECK_DB
	try {
		dlg = new CrlDetail(this,0,true);
		dlg->setCrl((pki_crl *)item);
		connect( dlg->certList, SIGNAL( doubleClicked(QListViewItem*) ), 
			this, SLOT( showCert(QListViewItem *) ));
		connect( dlg->issuerIntName, SIGNAL( doubleClicked(QString) ), 
			this, SLOT( showCert(QString) ));
		
		dlg->exec();
    }
    catch (errorEx &err) {
	    Error(err);
    }
	if (dlg)
		delete dlg;
		
    return;
}

void CrlView::deleteItem()
{
	deleteItem_default(tr("The Revocation list"),
		tr("is going to be deleted"));
}

void CrlView::load()
{
	load_crl l;
	load_default(l);
}

void CrlView::writeCrl_pem()
{
	store(true);
}	
void CrlView::writeCrl_der()
{
	store(false);
}	
	
void CrlView::store(bool pem)
{
	pki_crl *crl;
	CHECK_DB

	try {
		crl = (pki_crl *)getSelected();
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}
	
	if (!crl) return;
	QStringList filt;
	filt.append("Revocation Lists ( *.crl *.pem)");
	filt.append("All Files ( *.* )");
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Export Certificate revokation list"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( (crl->getIntName() + ".crl") );
	dlg->setDir(MainWindow::getPath());

	if (dlg->exec()) {
		s = dlg->selectedFile();
		MainWindow::setPath(dlg->dirPath());
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


void CrlView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	
	if (!item) {
		menu->insertItem(tr("Import"), this, SLOT(load()));
	}
	else {
		CHECK_DB
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Show Details"), this, SLOT(showItem()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("PEM"), this, SLOT(writeCrl_pem()));
		subExport->insertItem(tr("DER"), this, SLOT(writeCrl_der()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
	}
	menu->exec(pt);
	delete menu;
	delete subExport;
	
	return;
}

pki_crl *CrlView::newItem(pki_x509 *cert)
{
	if (!cert) return NULL;
	QList<pki_x509> list;
	a1time time;
	pki_x509 *issuedcert = NULL;
	pki_crl *crl = NULL;
	CHECK_DB_NULL
	x509v3ext e;
	X509V3_CTX ext_ctx;
	X509V3_set_ctx(&ext_ctx, cert->getCert() , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));
		   
	try {	
		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);

		list = MainWindow::certs->getIssuedCerts(cert);
		if (!list.isEmpty()) {
	    	for ( issuedcert = list.first(); 
					issuedcert != NULL; issuedcert = list.next() )
			{
				if (issuedcert->isRevoked() ) {
					crl->addRev(issuedcert->getRev());
				}
			}
		}
		crl->addV3ext(e.create(NID_authority_key_identifier,
			"keyid,issuer", &ext_ctx));
		if (cert->hasSubAltName()) {
			crl->addV3ext(e.create(NID_issuer_alt_name,
				"issuer:copy", &ext_ctx));
		}
		crl->setLastUpdate(time.now());
		crl->setNextUpdate(time.now(60*60*24*cert->getCrlDays()));
		cert->setLastCrl(time);
		crl->sign(cert->getRefKey(), EVP_md5());
		MainWindow::certs->updatePKI(cert); 
		// FIXME: set Last update
		db->insert(crl); 
		updateView();
	}
	catch (errorEx &err) {
		Error(err);
	}
	return crl;
}

