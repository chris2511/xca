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
#include "widgets/CrlDetail.h"
#include "lib/pki_crl.h"
#include "widgets/MainWindow.h"
#include "widgets/clicklabel.h"

CrlView::CrlView(QWidget * parent = 0, const char * name = 0, WFlags f = 0)
	:XcaListView(parent, name, f)
{
	addColumn(tr("Common Name"));
	addColumn(tr("Issuer C-Name"));
	addColumn(tr("Count"));
}


void CrlView::dlg_showCert(QListViewItem *i)
{
	emit showCert(i->text(0));
}					 

void CrlView::dlg_showCert(QString name)
{
	emit showCert(name);
}					 

void CrlView::showItem(pki_base *item, bool import)
{
	if (!item) return;
    try {
	CrlDetail *dlg = new CrlDetail(this,0,true);
	dlg->setCrl((pki_crl *)item);
	connect( dlg->certList, SIGNAL( doubleClicked(QListViewItem*) ), 
		this, SLOT( dlg_showCert(QListViewItem *) ));
	connect( dlg->issuerIntName, SIGNAL( doubleClicked(QString) ), 
		this, SLOT( dlg_showCert(QString) ));
	QString odesc = item->getIntName();
	bool ret = dlg->exec();
	QString ndesc = dlg->descr->text();
	delete dlg;
	if (!ret && import) {
                delete item;
        }
	if (!ret) return;
	if (MainWindow::crls == NULL) {
                emit init_database();
        }
	if (import) {
                item = insert(item);
        }
	
	if (ndesc != odesc) {
		MainWindow::crls->renamePKI(item, ndesc);
	}
		
	
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return;
}

void CrlView::deleteItem()
{
	deleteItem_default(tr("The Revokation list"),
		tr("is going to be deleted"));
}

pki_base *CrlView::loadItem(QString fname)
{
        pki_base *crl = new pki_crl(fname);
        return crl;
}
		
void CrlView::load()
{
	QStringList filter;
	filter.append(tr("Revokation lists ( *.pem *.crl )")); 
	filter.append(tr("All files ( *.* )"));
	load_default(filter, tr("Load CRL"));
}

pki_base *CrlView::insert(pki_base *item)
{
    pki_crl * crl = (pki_crl *)item;
    try {
	pki_crl *oldcrl = (pki_crl *)MainWindow::crls->getByReference(crl);
	if (oldcrl) {
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The revokation list already exists in the database as") +
		":\n'" + oldcrl->getIntName() + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(crl);
	   return oldcrl;
	}
	MainWindow::crls->insertPKI(crl);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return crl;
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
	try {
                crl = (pki_crl *)getSelected();
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

pki_crl *CrlView::newItem(pki_x509 *cert)
{
	if (!cert) return NULL;
	QList<pki_x509> list;
	pki_x509 *issuedcert = NULL;
	pki_crl *crl = NULL;
	x509v3ext e;
	X509V3_CTX ext_ctx;
	X509V3_set_ctx(&ext_ctx, cert->getCert() , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));
		   
	try {	
		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);

		list = MainWindow::certs->getIssuedCerts(cert);
		if (!list.isEmpty()) {
	       		for ( issuedcert = list.first(); issuedcert != NULL; issuedcert = list.next() ) {
				if (issuedcert->isRevoked() ) {
					crl->addRev(issuedcert->getRev());
				}
			}
		}
		crl->addV3ext(e.create(NID_authority_key_identifier, "keyid,issuer"));
		crl->addV3ext(e.create(NID_issuer_alt_name, "issuer:copy"));
		crl->sign(cert->getRefKey());
		cert->setLastCrl(crl->getLastUpdate());
		MainWindow::certs->updatePKI(cert);
	}
	catch (errorEx &err) {
		Error(err);
	}
	return crl;
}

