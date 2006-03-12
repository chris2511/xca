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


#include "ImportMulti.h"
#include "MainWindow.h"
#include "lib/pki_base.h"
//#include "lib/pki_pkcs7.h"
//#include "lib/pki_pkcs12.h"
//#include "lib/pki_crl.h"
//#include "widgets/CrlDetail.h"
//#include "widgets/CertDetail.h"
#include "widgets/KeyDetail.h"
//#include "widgets/ReqDetail.h"
#include <Qt/qpushbutton.h>
#include <Qt/qmessagebox.h>
#include <Qt/qlabel.h>

ImportMulti::ImportMulti(QWidget *parent)
	:QDialog(parent)
{
	setWindowTitle(tr(XCA_TITLE));
	//image->setPixmap(*MainWindow::certImg);		 
	//itemView->addColumn(tr("Internal name"));
	//itemView->addColumn(tr("Common name"));
	//itemView->addColumn(tr("Serial"));
	cont.clear();
	cont.setAutoDelete(false);
	connect( itemView, SIGNAL(doubleClicked()),
		this, SLOT(details())) ;
	  
}

void ImportMulti::addItem(pki_base *pki)
{
	if (!pki) return;
	QString cn = pki->getClassName();
	if (cn == "pki_x509" || cn == "pki_key" || cn == "pki_x509req" ||
			cn == "pki_crl"  || cn == "pki_temp" ) {
		//Q3ListViewItem *current = new Q3ListViewItem(itemView);
		cont.append(pki);
	}
#if 0
	else if (cn == "pki_pkcs7") {
		pki_pkcs7 *p7 = ( pki_pkcs7 *)pki;
		for (int i=0; i<p7->numCert(); i++) {
			addItem(p7->getCert(i));
		}
		delete p7;
	}
	else if (cn == "pki_pkcs12") {
		pki_pkcs12 *p12 = ( pki_pkcs12 *)pki;
		addItem(p12->getKey());
		addItem(p12->getCert());
		for (int i=0; i<p12->numCa(); i++) {
			addItem(p12->getCa(i));
		}
		delete p12;
	}
	else  {
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized: ") + cn, tr("OK"));
	}
#endif
	
}
	
#if 0
void ImportMulti::showPopupMenu(Q3ListViewItem *item, const QPoint &pt, int x)
{
	Q3PopupMenu *menu = new Q3PopupMenu(this);

	menu->insertItem(tr("Import"), this, SLOT(import()));
	menu->insertItem(tr("Details"), this, SLOT(details()));
	menu->insertItem(tr("Remove"), this, SLOT(remove()));
	menu->exec(pt);
	delete menu;
}	

void ImportMulti::remove()
{
	pki_base *pki = getSelected();
	if (!pki) return;
	if (pki->getLvi())
		delete pki->getLvi();
	pki->delLvi();
	delete pki;
	cont.remove(pki);
}

pki_base *ImportMulti::getSelected()
{
	Q3ListViewItem *current = itemView->selectedItem();
	return search(current);
}
#endif
#if 0
pki_base *ImportMulti::search(Q3ListViewItem *current)
{
	for (pki_base *pki = cont.first(); pki != 0; pki = cont.next() ) {
		if (current == pki->getLvi()) return pki;
	}
	return NULL;
}

void ImportMulti::importAll()
{
	for (pki_base *pki = cont.first(); pki != 0; pki = cont.first() ) {
		import(pki);
	}
	accept();
}

void ImportMulti::import()
{
	pki_base *pki = getSelected();
	import(pki);
}

void ImportMulti::import(pki_base *pki)
{
	if (!pki) return;
	Q3ListViewItem *lvi = pki->getLvi();
	pki->delLvi();
	QString cn = pki->getClassName();
	emit init_database();

	if (cn == "pki_x509") {
		MainWindow::certs->insert(pki);
	}
	else if (cn == "pki_key") {
		MainWindow::keys->insert(pki);
	}
	else if (cn == "pki_x509req") {
		MainWindow::reqs->insert(pki);
	}
	else if (cn == "pki_crl") {
		MainWindow::crls->insert(pki);
	}
	else if (cn == "pki_temp") {
		MainWindow::temps->insert(pki);
	}
	else  {
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized: ") + cn, tr("OK"));
		delete pki;
	}
	if (lvi)
		delete lvi;
	cont.remove(pki);
}

void ImportMulti::details()
{
	pki_base *pki = getSelected();
	if (!pki) return;
	QString cn = pki->getClassName();
	try {
		if (cn == "pki_x509"){
			CertDetail *dlg;
			dlg = new CertDetail(this,0,true);
			dlg->setCert((pki_x509 *)pki);
			dlg->exec();
			delete dlg;
		}						  
		else if (cn == "pki_key") {
			KeyDetail *dlg;
			dlg = new KeyDetail(this,0,true);
			dlg->setKey((pki_key *)pki);
			dlg->exec();
			delete dlg;
		}						  
		else if (cn == "pki_x509req") {
			ReqDetail *dlg;
			dlg = new ReqDetail(this,0,true);
			dlg->setReq((pki_x509req *)pki);
			dlg->exec();
			delete dlg;
		}						  
		else if (cn == "pki_crl") {
			CrlDetail *dlg;
			dlg = new CrlDetail(this,0,true);
			dlg->setCrl((pki_crl *)pki);
			dlg->exec();
			delete dlg;
		}
		else if (cn == "pki_temp") {
			QMessageBox::warning(this, XCA_TITLE,
				tr("Details of this item cannot be shown: ") + cn, tr("OK"));
		}
			
		else 
			QMessageBox::warning(this, XCA_TITLE,
				tr("The type of the Item is not recognized ") + cn, tr("OK"));
	}
	catch (errorEx &err) {
		QMessageBox::warning(this, XCA_TITLE,
			tr("Error") + pki->getClassName() +
			err.getString(), tr("OK"));
	}
 
}

ImportMulti::~ImportMulti()
{
	cont.setAutoDelete(true);
	cont.clear();
}	 

#endif
void ImportMulti::execute(int force)
{
	/* if there is nothing to import don't pop up */
	if (cont.count() == 0) return;
	/* if there is only 1 item and force is 0 import it silently */
	if (cont.count() == 1 && force == 0) {
//		import(cont.first());
		return;
	}
	/* the behavoiour for more than one item */
	exec();
}
