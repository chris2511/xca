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
#include <qpushbutton.h>
#include <qpopupmenu.h>
#include <qmessagebox.h>
#include <qlabel.h>

ImportMulti::ImportMulti(QWidget *parent, const char *name, bool modal, WFlags f )
	:ImportMulti_UI(parent, name, modal, f)
{
	setCaption(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::certImg);		 
	itemView->addColumn(tr("Internal name"));
	itemView->addColumn(tr("Common name"));
	itemView->addColumn(tr("Serial"));
	itemView->addColumn(tr("not After"));
			
}

void ImportMulti::addItem(pki_base *pki)
{
	if (!pki) return;
	QListViewItem *current = new QListViewItem(itemView);
	pki->setLvi(current);
	pki->updateView();
	cont.append(pki);
}

void ImportMulti::showPopupMenu(QListViewItem *item, const QPoint &pt, int x)
{
	QPopupMenu *menu = new QPopupMenu(this);

	menu->insertItem(tr("Import"), this, SLOT(import()));
	menu->insertItem(tr("Details"), this, SLOT(details()));
	menu->insertItem(tr("Remove"), this, SLOT(remove()));
	menu->exec(pt);
	delete menu;
}	

void ImportMulti::remove()
{
	pki_base *pki = getSelected();
	delete pki;
}

pki_base *ImportMulti::getSelected()
{
	QListViewItem *current = itemView->selectedItem();
	return search(current);
}

pki_base *ImportMulti::search(QListViewItem *current)
{
	for (pki_base *pki = cont.first(); pki != 0; pki = cont.next() ) {
		if (current == pki->getLvi()) return pki;
	}
	return NULL;
}

void ImportMulti::import()
{
	pki_base *pki = getSelected();
	if (pki->getClassName() == "pki_x509")
		emit importCert((pki_x509 *)pki);
	else if (pki->getClassName() == "pki_key")
		emit importKey((pki_key *)pki);
	else 
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized ") +
			pki->getClassName(), tr("OK"));
	delete pki;
}

void ImportMulti::details()
{
	pki_base *pki = getSelected();
	if (pki->getClassName() == "pki_x509")
		emit showCert((pki_x509 *)pki);
	else if (pki->getClassName() == "pki_key")
		emit showKey((pki_key *)pki);
	else 
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized ") +
			pki->getClassName(), tr("OK"));
	delete pki;
}

