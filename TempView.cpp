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


#include "TempView.h"
#include "TempView.h"

KeyView::KeyView(QWidget * parent = 0, const char * name = 0, WFlags f = 0)
	        :XcaListView(parent, name, f)
{
	keyicon = loadImg("template.png");
	addColumn(tr("Type"));
}

void TempView::newItem(int type)
{
	pki_temp *temp = new pki_temp("--", type);
	if (alterTemp(temp)) {
		insert(temp);
	}
}

bool TempView::alterTemp(pki_temp *temp)
{
	NewX509 *dlg = MainWindow::newX509(TempView::tempCert);
	dlg->setTemp(temp);
	dlg->fromTemplate(temp);
	if (!dlg->exec()) {
		delete dlg;
		return false;
	}
	dlg->toTemplate(temp);
	delete dlg;
	return true;
}

void TempView::show(pki_base *item, bool import)
{
	pki_temp *temp = (pki_temp *)item;
	if (!temp) return;
	QString oldname = temp->getIntName();
	alterTemp(temp);
	QString newname = temp->getIntName();
	if (newname!= oldname) {
		temp->setIntName(oldname);
		temps->renamePKI(temp, newname);
	}
	temps->updatePKI(temp);
}


void TempView::deleteItem()
{
	pki_temp *delTemp = (pki_temp *)getSelected();
	if (!delTemp) return;
	if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("The template") + ": '" + 
			QString::fromLatin1(delTemp->getDescription().c_str()) +
			"'\n" + tr("is going to be deleted"),
			"Delete", "Cancel")
	) return;
	temps->deletePKI(delTemp);
}



void TempView::insert(pki_temp *temp)
{
	temps->insertPKI(temp);
}

void TempView::certFromTemp()
{
	pki_temp *temp = (pki_temp *)getSelected();
	newCert(temp);
}

void TempView::reqFromTemp()
{
	pki_temp *temp = (pki_temp *)getSelected();
	newReq(temp);
}

void TempView::popupMenu(QListViewItem *item, const QPoint &pt, int x)
{
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subMenu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Template"),  subMenu);
		subMenu->insertItem(tr("Empty"), this, SLOT(newEmpTemp()));
		subMenu->insertItem(tr("CA"), this, SLOT(newCATemp()));
		subMenu->insertItem(tr("Client"), this, SLOT(newCliTemp()));
		subMenu->insertItem(tr("Server"), this, SLOT(newSerTemp()));
		
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameTemp()));
		menu->insertItem(tr("Change"), this, SLOT(alterTemp()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteTemp()));
		menu->insertItem(tr("Create certificate"), this, SLOT(certFromTemp()));
		menu->insertItem(tr("Create request"), this, SLOT(reqFromTemp()));
	}
	menu->exec(pt);
	delete menu;
	delete subMenu;
	return;
}

void TempView::updateViewPKI(pki_base *pki)
{
        db_base::updateViewPKI(pki);
        if (! pki) return;
        QListViewItem *current = (QListViewItem *)pki->getPointer();
        if (!current) return; 
        current->setPixmap(0, *keyicon);
        QString typec[]={tr("Empty"), tr("CA"), tr("Client"), tr("Server")};
        current->setText(1, typec[((pki_temp *)pki)->type]);
 
}
