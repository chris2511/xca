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


void MainWindow::newTemp(int type)
{
	pki_temp *temp = new pki_temp("--", type);
	if (alterTemp(temp)) {
		temps->insertPKI(temp);
	}
}

bool MainWindow::alterTemp(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(this, NULL, NULL, NULL, NULL, NULL, tempImg, nsImg );
	MARK
	dlg->setTemp(temp);
	MARK
	dlg->fromTemplate(temp);
	MARK
	if (!dlg->exec()) {
		delete dlg;
		return false;
	}
	dlg->toTemplate(temp);
	delete dlg;
	return true;
}

void MainWindow::alterTemp()
{
	MARK
	pki_temp *temp = (pki_temp *)temps->getSelectedPKI();
	if (!temp) return;
	MARK
	string oldname = temp->getDescription();
	alterTemp(temp);
	string newname = temp->getDescription();
	if (newname!= oldname) {
		temp->setDescription(oldname);
		temps->renamePKI(temp, newname);
	}
	temps->updatePKI(temp);
}


void MainWindow::deleteTemp()
{
	pki_temp *delTemp = (pki_temp *)temps->getSelectedPKI();
	if (!delTemp) return;
	if (QMessageBox::information(this,"Delete template",
			tr("The template") + ": '" + 
			QString::fromLatin1(delTemp->getDescription().c_str()) +
			"'\n" + tr("is going to be deleted"),
			"Delete", "Cancel")
	) return;
	temps->deletePKI(delTemp);
}



void MainWindow::insertTemp(pki_temp *temp)
{
	if (!temps->insertPKI(temp))
	   QMessageBox::warning(this, "Template storage",
		tr("The template could not be stored into the database"), "OK");
	
}

void MainWindow::certFromTemp()
{
	pki_temp *temp = (pki_temp *)temps->getSelectedPKI();
	newCert(temp);
}

void MainWindow::reqFromTemp()
{
	pki_temp *temp = (pki_temp *)temps->getSelectedPKI();
	newReq(temp);
}

void MainWindow::showPopupTemp(QListViewItem *item, const QPoint &pt, int x) {
	CERR( " popup template" );
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

void MainWindow::renameTemp(QListViewItem *item, int col, const QString &text)
{
	pki_base *pki = temps->getSelectedPKI(item);
	string txt =  text.latin1();
	temps->renamePKI(pki, txt);
}

void MainWindow::startRenameTemp()
{
#ifdef qt3
	
	CERR("rename" );
	pki_base *pki = temps->getSelectedPKI();
	CERR("rename" );
	if (!pki) return;
	QListViewItem *item = (QListViewItem *)pki->getPointer();
	item->startRename(0);
#else
	CERR ( "rename qt2" );
	renamePKI(temps);
#endif
}
