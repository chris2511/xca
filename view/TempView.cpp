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


#include "TempView.h"
#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include <qmessagebox.h>
#include <qpopupmenu.h>

TempView::TempView(QWidget * parent, const char * name, WFlags f)
	        :XcaListView(parent, name, f)
{
	addColumn(tr("Internal name"));
	addColumn(tr("Type"));
}

void TempView::newEmptyTemp()
{
	newItem(pki_temp::EMPTY);
}

void TempView::newCaTemp()
{
	newItem(pki_temp::CA);
}

void TempView::newClientTemp()
{
	newItem(pki_temp::CLIENT);
}

void TempView::newServerTemp()
{
	newItem(pki_temp::SERVER);
}

void TempView::newItem(int type)
{
	pki_temp *temp = new pki_temp("--", type);
	if (alterTemp(temp)) {
		insert(temp);
	}
	else {
		delete temp;
	}
}

void TempView::alterTemp()
{
	alterTemp((pki_temp *)getSelected());
}

bool TempView::alterTemp(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(this, NULL, true);
	emit connNewX509(dlg);
	 
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

void TempView::showItem(pki_base *item, bool import)
{
	pki_temp *temp = (pki_temp *)item;
	if (!temp) return;
	QString oldname = temp->getIntName();
	alterTemp(temp);
	QString newname = temp->getIntName();
	if (newname!= oldname) {
		temp->setIntName(oldname);
		MainWindow::temps->renamePKI(temp, newname);
	}
	MainWindow::temps->updatePKI(temp);
}


void TempView::deleteItem()
{
	deleteItem_default(tr("The Template"), tr("is going to be deleted"));
}

void TempView::load()
{   
	QStringList filter;
	filter.append( "XCA templates ( *.xca )");
	load_default(filter, tr("Import key"));
}

pki_base *TempView::loadItem(QString fname)
{   
	pki_temp *temp = new pki_temp(fname);
	try {
		temp->loadTemp(fname);
	}
    catch (errorEx &err) {
        Error(err);
		delete temp;
        return NULL;
    }
	return temp;
}

void TempView::store()
{
    pki_temp *temp;
    try {
        temp = (pki_temp *)getSelected();
    }
    catch (errorEx &err) {
        Error(err);
        return;
    }

    if (!temp) return;
    QStringList filt; 
    filt.append("XCA Templates ( *.xca )");
    filt.append("All Files ( *.* )");
    QString s="";
    QFileDialog *dlg = new QFileDialog(this,0,true);
    dlg->setCaption(tr("Export Template"));
    dlg->setFilters(filt);
    dlg->setMode( QFileDialog::AnyFile );
    dlg->setSelection( temp->getIntName() + ".xca" );
    dlg->setDir(MainWindow::getPath());
    if (dlg->exec()) {
        s = dlg->selectedFile();
        MainWindow::setPath(dlg->dirPath());
    }
    delete dlg;
    if (s.isEmpty()) return;
    s=QDir::convertSeparators(s);
    try {
        temp->writeTemp(s);
    }
    catch (errorEx &err) {
        Error(err);
    }
}

pki_base *TempView::insert(pki_base *temp)
{
	if(! temp) return NULL;
	MainWindow::temps->insertPKI(temp);
	updateView();
	return temp;
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
		subMenu->insertItem(tr("Empty"), this, SLOT(newEmptyTemp()));
		subMenu->insertItem(tr("CA"), this, SLOT(newCaTemp()));
		subMenu->insertItem(tr("Client"), this, SLOT(newClientTemp()));
		subMenu->insertItem(tr("Server"), this, SLOT(newServerTemp()));
		menu->insertItem(tr("Import"), this, SLOT(load()));
		
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Export"), this, SLOT(store()));
		menu->insertItem(tr("Change"), this, SLOT(alterTemp()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
		menu->insertItem(tr("Create certificate"), this, SLOT(certFromTemp()));
		menu->insertItem(tr("Create request"), this, SLOT(reqFromTemp()));
	}
	menu->exec(pt);
	delete menu;
	delete subMenu;
	return;
}
