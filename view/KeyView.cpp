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

#include "KeyView.h"
#include "ui/NewKey.h"
#include "widgets/KeyDetail.h"
#include "widgets/ExportKey.h"
#include "widgets/MainWindow.h"
#include "widgets/clicklabel.h"
#include <qcombobox.h>
#include <qlabel.h>
#include <qprogressdialog.h>
#include <qpushbutton.h>
#include <qlineedit.h>
#include <qtextview.h>
#include <qmessagebox.h>
#include <qpopupmenu.h>
#include <qcheckbox.h>

const int KeyView::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };

KeyView::KeyView(QWidget * parent, const char * name, WFlags f)
	:XcaListView(parent, name, f)
{
	addColumn(tr("Common Name"));
	addColumn(tr("Keylength"));
	addColumn(tr("Use count"));
}

void KeyView::newItem()
{
	NewKey_UI *dlg = new NewKey_UI(this,0,true,0);
	QString x;
	for (int i=0; sizeList[i] != 0; i++ ) 
	   dlg->keyLength->insertItem( x.number(sizeList[i]) +" bit");	
	dlg->keyLength->setCurrentItem(2);
	dlg->image->setPixmap(*MainWindow::keyImg);
	if (dlg->exec()) {
	  try {
	   int sel = dlg->keyLength->currentItem();
	   QProgressDialog *progress = new QProgressDialog(
		tr("Please wait, Key generation is in progress"),
		tr("Cancel"),90, 0, 0, true);
	   progress->setMinimumDuration(0);
	   progress->setProgress(0);	
	   progress->setCaption(tr(XCA_TITLE));
	   pki_key *nkey = new pki_key (dlg->keyDesc->text(), 
		       &incProgress,
		       progress,
		       sizeList[sel]);
           progress->cancel();
	   delete progress;
	   insert(nkey);
	   x = nkey->getIntName();
	   emit keyDone(x);
	  }
	  catch (errorEx &err) {
		  Error(err);
	  }
	}
	delete dlg;
	updateView();
}

void KeyView::deleteItem()
{
	deleteItem_default(tr("The key"), tr("is going to be deleted")); 
}

void KeyView::showItem(pki_base *item, bool import)
{
	pki_key *key = (pki_key *)item;
	KeyDetail *detDlg;
	if (!key) return;
	try {	
		detDlg = new KeyDetail(this, 0, true, 0 );
		detDlg->setKey(key);
	}
	catch (errorEx &err) {
		Error(err);
	}
	if (detDlg)
		delete detDlg;
}

void KeyView::load()
{
	QStringList filter;
	filter.append( "PKI Keys ( *.pem *.der *.key )"); 
	filter.append( "PKCS#8 Keys ( *.p8 *.pk8 )"); 
	load_default(filter, tr("Import key"));
}

pki_base *KeyView::loadItem(QString fname)
{
	pki_base *lkey = new pki_key(fname, &MainWindow::passRead);
	return lkey;
}

pki_base* KeyView::insert(pki_base *item)
{
	pki_key *lkey = (pki_key *)item;
	pki_key *oldkey;
	emit init_database();
	try {
	    oldkey = (pki_key *)db->getByReference(lkey);
	    if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) ||
		    lkey->isPubKey()){
	   	    QMessageBox::information(this,tr(XCA_TITLE),
			tr("The key is already in the database as") +":\n'" +
			oldkey->getIntName() + 
			"'\n" + tr("and is not going to be imported"), "OK");
		    delete(lkey);
		    return oldkey;
		}
		else {
	   	    QMessageBox::information(this,tr(XCA_TITLE),
			tr("The database already contains the public part of the imported key as") +":\n'" +
			oldkey->getIntName() + 
			"'\n" + tr("and will be completed by the new, private part of the key"), "OK");
		    db->deletePKI(oldkey);
		    lkey->setIntName(oldkey->getIntName());
		    delete(oldkey);
		}
	    }
	    db->insertPKI(lkey);
		updateView();
	}
	catch (errorEx &err) {
		Error(err);
	}
	return lkey;
}


void KeyView::store()
{
	bool PEM = false;
	const EVP_CIPHER *enc = NULL;
	pki_key *targetKey = NULL;
	targetKey = (pki_key *)getSelected();
	if (!targetKey) return;
	ExportKey *dlg = new ExportKey((targetKey->getIntName() + ".pem"),
			targetKey->isPubKey(), MainWindow::getPath(), this);
	dlg->image->setPixmap(*MainWindow::keyImg);
	
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	MainWindow::setPath(dlg->dirPath);
	QString fname = dlg->filename->text();
	if (fname.isEmpty()) {
		delete dlg;
		return;
	}
	try {
		if (dlg->exportFormat->currentText() == "PEM") PEM = true;
		if (dlg->exportFormat->currentText() == "PKCS#8")
			targetKey->writePKCS8(fname, &MainWindow::passWrite);
		else if (dlg->exportPrivate->isChecked()) {
			if (dlg->encryptKey->isChecked())
				enc = EVP_des_ede3_cbc();
			targetKey->writeKey(fname, enc, &MainWindow::passWrite, PEM);
		}
		else {
			targetKey->writePublic(fname, PEM);
		}
	}
	catch (errorEx &err) {
		Error(err);
	}
	delete dlg;

}


void KeyView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	CERR( " popup key" );
	QPopupMenu *menu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Key"), this, SLOT(newItem()));
		menu->insertItem(tr("Import"), this, SLOT(load()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Show Details"), this, SLOT(showItem()));
		menu->insertItem(tr("Export"), this, SLOT(store()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
	}
	menu->exec(pt);
	delete menu;
	return;
}

void KeyView::incProgress(int a, int b, void *progress)
{
	int i = ((QProgressDialog *)progress)->progress();
	((QProgressDialog *)progress)->setProgress(++i);
}

void KeyView::importKey(pki_key *k)
{
	showItem(k, true);
}

void KeyView::showKey(pki_key *k)
{
	insert(k);
}
