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
#include "ui/KeyDetail.h"
#include "widgets/ExportKey.h"
#include "widgets/MainWindow.h"
#include <qcombobox.h>
#include <qlabel.h>
#include <qprogressdialog.h>
#include <qtextview.h>
#include <qmessagebox.h>
#include <qpopupmenu.h>
#include <qcheckbox.h>

const int KeyView::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };

KeyView::KeyView(QWidget * parent = 0, const char * name = 0, WFlags f = 0)
	:XcaListView(parent, name, f)
{
	addColumn(tr("Keysize"));
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
}

void KeyView::deleteItem()
{
	deleteItem_default(tr("The key"), tr("is going to be deleted")); 
}

void KeyView::showItem(pki_base *item, bool import)
{
	pki_key *key = (pki_key *)item;
	if (!key) return;
	KeyDetail_UI *detDlg = new KeyDetail_UI(this, 0, true, 0 );
	try {	
		detDlg->setCaption(tr(XCA_TITLE));
		detDlg->keyDesc->setText( key->getIntName() );
		detDlg->keyLength->setText( key->length() );
		detDlg->keyPubEx->setText( key->pubEx() );
		detDlg->keyModulus->setText( key->modulus());
		if (key->isPubKey()) {
			detDlg->keyPrivEx->setText(tr("not available") );
			detDlg->keyPrivEx->setDisabled(true);
		}
		detDlg->image->setPixmap(*MainWindow::keyImg);
		if (import) {
			detDlg->but_ok->setText(tr("Import"));
			detDlg->but_cancel->setText(tr("Discard"));
		}
	}
	catch (errorEx &err) {
		Error(err);
		delete detDlg;
		return;
	}
	QString odesc = key->getIntName();
	bool ret = detDlg->exec();
	QString ndesc = detDlg->keyDesc->text();
	delete detDlg;
	if (!ret && import) {
		delete key;
	}
	if (!ret) return;
	
	emit init_database();
	
	if (import) {
		key = (pki_key *)insert(key);
	}
	CERR(ndesc << " " << key->getIntName());
	if ( ndesc != odesc) {
		MARK
		try {
			db->renamePKI(key, ndesc);
			MARK
		}
		catch (errorEx &err) {
			Error(err);
		}
		return;
	}
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
		    CERR( "before deleting pki...");
		    db->deletePKI(oldkey);
		    lkey->setIntName(oldkey->getIntName());
		    delete(oldkey);
		}
	    }
	    CERR( "after findkey");
	    db->insertPKI(lkey);
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
	int dlgret = dlg->exec();
	MainWindow::setPath(dlg->dirPath);

	if (!dlgret) {
		delete dlg;
		return;
	}
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
		menu->insertItem(tr("Show Details"), this, SLOT(show()));
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

