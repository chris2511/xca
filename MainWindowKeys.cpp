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

const int MainWindow::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };


pki_key *MainWindow::getSelectedKey()
{
	CERR( "get Selected Key");
	pki_key *targetKey = (pki_key *)keys->getSelectedPKI();
	CERR( "got selected: "<< (int)targetKey );
	if (targetKey) {
	   string errtxt = targetKey->getError();
	   if (errtxt != "")
		QMessageBox::warning(this,tr(XCA_TITLE),
			tr("The Key: ") + QString::fromLatin1(targetKey->getDescription().c_str()) +
			tr(" is not consistent:") + QString::fromLatin1(errtxt.c_str()) );
	}
	CERR( "targetKey = " << (int)targetKey );
	return targetKey;
}


void MainWindow::newKey()
{
	NewKey_UI *dlg = new NewKey_UI(this,0,true,0);
	QString x;
	for (int i=0; sizeList[i] != 0; i++ ) 
	   dlg->keyLength->insertItem( x.number(sizeList[i]) +" bit");	
	dlg->keyLength->setCurrentItem(2);
	dlg->image->setPixmap(*keyImg);
	if (dlg->exec()) {
	  try {
	   int sel = dlg->keyLength->currentItem();
	   QProgressDialog *progress = new QProgressDialog(
		tr("Please wait, Key generation is in progress"),
		tr("Cancel"),90, 0, 0, true);
	   progress->setMinimumDuration(0);
	   progress->setProgress(0);	
	   progress->setCaption(tr(XCA_TITLE));
	   pki_key *nkey = new pki_key (dlg->keyDesc->text().latin1(), 
		       &MainWindow::incProgress,
		       progress,
		       sizeList[sel]);
           progress->cancel();
	   delete progress;
	   insertKey(nkey);
	   x = nkey->getDescription().c_str();
	   emit keyDone(x);
	  }
	  catch (errorEx &err) {
		  Error(err);
	  }
	}
	delete dlg;
}


void MainWindow::deleteKey()
{
	pki_key *delKey = getSelectedKey();
	if (!delKey) return;
	if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("The key") + ": '" + 
			QString::fromLatin1(delKey->getDescription().c_str()) +
			"'\n" + tr("is going to be deleted"),
			"Delete", "Cancel")
	) return;
	try {
		keys->deletePKI(delKey);
	}
	catch (errorEx &err) {
		Error(err);
	}
}


bool MainWindow::showDetailsKey(pki_key *key, bool import)
{
	if (opensslError(key)) return false;
	KeyDetail_UI *detDlg = new KeyDetail_UI(this, 0, true, 0 );
	try {	
		detDlg->setCaption(tr(XCA_TITLE));
		detDlg->keyDesc->setText(
			key->getDescription().c_str() );
		detDlg->keyLength->setText(
			key->length().c_str() );
		detDlg->keyPubEx->setText(
			key->pubEx().c_str() );
		detDlg->keyModulus->setText(
			key->modulus().c_str() );
		if (key->isPubKey()) {
			detDlg->keyPrivEx->setText(tr("not available") );
			detDlg->keyPrivEx->setDisabled(true);
		}
		detDlg->image->setPixmap(*keyImg);
		if (import) {
			detDlg->but_ok->setText(tr("Import"));
			detDlg->but_cancel->setText(tr("Discard"));
		}
	}
	catch (errorEx &err) {
		Error(err);
		delete detDlg;
		return false;
	}
	bool ret = detDlg->exec();
	string ndesc = detDlg->keyDesc->text().latin1();
	delete detDlg;
	CERR(ndesc << " " << key->getDescription());
	if ( ret && ndesc != key->getDescription()) {
		MARK
		try {
			keys->renamePKI(key, ndesc);
			MARK
		}
		catch (errorEx &err) {
			Error(err);
		}
		return true;
	}
	MARK
	return false;
}


void MainWindow::showDetailsKey()
{
	pki_key *targetKey = getSelectedKey();
	if (targetKey) showDetailsKey(targetKey);
}


void MainWindow::showDetailsKey(QListViewItem *item)
{
	string key = item->text(0).latin1();
	showDetailsKey((pki_key *)keys->getSelectedPKI(key));
}


void MainWindow::loadKey()
{
	QStringList filt;
	filt.append( "PKI Keys ( *.pem *.der )"); 
	filt.append( "PKCS#8 Keys ( *.p8 *.pk8 )"); 
	filt.append( "All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Import key");
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
	setPath(dlg);
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		newPath(dlg);
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pki_key *lkey = new pki_key(s.latin1(), &MainWindow::passRead);
			insertKey(lkey);
		}
		catch (errorEx &err) {
			Error(err);
		}
	}
}


void MainWindow::insertKey(pki_key *lkey)
{
	
	pki_key *oldkey;
	try {
	    oldkey = (pki_key *)keys->findPKI(lkey);
	    if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) ||
		    lkey->isPubKey()){
	   	    QMessageBox::information(this,tr(XCA_TITLE),
			tr("The key is already in the database as") +":\n'" +
			QString::fromLatin1(oldkey->getDescription().c_str()) + 
			"'\n" + tr("and is not going to be imported"), "OK");
		    delete(lkey);
		    return;
		}
		else {
	   	    QMessageBox::information(this,tr(XCA_TITLE),
			tr("The database already contains the public part of the imported key as") +":\n'" +
			QString::fromLatin1(oldkey->getDescription().c_str()) + 
			"'\n" + tr("and will be completed by the new, private part of the key"), "OK");
		    CERR( "before deleting pki...");
		    keys->deletePKI(oldkey);
		    lkey->setDescription(oldkey->getDescription());
		    delete(oldkey);
		}
	    }
	    CERR( "after findkey");
	    keys->insertPKI(lkey);
	}
	catch (errorEx &err) {
		Error(err);
	}

}


void MainWindow::writeKey()
{
	bool PEM=false;
	const EVP_CIPHER *enc = NULL;
	pki_key *targetKey = NULL;
	targetKey = getSelectedKey();
	if (!targetKey) return;
	ExportKey *dlg = new ExportKey((targetKey->getDescription() + ".pem").c_str(),
			targetKey->isPubKey(), this);
	dlg->image->setPixmap(*keyImg);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	string fname = dlg->filename->text().latin1();
	if (fname == "") {
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


void MainWindow::showPopupKey(QListViewItem *item, const QPoint &pt, int x) {
	CERR( " popup key" );
	QPopupMenu *menu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Key"), this, SLOT(newKey()));
		menu->insertItem(tr("Import"), this, SLOT(loadKey()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameKey()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsKey()));
		menu->insertItem(tr("Export"), this, SLOT(writeKey()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteKey()));
	}
	menu->exec(pt);
	delete menu;
	return;
}

void MainWindow::renameKey(QListViewItem *item, int col, const QString &text)
{
	try {
		pki_base *pki = keys->getSelectedPKI(item);
		string txt =  text.latin1();
		keys->renamePKI(pki, txt);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::startRenameKey()
{
	try {
#ifdef qt3
		pki_base *pki = keys->getSelectedPKI();
		if (!pki) return;
		QListViewItem *item = (QListViewItem *)pki->getPointer();
		item->startRename(0);
#else
		renamePKI(keys);
#endif
	}
	catch (errorEx &err) {
		Error(err);
	}
}



