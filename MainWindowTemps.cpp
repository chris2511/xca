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


void MainWindow::newTemp(int type=1)
{
	NewKey_UI *dlg = new NewKey_UI(this,0,true,0);
	QString x;
	for (int i=0; sizeList[i] != 0; i++ ) 
	   dlg->keyLength->insertItem( x.number(sizeList[i]) +" bit");	
	dlg->keyLength->setCurrentItem(2);
	dlg->image->setPixmap(*keyImg);
	if (dlg->exec()) {
	   int sel = dlg->keyLength->currentItem();
	   QProgressDialog *progress = new QProgressDialog(
		tr("Please wait, Key generation is in progress"),
		tr("Cancel"),90, 0, 0, true);
	   progress->setMinimumDuration(0);
	   progress->setProgress(0);	
	   pki_key *nkey = new pki_key (dlg->keyDesc->text().latin1(), 
		       &MainWindow::incProgress,
		       progress,
		       sizeList[sel]);
           progress->cancel();
	   insertKey(nkey);
	   x=nkey->getDescription().c_str();
	   emit keyDone(x);
	}
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
	keys->deletePKI(delTemp);
}


bool MainWindow::showDetailsTemp(pki_temp *key)
{
	/*
	if (!key) return false;
	if (opensslError(key)) return false;
	KeyDetail_UI *detDlg = new KeyDetail_UI(this, 0, true, 0 );
	
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
	
	if ( !detDlg->exec()) return false;
	string ndesc = detDlg->keyDesc->text().latin1();
	if (ndesc != key->getDescription()) {
		keys->renamePKI(key, ndesc);
	}
	*/
	return true;
}


void MainWindow::showDetailsTemp()
{
	pki_temp *targetTemp = (pki_temp *)temps->getSelectedPKI();
	if (targetTemp) showDetailsTemp(targetTemp);
}


void MainWindow::showDetailsTemp(QListViewItem *item)
{
	string temp = item->text(0).latin1();
	showDetailsTemp((pki_temp *)temps->getSelectedPKI(temp));
}


void MainWindow::insertTemp(pki_temp *temp)
{
	if (!temps->insertPKI(temp))
	   QMessageBox::warning(this, "Template storage",
		tr("The template could not be stored into the database"), "OK");
	
}

void MainWindow::showPopupTemp(QListViewItem *item, const QPoint &pt, int x) {
	CERR << "hallo popup template" << endl;
	QPopupMenu *menu = new QPopupMenu(this);
	if (!item) {
		menu->insertItem(tr("New Template"), this, SLOT(newTemp()));
	}
	else {
		menu->insertItem(tr("Rename"), this, SLOT(startRenameTemp()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsTemp()));
		menu->insertItem(tr("Create certificate"), this, SLOT(newTemp()));
		menu->insertItem(tr("Create request"), this, SLOT(newTemp()));
	}
	menu->exec(pt);
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
	pki_base *pki = temps->getSelectedPKI();
	QListViewItem *item = (QListViewItem *)pki->getPointer();
	item->startRename(0);
#else
	renamePKI(temps);
#endif
}
