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
 *	written by Eric Young (eay@cryptsoft.com)"
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


#include "db_key.h"
#include <Qt/qmessagebox.h>
#include <Qt/qprogressbar.h>
#include <Qt/qstatusbar.h>
#include <Qt/qevent.h>
#include "exception.h"
#include "ui/NewKey.h"

#include "widgets/MainWindow.h"
#include "widgets/ExportKey.h"
#include "widgets/KeyDetail.h"

db_key::db_key(QString db, MainWindow *mw)
	:db_base(db, mw)
{
	delete rootItem;
	rootItem = newPKI();
	headertext << "Name" << "Type" << "Size" << "Use counter";
	delete_txt = tr("Delete the key(s)");
	loadContainer();
}

pki_base *db_key::newPKI(){
	return new pki_key("");
}


QStringList db_key::getPrivateDesc()
{
	QStringList x;
	x.clear();
	FOR_ALL_pki(pki, pki_key)
		if (pki->isPrivKey())
			x.append(pki->getIntName());
	return x;
}

QStringList db_key::get0PrivateDesc()
{
	QStringList x;
	x.clear();
	FOR_ALL_pki(pki, pki_key) {
		//printf("0Privatre desc: %s: priv:%d, cnt:%d\n", CCHAR(pki->getIntName()),	pki->isPrivKey() ,pki->getUcount());
		if (pki->isPrivKey() && pki->getUcount() == 0)
			x.append(pki->getIntNameWithType());
	}
	return x;
}

void db_key::remFromCont(QModelIndex &idx)
{
	db_base::remFromCont(idx);
	pki_base *pki = static_cast<pki_base*>(currentIdx.internalPointer());
	emit delKey((pki_key *)pki);
}

void db_key::inToCont(pki_base *pki)
{
	db_base::inToCont(pki);
	emit newKey((pki_key *)pki);
}

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = (pki_key *)item;
	pki_key *oldkey;

	oldkey = (pki_key *)getByReference(lkey);
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			QMessageBox::information(NULL, tr(XCA_TITLE),
			tr("The key is already in the database as") +":\n'" +
			oldkey->getIntName() +
			"'\n" + tr("and is not going to be imported"), "OK");
			delete(lkey);
			return oldkey;
		}
		else {
			QMessageBox::information(NULL,tr(XCA_TITLE),
			tr("The database already contains the public part of the imported key as") +":\n'" +
			oldkey->getIntName() +
			"'\n" + tr("and will be completed by the new, private part of the key"), "OK");
			lkey->setIntName(oldkey->getIntName());
			currentIdx = index(oldkey->row(), 0, QModelIndex());
			deletePKI();
			currentIdx = QModelIndex();
		}
	}
	insertPKI(lkey);

	return lkey;
}


void db_key::newItem()
{
	const int sizeList[] = { 512, 1024, 2048, 4096, 0 };

	QDialog *dlg = new QDialog(qApp->activeWindow());
	Ui::NewKey ui;
	ui.setupUi(dlg);
	QProgressBar *bar = new QProgressBar();
	QStatusBar *status = mainwin->statusBar();

	pki_key *nkey = NULL;
	QString x;
	int keytypes[] = {EVP_PKEY_RSA, EVP_PKEY_DSA };
	ui.keyLength->setEditable(true);
	for (int i=0; sizeList[i] != 0; i++ ) {
		ui.keyLength->addItem( x.number(sizeList[i]) +" bit");
	}
	ui.keyLength->setCurrentIndex(1);
	ui.keyDesc->setFocus();

	ui.image->setPixmap(*MainWindow::keyImg);

	if (dlg->exec()) {
		db mydb(dbName);

		QString ksizes = ui.keyLength->currentText();
		ksizes.replace( QRegExp("[^0-9]"), "" );
		int ksize = ksizes.toInt();
		if (ksize < 32) throw errorEx(tr("Key size too small !"));
		if (ksize < 512 || ksize > 4096)
			if (!QMessageBox::warning(NULL, XCA_TITLE, tr("You are sure to create a key of the size: ")
				+QString::number(ksize) + " ?", tr("Cancel"), tr("Create") ))
					return;

		nkey = new pki_key(ui.keyDesc->text());

		QString m = status->currentMessage();
		status->clearMessage();
		status->addPermanentWidget(bar,1);
		nkey->generate(ksize, keytypes[ui.keyType->currentIndex()], bar );
		status->removeWidget(bar);
		delete bar;
		status->showMessage(m);
		nkey = (pki_key*)insert(nkey);
		printf("Emit KeyDone\n");
		emit keyDone(nkey->getIntNameWithType());
	}
	delete dlg;
}

void db_key::load(void)
{
	load_key l;
	load_default(l);
}

void db_key::showItem()
{
	if (!currentIdx.isValid())
		return;
	pki_key *key = static_cast<pki_key*>(currentIdx.internalPointer());
	KeyDetail *dlg;

	dlg = new KeyDetail(mainwin);
	if (dlg) {
		dlg->setKey(key);
		dlg->exec();
		delete dlg;
	}
}

void db_key::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);

	currentIdx = index;
	pki_key *key = static_cast<pki_key*>(currentIdx.internalPointer());

	menu->addAction(tr("New Key"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		menu->addAction(tr("Export"), this, SLOT(store()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
		if (!key->getOwnPass())
			menu->addAction(tr("Change password"), this, SLOT(setOwnPass()));
		else
			menu->addAction(tr("Reset password"), this, SLOT(resetOwnPass()));
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}

void db_key::store()
{
	bool PEM = false;
	const EVP_CIPHER *enc = NULL;

	if (!currentIdx.isValid())
		return;

	pki_key *targetKey = static_cast<pki_key*>(currentIdx.internalPointer());

	QString fn = targetKey->getIntName() + ".pem";

	ExportKey *dlg = new ExportKey(mainwin, fn,
			targetKey->isPubKey(), mainwin->getPath() );
	dlg->image->setPixmap(*MainWindow::keyImg);

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	mainwin->setPath(dlg->dirPath);
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
		mainwin->Error(err);
	}
	delete dlg;

}

void db_key::setOwnPass()
{
	try {
		__setOwnPass(1);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::resetOwnPass()
{
	try {
		__setOwnPass(0);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::__setOwnPass(int x)
{
	pki_key *targetKey;
	if (!currentIdx.isValid())
		        return;
    targetKey = static_cast<pki_key*>(currentIdx.internalPointer());
	targetKey->setOwnPass(x);
	updatePKI(targetKey);
}

