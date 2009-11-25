/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_key.h"
#include "pki_evp.h"

#include "pki_scard.h"
#include <qmessagebox.h>
#include <qprogressbar.h>
#include <qstatusbar.h>
#include <qevent.h>
#include "exception.h"
#include "ui_NewKey.h"
#include "pkcs11.h"

#include "widgets/MainWindow.h"
#include "widgets/ExportKey.h"
#include "widgets/KeyDetail.h"
#include "widgets/NewKey.h"

db_key::db_key(QString db, MainWindow *mw)
	:db_base(db, mw)
{
	rootItem->setIntName("[key root]");
	headertext << "Name" << "Type" << "Size" << "Use" << "Password";
	delete_txt = tr("Delete the key(s)");
	view = mw->keyView;
	class_name = "keys";
	pkitype[0] = asym_key;
	pkitype[1] = smartCard;
	loadContainer();
}

pki_base *db_key::newPKI(db_header_t *head)
{
	if (!head || head->type == asym_key)
		return new pki_evp("");
	return new pki_scard("");
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

QStringList db_key::get0PrivateDesc(bool all)
{
	QStringList x;
	x.clear();
	FOR_ALL_pki(pki, pki_key) {
		if (pki->isPrivKey() && ((pki->getUcount() == 0) || all))
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

void db_key::newItem() {
	newItem("");
}

void db_key::newItem(QString name)
{
	NewKey *dlg = new NewKey(qApp->activeWindow(), name);
	QProgressBar *bar;
	QStatusBar *status = mainwin->statusBar();
	pki_evp *nkey = NULL;

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	int ksize = dlg->getKeysize();
	if (ksize > 0) {
		if (ksize < 32) {
			QMessageBox::warning(NULL, XCA_TITLE,
				tr("Key size too small !"));
			delete dlg;
			return;
		}
		if (ksize < 1024 || ksize > 8192)
			if (!QMessageBox::warning(NULL, XCA_TITLE,
				tr("You are sure to create a key of the size: ")
				+QString::number(ksize) + " ?", tr("Cancel"),
				tr("Create") ))
			{
				delete dlg;
				return;
			}
	}
	mainwin->repaint();
	nkey = new pki_evp(dlg->keyDesc->text());
	bar = new QProgressBar();
	status->addPermanentWidget(bar, 1);
	try {
		nkey->generate(ksize, dlg->getKeytype(), bar,dlg->getKeyCurve_nid());
		nkey = (pki_evp*)insert(nkey);
		emit keyDone(nkey->getIntNameWithType());
	} catch (errorEx &err) {
		delete nkey;
		mainwin->Error(err);
	}
	status->removeWidget(bar);
	delete bar;
	delete dlg;
}

void db_key::load(void)
{
	load_key l;
	load_default(l);
}

void db_key::showPki(pki_base *pki)
{
	pki_evp *key = (pki_evp *)pki;
	KeyDetail *dlg = new KeyDetail(mainwin);
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
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
		menu->addAction(tr("Export"), this, SLOT(store()));
		if (key->isPrivKey() && !key->isScard()) {
			switch (key->getOwnPass()) {
			case pki_key::ptCommon:
				menu->addAction(tr("Change password"), this,
						SLOT(setOwnPass()));
				break;
			case pki_key::ptPrivate:
				menu->addAction(tr("Reset password"), this,
						SLOT(resetOwnPass()));
				break;
			}
		}
		if (key->isScard() && pkcs11::loaded()) {
			menu->addAction(tr("Change PIN"), this,
				SLOT(changePin()));
#if 0
			menu->addAction(tr("Init PIN with SO PIN (PUK)"), this,
				SLOT(initPin()));
			menu->addAction(tr("Change SO PIN (PUK)"), this,
				SLOT(changeSoPin()));
#endif
		}
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}

void db_key::store()
{
	bool pem;
	const EVP_CIPHER *enc = NULL;

	if (!currentIdx.isValid())
		return;

	pki_key *targetKey =static_cast<pki_evp*>(currentIdx.internalPointer());

	QString fn = mainwin->getPath() + QDir::separator() +
			targetKey->getUnderlinedName() + ".pem";

	ExportKey *dlg = new ExportKey(mainwin, fn,
		targetKey->isPubKey() || targetKey->isScard());
	dlg->image->setPixmap(*MainWindow::keyImg);

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	if (fname.isEmpty()) {
		delete dlg;
		return;
	}
	mainwin->setPath(fname.mid(0, fname.lastIndexOf(QRegExp("[/\\\\]")) ));
	try {
		pem = dlg->exportFormat->currentText() == "PEM" ? true : false;
		if (dlg->encryptKey->isChecked())
			enc = EVP_des_ede3_cbc();
		if (dlg->exportPrivate->isChecked() && !targetKey->isScard()) {
			pki_evp *evpKey = (pki_evp *)targetKey;
			if (dlg->exportPkcs8->isChecked()) {
				evpKey->writePKCS8(fname, enc, &MainWindow::passWrite, pem);
			} else {
				evpKey->writeKey(fname, enc, &MainWindow::passWrite, pem);
			}
		} else {
			targetKey->writePublic(fname, pem);
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
		__setOwnPass(pki_key::ptPrivate);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::resetOwnPass()
{
	try {
		__setOwnPass(pki_key::ptCommon);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::__setOwnPass(enum pki_key::passType x)
{
	pki_evp *targetKey;
	if (!currentIdx.isValid())
		        return;
	targetKey = static_cast<pki_evp*>(currentIdx.internalPointer());
	if (targetKey->isScard()) {
		throw errorEx(tr("Tried to change password of a smart card"));
	}
	targetKey->setOwnPass(x);
	updatePKI(targetKey);
}

void db_key::changePin()
{
	pki_scard *scard;
	if (!currentIdx.isValid())
		        return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isScard()) {
			throw errorEx(tr("Tried to change PIN of a key"));
		}
		scard->changePin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::initPin()
{
	pki_scard *scard;
	if (!currentIdx.isValid())
		        return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isScard()) {
			throw errorEx(tr("Tried to init PIN of a key"));
		}
		scard->initPin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_key::changeSoPin()
{
	pki_scard *scard;
	if (!currentIdx.isValid())
		        return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isScard()) {
			throw errorEx(tr("Tried to change SO PIN of a key"));
		}
		scard->changeSoPin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

