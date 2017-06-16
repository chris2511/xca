/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_key.h"
#include "pki_evp.h"

#include "pki_scard.h"
#include <QDialog>
#include <QLabel>
#include <QPushButton>

#include <QMessageBox>
#include <QProgressBar>
#include <QStatusBar>
#include <QContextMenuEvent>

#include "exception.h"
#include "ui_NewKey.h"
#include "pkcs11.h"

#include "widgets/PwDialog.h"
#include "widgets/ExportDialog.h"
#include "widgets/KeyDetail.h"
#include "widgets/NewKey.h"

db_key::db_key(QString db, MainWindow *mw)
	:db_base(db, mw)
{
	rootItem->setIntName("[key root]");
	class_name = "keys";
	pkitype << asym_key << smartCard;
	updateHeaders();
	loadContainer();
}

dbheaderList db_key::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_key_type,   true, tr("Type")) <<
		new dbheader(HD_key_size,   true, tr("Size")) <<
#ifndef OPENSSL_NO_EC
		new dbheader(HD_key_curve,  false,tr("EC Group")) <<
#endif
		new dbheader(HD_key_use,    true, tr("Use")) <<
		new dbheader(HD_key_passwd, true, tr("Password"));
	return h;
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

QStringList db_key::get0KeyDesc(bool all)
{
	QStringList x;
	FOR_ALL_pki(pki, pki_key) {
		if ((pki->getUcount() == 0) || all)
			x.append(pki->getIntNameWithType());
	}
	return x;
}

void db_key::remFromCont(QModelIndex &idx)
{
	db_base::remFromCont(idx);
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
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
			XCA_INFO(
			tr("The key is already in the database as:\n'%1'\nand is not going to be imported").arg(oldkey->getIntName()));
			delete(lkey);
			return NULL;
		}
		else {
			XCA_INFO(
			tr("The database already contains the public part of the imported key as\n'%1\nand will be completed by the new, private part of the key").arg(oldkey->getIntName()));
			lkey->setIntName(oldkey->getIntName());
			deletePKI(index(oldkey->row(), 0, QModelIndex()));
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
	pki_scard *cardkey = NULL;
	pki_key *key = NULL;

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	int ksize = dlg->getKeysize();
	if (ksize > 0) {
		if (ksize < 32) {
			XCA_WARN(tr("Key size too small !"));
			delete dlg;
			return;
		}
		if (ksize < 1024 || ksize > 8192)
			if (!XCA_YESNO(tr("You are sure to create a key of the size: %1 ?").arg(ksize))) {
				delete dlg;
				return;
			}
	}
	mainwin->repaint();
	bar = new QProgressBar();
	status->addPermanentWidget(bar, 1);
	try {
		if (dlg->isToken()) {
			key = cardkey = new pki_scard(dlg->keyDesc->text());
			cardkey->generateKey_card(dlg->getKeytype(),
				dlg->getKeyCardSlot(), ksize,
				dlg->getKeyCurve_nid(), bar);
		} else {
			key = nkey = new pki_evp(dlg->keyDesc->text());
			nkey->generate(ksize, dlg->getKeytype(), bar,
				dlg->getKeyCurve_nid());
		}
		key = (pki_key*)insert(key);
		emit keyDone(key->getIntNameWithType());
		createSuccess(key);

	} catch (errorEx &err) {
		delete key;
		mainwin->Error(err);
	}
	if (dlg->rememberDefault->isChecked()) {
		QString def = dlg->getAsString();
		if (dlg->setDefault(def) == 0)
			mainwin->setDefaultKey(def);
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
exportType::etype db_key::clipboardFormat(QModelIndexList indexes)
{
	QList<exportType> types;
	bool allPriv = true;
	bool allRSADSA = true;

	foreach(QModelIndex idx, indexes) {
		pki_key *key = static_cast<pki_key*>
				(idx.internalPointer());
		if (key->isPubKey() || key->isToken())
			allPriv = false;
		if (key->getKeyType() != EVP_PKEY_RSA &&
		    key->getKeyType() != EVP_PKEY_DSA)
			allRSADSA = false;
	}
	if (!allPriv && !allRSADSA)
		return exportType::PEM_key;

	types << exportType(exportType::PEM_key, "pem", tr("PEM public"));
	if (allRSADSA)
		types << exportType(exportType::SSH2_public,
			"pub", tr("SSH2 public"));
	if (allPriv)
		types << exportType(exportType::PEM_private, "pem",
			tr("PEM private"));

	ExportDialog *dlg = new ExportDialog(mainwin,
		tr("Export keys to Clipboard"), QString(), NULL,
		MainWindow::keyImg, types);

	dlg->filename->setText(tr("Clipboard"));
	dlg->filename->setEnabled(false);
	dlg->fileBut->setEnabled(false);
	if (!dlg->exec()) {
		delete dlg;
		return exportType::Separator;
	}
	return dlg->type();
}

void db_key::store(QModelIndex index)
{
	const EVP_CIPHER *enc = NULL;
	QString title = tr("Export public key [%1]");
	QList<exportType> types;

	if (!index.isValid())
		return;

	pki_key *key =static_cast<pki_evp*>(index.internalPointer());
	pki_evp *privkey = (pki_evp *)key;

	types <<
	exportType(exportType::PEM_key, "pem", tr("PEM public")) <<
	exportType(exportType::DER_key, "der", tr("DER public"));
	if (key->getKeyType() == EVP_PKEY_RSA ||
            key->getKeyType() == EVP_PKEY_DSA)
		types << exportType(exportType::SSH2_public,
					"pub", tr("SSH2 public"));
	if (!key->isPubKey() && !key->isToken()) {
		QList<exportType> usual;
		types <<
		exportType(exportType::DER_private, "der",
			tr("DER private")) <<
		exportType(exportType::PEM_private_encrypt, "pem",
			tr("PEM encryped")) <<
		exportType(exportType::PKCS8, "pk8",
			"PKCS#8");
		usual <<
		exportType(exportType::PEM_private, "pem",
			tr("PEM private")) <<
		exportType(exportType::PKCS8_encrypt, "pk8",
			tr("PKCS#8 encrypted"));
		title = tr("Export private key [%1]");
		types = usual << exportType() << types;
	}
	ExportDialog *dlg = new ExportDialog(mainwin,
		title.arg(key->getTypeString()),
		tr("Private Keys ( *.pem *.der *.pk8 );; "
		   "SSH Public Keys ( *.pub )"), key,
		key->isToken() ? MainWindow::scardImg : MainWindow::keyImg,
		types);

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	try {
		exportType::etype type = dlg->type();
		switch (type) {
		case exportType::DER_key:
			key->writePublic(fname, false);
			break;
		case exportType::DER_private:
			privkey->writeKey(fname, NULL, NULL, false);
			break;
		case exportType::PEM_key:
			key->writePublic(fname, true);
			break;
		case exportType::PEM_private_encrypt:
			enc = EVP_des_ede3_cbc();
			/* fallthrough */
		case exportType::PEM_private:
			privkey->writeKey(fname, enc,
				PwDialog::pwCallback, true);
			break;
		case exportType::PKCS8_encrypt:
			enc = EVP_des_ede3_cbc();
			/* fallthrough */
		case exportType::PKCS8:
			privkey->writePKCS8(fname, enc,
				PwDialog::pwCallback, true);
			break;
		case exportType::SSH2_public:
			key->writeSSH2public(fname);
			break;
		default:
			exit(1);
		}
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
	delete dlg;
}

void db_key::setOwnPass(QModelIndex idx, enum pki_key::passType x)
{
	pki_evp *targetKey;
	if (!idx.isValid())
		return;
	targetKey = static_cast<pki_evp*>(idx.internalPointer());
	if (targetKey->isToken()) {
		throw errorEx(tr("Tried to change password of a token"));
	}
	targetKey->setOwnPass(x);
	updatePKI(targetKey);
}
