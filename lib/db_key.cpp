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

db_key::db_key(MainWindow *mw)
	:db_base(mw)
{
	class_name = "keys";
	sqlHashTable = "public_keys";
	pkitype << asym_key << smartCard;
	updateHeaders();
	loadContainer();
}

void db_key::loadContainer()
{
	XSqlQuery q;

	db_base::loadContainer();
	FOR_ALL_pki(key, pki_key)
		key->setUcount(0);

	SQL_PREPARE(q, "SELECT pkey, COUNT(*) FROM x509super WHERE pkey IS NOT NULL GROUP by pkey");
	q.exec();
	while (q.next()) {
		pki_key *key = lookupPki<pki_key>(q.value(0));
		if (!key) {
			qDebug() << "Unknown key" << q.value(0).toULongLong();
			continue;
		}
		key->setUcount(q.value(1).toInt());
	}
	MainWindow::dbSqlError(q.lastError());
}

dbheaderList db_key::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_key_type, true, tr("Type")) <<
		new num_dbheader(HD_key_size, true, tr("Size")) <<
#ifndef OPENSSL_NO_EC
		new dbheader(HD_key_curve, false,tr("EC Group")) <<
#endif
		new num_dbheader(HD_key_use, true, tr("Use")) <<
		new dbheader(HD_key_passwd, true, tr("Password"));
	return h;
}

pki_base *db_key::newPKI(enum pki_type type)
{
	if (type == asym_key)
		return new pki_evp("");
	return new pki_scard("");
}

QList<pki_key *> db_key::getAllKeys()
{
	return sqlSELECTpki<pki_key>("SELECT item from public_keys");
}

QList<pki_key *> db_key::getUnusedKeys()
{
	return sqlSELECTpki<pki_key>("SELECT public_keys.item FROM public_keys "
		"LEFT OUTER JOIN x509super ON x509super.pkey= public_keys.item "
		"WHERE x509super.item IS NULL");
}

void db_key::remFromCont(const QModelIndex &idx)
{
	db_base::remFromCont(idx);
	XSqlQuery q;

	/* "pkey" column in "x509super" table already updated
	 * in deleteSql()
	 */
	QList<pki_x509super*> items = sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey is NULL");
	foreach(pki_x509super *x509s, items) {
		x509s->setRefKey(NULL);
	}
	/* "UPDATE x509super SET pkey=NULL WHERE pkey=?" done in
	 * pki->deleteSqlData() */
}

void db_key::inToCont(pki_base *pki)
{
	db_base::inToCont(pki);
	pki_key *key = static_cast<pki_key*>(pki);
	unsigned hash = key->hash();
	QList<pki_x509super*> items = sqlSELECTpki<pki_x509super>(
		"SELECT item FROM x509super WHERE pkey IS NULL AND key_hash=?",
		QList<QVariant>() << QVariant(hash));
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE x509super SET pkey=? WHERE item=?");
	q.bindValue(0, key->getSqlItemId());
	foreach(pki_x509super *x509s, items) {
		if (!x509s->compareRefKey(key))
			continue;
		/* Found item matching this key */
		x509s->setRefKey(key);
		q.bindValue(1, x509s->getSqlItemId());
		AffectedItems(x509s->getSqlItemId());
		q.exec();
		mainwin->dbSqlError(q.lastError());
	}
}

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = static_cast<pki_key *>(item);
	pki_key *oldkey;

	oldkey = static_cast<pki_key *>(getByReference(lkey));
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			XCA_INFO(
			tr("The key is already in the database as:\n'%1'\nand is not going to be imported").arg(oldkey->getIntName()));
			delete(lkey);
			return NULL;
		} else {
			XCA_INFO(
			tr("The database already contains the public part of the imported key as\n'%1\nand will be completed by the new, private part of the key").arg(oldkey->getIntName()));
			lkey->setComment(oldkey->getComment());
			lkey->selfComment(tr("Extending public key from %1 by imported key '%2'")
				.arg(oldkey->getInsertionDate().toPretty())
				.arg(lkey->getIntName()));
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
#ifndef OPENSSL_NO_EC
	if (dlg->getKeytype() != EVP_PKEY_EC)
#endif
	{
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
		key->pkiSource = generated;
		key = (pki_key*)insert(key);
		emit keyDone(key);
		createSuccess(key);

	} catch (errorEx &err) {
		delete key;
		mainwin->Error(err);
	}
	if (dlg->rememberDefault->isChecked()) {
		QString def = dlg->getAsString();
		if (dlg->setDefault(def) == 0)
			Settings["defaultkey"] = def;
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
	pki_key *key = dynamic_cast<pki_key *>(pki);
	if (!key)
		return;
	KeyDetail *dlg = new KeyDetail(mainwin);
	if (!dlg)
		return;
	dlg->setKey(key);

	if (dlg->exec()) {
		QString newname = dlg->keyDesc->text();
		QString newcomment = dlg->comment->toPlainText();
		if (newname != pki->getIntName() ||
		    newcomment != pki->getComment())
		{
			updateItem(pki, newname, newcomment);
		}
	}
	delete dlg;
}
exportType::etype db_key::clipboardFormat(QModelIndexList indexes) const
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
			tr("PEM private"))
		      << exportType(exportType::PKCS8, "pk8",
			"PKCS#8");

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
	const EVP_CIPHER *algo = NULL, *encrypt = EVP_aes_256_cbc();
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
			algo = encrypt;
			/* fallthrough */
		case exportType::PEM_private:
			privkey->writeKey(fname, algo,
				PwDialog::pwCallback, true);
			break;
		case exportType::PKCS8_encrypt:
			algo = encrypt;
			/* fallthrough */
		case exportType::PKCS8:
			privkey->writePKCS8(fname, algo,
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
	enum pki_key::passType old_type;

	if (!idx.isValid())
		return;
	targetKey = static_cast<pki_evp*>(idx.internalPointer());
	if (targetKey->isToken()) {
		throw errorEx(tr("Tried to change password of a token"));
	}
	old_type = targetKey->getOwnPass();
	targetKey->setOwnPass(x);
	if (!targetKey->sqlUpdatePrivateKey())
		targetKey->setOwnPass(old_type);
}
