/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_key.h"
#include "pki_evp.h"

#include "pki_scard.h"
#include "main.h"
#include <QDialog>
#include <QLabel>
#include <QPushButton>

#include "exception.h"
#include "ui_NewKey.h"
#include "pkcs11.h"

#include "widgets/XcaWarning.h"
#include "widgets/PwDialog.h"
#include "widgets/ExportDialog.h"

db_key::db_key() : db_base("keys")
{
	sqlHashTable = "public_keys";
	pkitype << asym_key << smartCard;
	updateHeaders();
	loadContainer();
}

void db_key::loadContainer()
{
	XSqlQuery q;

	db_base::loadContainer();
	foreach(pki_key *key, Store.getAll<pki_key>())
		key->setUcount(0);

	SQL_PREPARE(q, "SELECT pkey, COUNT(*) FROM x509super WHERE pkey IS NOT NULL GROUP by pkey");
	q.exec();
	while (q.next()) {
		pki_key *key = Store.lookupPki<pki_key>(q.value(0));
		if (!key) {
			qDebug() << "Unknown key" << q.value(0).toULongLong();
			continue;
		}
		key->setUcount(q.value(1).toInt());
	}
	XCA_SQLERROR(q.lastError());
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
	return Store.sqlSELECTpki<pki_key>("SELECT item from public_keys");
}

QList<pki_key *> db_key::getUnusedKeys()
{
	return Store.sqlSELECTpki<pki_key>(
		"SELECT public_keys.item FROM public_keys "
		"LEFT OUTER JOIN x509super ON x509super.pkey= public_keys.item "
		"WHERE x509super.item IS NULL");
}

void db_key::remFromCont(const QModelIndex &idx)
{
	db_base::remFromCont(idx);
	XSqlQuery q;

	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
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
	QList<pki_x509super*> items = Store.sqlSELECTpki<pki_x509super>(
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
		XCA_SQLERROR(q.lastError());
	}
}

pki_base* db_key::insert(pki_base *item)
{
	pki_key *lkey = dynamic_cast<pki_key *>(item);
	pki_key *oldkey;
	pki_evp *evp = dynamic_cast<pki_evp*>(lkey);

	if (evp)
		evp->setOwnPass(pki_evp::ptCommon);

	oldkey = static_cast<pki_key *>(getByReference(lkey));
	if (oldkey != NULL) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) || lkey->isPubKey()){
			XCA_INFO(
			tr("The key is already in the database as:\n'%1'\nand is not going to be imported").arg(oldkey->getIntName()));
			delete lkey;
			return NULL;
		} else {
			XCA_INFO(
			tr("The database already contains the public part of the imported key as\n'%1\nand will be completed by the new, private part of the key").arg(oldkey->getIntName()));
			lkey->setComment(oldkey->getComment());
			lkey->selfComment(tr("Extending public key from %1 by imported key '%2'")
				.arg(oldkey->getInsertionDate().toPretty())
				.arg(lkey->getIntName()));
			lkey->setIntName(oldkey->getIntName());
			deletePKI(index(oldkey));
		}
	}
	return insertPKI(lkey);
}

pki_key *db_key::newKey(const keyjob &task, const QString &name)
{
	pki_key *key = NULL;

	if (!task.isEC() && !task.isED25519()) {
		if (task.size < 32) {
			XCA_WARN(tr("Key size too small !"));
			return NULL;
		}
		if (task.size < 1024 || task.size > 8192)
			if (!XCA_YESNO(tr("You are sure to create a key of the size: %1 ?").arg(task.size))) {
				return NULL;
			}
	}
	try {
		if (task.isToken()) {
			key = new pki_scard(name);
		} else {
			key = new pki_evp(name);
		}
		key->generate(task);
		key->pkiSource = generated;
		if (key->getIntName().isEmpty())
			key->autoIntName(name);
		key = dynamic_cast<pki_key*>(insert(key));
		emit keyDone(key);
		createSuccess(key);

	} catch (errorEx &err) {
		delete key;
		key = NULL;
		XCA_ERROR(err);
	}
	return key;
}

void db_key::load(void)
{
	load_key l;
	load_default(l);
}

exportType::etype db_key::clipboardFormat(QModelIndexList indexes) const
{
	QList<exportType> types;
	bool allPriv = true;
	bool ssh2compatible = true;

	foreach(QModelIndex idx, indexes) {
		pki_key *key = fromIndex<pki_key>(idx);
		if (!key)
			continue;
		if (key->isPubKey() || key->isToken())
			allPriv = false;
		if (!key->SSH2_compatible())
			ssh2compatible = false;
	}
	if (!allPriv && !ssh2compatible)
		return exportType::PEM_key;

	types << exportType(exportType::PEM_key, "pem", tr("PEM public"));
	if (ssh2compatible)
		types << exportType(exportType::SSH2_public,
			"pub", tr("SSH2 public"));
	if (allPriv) {
		types << exportType(exportType::PEM_private, "pem",
			tr("PEM private"))
		      << exportType(exportType::PKCS8, "pk8",
			"PKCS#8");
		if (ssh2compatible)
			types << exportType(exportType::SSH2_private,
				"priv", tr("SSH2 private"));
	}
	ExportDialog *dlg = new ExportDialog(NULL,
		tr("Export keys to Clipboard"), QString(), NULL,
		QPixmap(":keyImg"), types, "keyexport");

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
	bool pvk = false, ed25519 = false;

	pki_key *key = fromIndex<pki_key>(index);
	pki_evp *privkey = dynamic_cast<pki_evp *>(key);

	if (!index.isValid() || !key)
		return;

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	int keytype = key->getKeyType();
	if (keytype == EVP_PKEY_RSA || keytype == EVP_PKEY_DSA)
		pvk = true;
#ifdef EVP_PKEY_ED25519
	if (keytype == EVP_PKEY_ED25519)
		ed25519 = true;
#endif
#endif

	types <<
	exportType(exportType::PEM_key, "pem", tr("PEM public")) <<
	exportType(exportType::DER_key, "der", tr("DER public"));

	if (key->SSH2_compatible())
		types << exportType(exportType::SSH2_public,
					"pub", tr("SSH2 public"));
	if (!key->isPubKey() && !key->isToken()) {
		QList<exportType> usual;
		if (!ed25519)
			types << exportType(exportType::PEM_private_encrypt,
				"pem", tr("PEM encryped"));
		types <<
			exportType(exportType::DER_private, "der",
				tr("DER private")) <<
			exportType(exportType::PKCS8, "pk8", "PKCS#8");

		if (pvk) {
			types <<
			exportType(exportType::PVK_private, "pvk",
				tr("PVK private")) <<
			exportType(exportType::PVK_encrypt, "pvk",
				tr("PVK encrypted"));
		}
		if (!ed25519)
			usual << exportType(exportType::PEM_private, "pem",
				tr("PEM private"));
		usual << exportType(exportType::PKCS8_encrypt, "pk8",
			tr("PKCS#8 encrypted"));
		if (key->SSH2_compatible())
			usual << exportType(exportType::SSH2_private, "priv",
				tr("SSH2 private"));
		title = tr("Export private key [%1]");
		types = usual << exportType() << types;
	}
	ExportDialog *dlg = new ExportDialog(NULL,
		title.arg(key->getTypeString()),
		tr("Private Keys ( *.pem *.der *.pk8 );; "
		   "SSH Public Keys ( *.pub )"), key,
		QPixmap(key->isToken() ? ":scardImg" : ":keyImg"),
		types, "keyexport");

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	try {
		exportType::etype type = dlg->type();
		pki_base::pem_comment = dlg->pemComment->isChecked();
		XFile file(dlg->filename->text());

		switch (type) {
		case exportType::DER_key:
		case exportType::PEM_key:
		case exportType::SSH2_public:
			file.open_write();
			break;
		default:
			file.open_key();
		}
		switch (type) {
		case exportType::DER_key:
			key->writePublic(file, false);
			break;
		case exportType::DER_private:
			privkey->writeKey(file, NULL, NULL, false);
			break;
		case exportType::PEM_key:
			key->writePublic(file, true);
			break;
		case exportType::PEM_private_encrypt:
			algo = encrypt;
			/* fallthrough */
		case exportType::PEM_private:
			privkey->writeKey(file, algo,
				PwDialog::pwCallback, true);
			break;
		case exportType::PKCS8_encrypt:
			algo = encrypt;
			/* fallthrough */
		case exportType::PKCS8:
			privkey->writePKCS8(file, algo,
				PwDialog::pwCallback, true);
			break;
		case exportType::SSH2_public:
			key->writeSSH2public(file);
			break;
		case exportType::SSH2_private:
			key->writeSSH2private(file, PwDialog::pwCallback);
			break;
		case exportType::PVK_private:
			privkey->writePVKprivate(file, NULL);
			break;
		case exportType::PVK_encrypt:
			privkey->writePVKprivate(file, PwDialog::pwCallback);
			break;
		default:
			throw errorEx(tr("Internal error"));
		}
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	pki_base::pem_comment = false;
	delete dlg;
}

void db_key::setOwnPass(QModelIndex idx, enum pki_key::passType x)
{
	pki_evp *targetKey = fromIndex<pki_evp>(idx);
	enum pki_key::passType old_type;

	if (!idx.isValid() || !targetKey)
		return;
	if (targetKey->isToken()) {
		throw errorEx(tr("Tried to change password of a token"));
	}
	old_type = targetKey->getOwnPass();
	targetKey->setOwnPass(x);
	if (!targetKey->sqlUpdatePrivateKey())
		targetKey->setOwnPass(old_type);
}
