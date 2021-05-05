/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509.h"
#include "pki_x509.h"
#include "pki_crl.h"
#include "pki_temp.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pass_info.h"
#include "database_model.h"
#include "entropy.h"

#include "widgets/XcaWarning.h"
#include "widgets/CertExtend.h"
#include "widgets/ExportDialog.h"
#include "widgets/MainWindow.h"
#include "widgets/PwDialog.h"
#include "widgets/RevocationList.h"
#include "widgets/NewX509.h"
#include "widgets/Help.h"

#include "ui_CaProperties.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include <QAction>

#include <openssl/rand.h>

db_x509::db_x509() : db_x509super("certificates")
{
	sqlHashTable = "certs";
	pkitype << x509;
	pkitype_depends << x509_req;
	updateHeaders();
	loadContainer();
}

void db_x509::loadContainer()
{
	db_x509super::loadContainer();

	XSqlQuery q("SELECT item, issuer FROM certs WHERE issuer is NOT NULL");
	while (q.next()) {
		pki_base *root = treeItem;
		pki_x509 *cert = Store.lookupPki<pki_x509>(q.value(0));
		pki_x509 *issuer = Store.lookupPki<pki_x509>(q.value(1));
		if (cert && issuer) {
			cert->setSigner(issuer);
			if (cert != issuer)
				root = issuer;
		}
		if (cert && cert->getParent() != root) {
			qDebug() << "MOVE" << cert->getIntName()
				<< "from" << cert->getParent()->getIntName()
				<< "to" << root->getIntName();
			insertChild(cert, root);
		}
	}
	emit columnsContentChanged();
}

dbheaderList db_x509::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_cert_ca, true, tr("CA"),
			tr("reflects the basic Constraints extension")) <<
		new num_dbheader(HD_cert_serial, true, tr("Serial")) <<
		new num_dbheader(HD_cert_md5fp, false,tr("MD5 fingerprint")) <<
		new num_dbheader(HD_cert_sha1fp,false,tr("SHA1 fingerprint")) <<
		new num_dbheader(HD_cert_sha256fp,false,tr("SHA256 fingerprint")) <<
		new date_dbheader(HD_cert_notBefore, false,tr("Start date"),
				tr("Not before")) <<
		new date_dbheader(HD_cert_notAfter, true, tr("Expiry date"),
				tr("Not after")) <<
		new date_dbheader(HD_cert_revocation,false, tr("Revocation")) <<
		new date_dbheader(HD_cert_crl_expire,true, tr("CRL Expiration"));
	return h;
}

pki_base *db_x509::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_x509();
}

QList<pki_x509 *> db_x509::getAllIssuers()
{
	/* Select X509 CA certificates with available private key */
	return Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN private_keys ON x509super.pkey = private_keys.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1") +
		Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN tokens ON x509super.pkey = tokens.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1");
}

void db_x509::remFromCont(const QModelIndex &idx)
{
	db_crl *crls = Database.model<db_crl>();
	db_x509super::remFromCont(idx);
	pki_base *pki = fromIndex(idx);
	pki_x509 *child;
	pki_base *new_parent;
	QList<pki_x509 *> childs;

	while (pki->childCount()) {
		child = dynamic_cast<pki_x509*>(pki->takeFirst());
		child->delSigner(dynamic_cast<pki_x509*>(pki));
		new_parent = child->findIssuer();
		insertChild(child);
		if (new_parent)
			childs << child;
	}
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	foreach(pki_x509 *child, childs) {
		q.bindValue(0, child->getSigner()->getSqlItemId());
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
	}
	crls->removeSigner(pki);
}

static bool recursiveSigning(pki_x509 *cert, pki_x509 *client)
{
	/* recursive signing check */
	for (pki_x509 *s = cert->getSigner(); s; s = s->getSigner()) {
		if (s == s->getSigner()) {
			return false;
		}
		if (s == client) {
			qWarning() << "Recursive signing:" << s->getIntName()
				<< "<->" << cert->getIntName();
			return true;
		}
	}
	return false;
}

void db_x509::inToCont(pki_base *pki)
{
	pki_x509 *cert = dynamic_cast<pki_x509*>(pki);
	cert->setParent(NULL);
	pki_base *root = cert->getSigner();

	insertChild(cert, root);

	QList<pki_x509 *> childs;
	QList<pki_x509 *> items;
	unsigned pubhash = cert->pubHash();
	unsigned namehash = cert->getSubject().hashNum();
	x509revList revList;

	/* Search for another certificate (name and key)
	 * and use its childs if we are newer */
	items = Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1 AND x509super.subj_hash=? "
		"AND x509super.key_hash=?",
			QList<QVariant>() << namehash << pubhash);
	foreach(pki_x509 *other, items) {
		if (other == cert)
			continue;
		if (!other->compareNameAndKey(cert))
			continue;
		if (cert->getNotAfter() < other->getNotAfter())
			continue;
		foreach(pki_base *b, other->getChildItems()) {
			pki_x509 *child = dynamic_cast<pki_x509*>(b);
			if (!child)
				continue;
			child->delSigner(other);
			childs << child;
		}
		revList.merge(other->getRevList());
	}
	/* Search rootItem childs, whether they are ours */
	foreach(pki_base *b, rootItem->getChildItems()) {
		pki_x509 *child = dynamic_cast<pki_x509*>(b);
		if (!child || child == cert || child->getSigner() == child)
			continue;
		if (child->verify_only(cert))
			childs << child;
	}
	/* move collected childs to us */
	XSqlQuery q;
	x509revList revokedChilds;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	q.bindValue(0, cert->getSqlItemId());
	foreach(pki_x509 *child, childs) {
		if (recursiveSigning(cert, child))
			continue;
		if (!child->verify(cert))
			continue;
		insertChild(child, cert);
		q.bindValue(1, child->getSqlItemId());
		AffectedItems(child->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
		if (child->isRevoked())
			revokedChilds << child->getRevocation();
	}
	q.finish();
	revList.merge(revokedChilds);
	cert->setRevocations(revList);

	/* Update CRLs */
	QList<pki_crl *> crls = Store.sqlSELECTpki<pki_crl>(
			"SELECT item FROM crls WHERE iss_hash=?",
			QList<QVariant>() << namehash);
	SQL_PREPARE(q, "UPDATE crls SET issuer=? WHERE item=?");
	foreach(pki_crl *crl, crls) {
		crl->verify(cert);
		if (cert != crl->getIssuer())
			continue;
		q.bindValue(0, cert->getSqlItemId());
		q.bindValue(1, crl->getSqlItemId());
		AffectedItems(crl->getSqlItemId());
		q.exec();
		XCA_SQLERROR(q.lastError());
	}
}

QList<pki_x509*> db_x509::getCerts(bool unrevoked)
{
	QList<pki_x509*> c;
	c.clear();
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
		if (unrevoked && pki->isRevoked())
			continue;
		c.append(pki);
	}
	return c;
}

void db_x509::writeIndex(const QString &fname, bool hierarchy) const
{
	if (hierarchy) {
		QString dir = fname + "/";
		if (!QDir().mkpath(fname)) {
			throw errorEx(tr("Failed to create directory '%1'")
				.arg(fname));
		}
		QList<pki_x509*> issuers = Store.sqlSELECTpki<pki_x509>(
			"SELECT DISTINCT issuer FROM certs WHERE issuer != item");
		foreach(pki_x509 *ca, issuers) {
			XFile file(dir + ca->getUnderlinedName() + ".txt");
			file.open_write();
			writeIndex(file, Store.sqlSELECTpki<pki_x509>(
				"SELECT item FROM certs WHERE issuer=?",
				QList<QVariant>()<<QVariant(ca->getSqlItemId()))
			);
		}
	} else {
		XFile file(fname);
		file.open_write();
		writeIndex(file, Store.sqlSELECTpki<pki_x509>(
					"SELECT item FROM certs"));
	}
}

static a1int randomSerial()
{
	unsigned char buf[SHA512_DIGEST_LENGTH];
	unsigned char md[SHA512_DIGEST_LENGTH];

	Entropy::seed_rng();

	RAND_bytes(buf, SHA512_DIGEST_LENGTH);
	SHA512(buf, SHA512_DIGEST_LENGTH, md);
	a1int serial;
	if (md[0] && md[0] < 0x80)
		serial.setRaw(md, (int)Settings["serial_len"] / 8);
	return serial;
}

a1int db_x509::getUniqueSerial(pki_x509 *signer)
{
	// returns an unused unique serial
	a1int serial, signer_serial;
	x509rev rev;
	x509revList revList;
	if (signer) {
		signer_serial = signer->getSerial();
		revList = signer->getRevList();
	}
	for (int i=0; ; i++) {
		if (i > 100)
			throw errorEx(tr("Failed to retrieve unique random serial"));
		serial = randomSerial();
		if (serial == a1int(0L))
			continue;
		if (!signer)
			break;
		if (signer_serial == serial)
			continue;
		rev.setSerial(serial);
		if (revList.contains(rev))
			continue;
		if (signer->getBySerial(serial))
			continue;
		break;
	}
	return serial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = dynamic_cast<pki_x509 *>(item);
	pki_x509 *oldcert = dynamic_cast<pki_x509 *>(getByReference(cert));
	if (oldcert) {
		XCA_INFO(tr("The certificate already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcert->getIntName()));
		delete cert;
		return NULL;
	}
	return insertPKI(cert);
}

void db_x509::load(void)
{
	load_cert c;
	load_default(c);
}

pki_x509 *db_x509::get1SelectedCert()
{
	QModelIndexList indexes = mainwin->certView->getSelectedIndexes();
	QModelIndex index;
	if (indexes.count())
		index = indexes[0];
	return fromIndex<pki_x509>(index);
}

void db_x509::markRequestSigned(pki_x509req *req, pki_x509 *cert)
{
	if (!req || !cert)
		return;
	pki_x509 *issuer = cert->getSigner();

	Transaction;
	if (!TransBegin())
		return;

	XSqlQuery q;
	req->setDone();
	SQL_PREPARE(q, "UPDATE requests SET signed=? WHERE item=?");
	q.bindValue(0, 1);
	q.bindValue(1, req->getSqlItemId());
	AffectedItems(req->getSqlItemId());
	q.exec();

	a1time a;
	req->selfComment(tr("Signed on %1 by '%2'").arg(a.toPretty())
		.arg(issuer ? issuer->getIntName() : tr("Unknown")));
	SQL_PREPARE(q, "UPDATE items SET comment=? WHERE id=?");
	q.bindValue(0, req->getComment());
	q.bindValue(1, req->getSqlItemId());
	q.exec();

	TransCommit();
}

void db_x509::newItem()
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	pki_x509 *sigcert = get1SelectedCert();
	dlg->defineSigner((pki_x509*)sigcert, true);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_x509req *req)
{
	NewX509 *dlg = new NewX509();
	pki_x509 *sigcert = get1SelectedCert();
	dlg->setCert();
	dlg->defineRequest(req);
	dlg->defineSigner(sigcert, true);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_temp *temp)
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->defineTemplate(temp);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_x509 *cert)
{
	NewX509 *dlg = new NewX509();
	dlg->setCert();
	dlg->fromX509super(cert, false);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

pki_x509 *db_x509::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL, *tempkey = NULL;
	a1int serial;
	QString intname;

    try {
	Transaction;
	// Step 1 - Subject and key
	if (!dlg->fromReqCB->isChecked()) {
		clientkey = dlg->getSelectedKey();
		if (!clientkey)
			return NULL;
		intname = dlg->description->text();
	} else {
		// A PKCS#10 Request was selected
		req = dlg->getSelectedReq();
		if (!req)
			return NULL;
		clientkey = req->getRefKey();
		if (clientkey == NULL) {
			clientkey = req->getPubKey();
			tempkey = clientkey;
		}
		intname = req->getIntName();
	}
	TransThrow();

	if (clientkey == NULL)
		throw errorEx(tr("Invalid public key"));
	// initially create cert
	cert = new pki_x509();
	cert->setIntName(intname);
	cert->setSubject(dlg->getX509name());
	cert->setPubKey(clientkey);

	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = dlg->getSelectedSigner();
		if (!signcert) {
			delete cert;
			return NULL;
		}
		serial = getUniqueSerial(signcert);
		signkey = signcert->getRefKey();
	} else {
		signcert = cert;
		signkey = clientkey;
		serial = getUniqueSerial(NULL);
	}

	dlg->initCtx(cert, signcert, NULL);
	// if we can not sign
	if (! signkey || signkey->isPubKey()) {
		delete cert;
		throw errorEx(tr("The key you selected for signing is not a private one."));
	}

	// set the issuers name
	cert->setIssuer(signcert->getSubject());
	cert->setSerial(serial);

	// Step 3 - Choose the Date
	// Date handling
	cert->setNotBefore(dlg->notBefore->getDate());
	a1time a;
	if (dlg->noWellDefinedExpDate->isChecked())
		a.setUndefined();
	else
		a = dlg->notAfter->getDate();

	cert->setNotAfter(a);

	// STEP 4 handle extensions

	// apply all extensions to the subject cert in the context
	dlg->getAllExt();

	// apply extensions from CSR if requested
	if (dlg->copyReqExtCB->isChecked() && dlg->fromReqCB->isChecked()) {
		extList el = req->getV3ext();
		int m = el.count();
		for (int i=0; i<m; i++)
			cert->addV3ext(el[i], true);
	}

	const EVP_MD *hashAlgo = dlg->hashAlgo->currentHash();
	// and finally sign the request
	cert->sign(signkey, hashAlgo);

	// set the comment field
	cert->setComment(dlg->comment->toPlainText());
	cert->pkiSource = dlg->getPkiSource();
	cert = dynamic_cast<pki_x509*>(insert(cert));
	createSuccess(cert);
	if (cert && clientkey->isToken()) {
		pki_scard *card = (pki_scard*)clientkey;
		if (XCA_YESNO(tr("Store the certificate to the key on the token '%1 (#%2)' ?").
			arg(card->getCardLabel()).arg(card->getSerial())))
		{
			try {
				cert->store_token(false);
			} catch (errorEx &err) {
				XCA_ERROR(err);
			}
		}
	}
	delete tempkey;
	markRequestSigned(req, cert);
	TransCommit();
    }

    catch (errorEx &err) {
		XCA_ERROR(err);
		delete cert;
		if (tempkey != NULL)
			delete(tempkey);
		cert = NULL;
    }
    return cert;
}

void db_x509::store(QModelIndex idx)
{
	QModelIndexList l;
	l << idx;
	store(l);
}

void db_x509::store(QModelIndexList list)
{
	QStringList filt;
	bool chain;
	QList<exportType> types, usual;

	if (list.size() == 0)
		return;

	pki_x509 *oldcrt, *crt = fromIndex<pki_x509>(list[0]);
	if (!crt)
		return;

	pki_key *privkey = crt->getRefKey();
	pki_evp *pkey;
	chain = crt->getSigner() && crt->getSigner() != crt;

	usual <<
		exportType(exportType::PEM, "crt", "PEM") <<
		exportType(exportType::PKCS7, "p7b", "PKCS #7");

	types << exportType(exportType::DER, "cer", "DER");

	if (list.size() > 1) {
		usual <<
			exportType(exportType::PEM_selected, "pem",
				"PEM selected") <<
			exportType(exportType::PKCS7_selected, "pem",
				"PKCS7 selected");
	}
	if (chain) {
		types <<
			exportType(exportType::PEM_chain, "pem",
				tr("PEM chain")) <<
			exportType(exportType::PKCS7_chain, "p7b",
				tr("PKCS#7 chain"));
	}

	if (privkey && privkey->isPrivKey() && !privkey->isToken()) {
		if (chain) {
			usual << exportType(exportType::PKCS12_chain, "pfx",
				tr("PKCS#12 chain"));
			types << exportType(exportType::PKCS12, "pfx",
				"PKCS #12");
		} else {
			usual << exportType(exportType::PKCS12, "pfx",
				"PKCS #12");
		}
		types <<
			exportType(exportType::PEM_cert_key, "pem",
				tr("PEM + key")) <<
			exportType(exportType::PEM_cert_pk8, "pem",
				"PEM + PKCS#8");
	}
	types << exportType() <<
		exportType(exportType::PKCS7_unrevoked, "p7b",
			tr("PKCS#7 unrevoked")) <<
		exportType(exportType::PKCS7_all, "p7b",
			tr("PKCS#7 all")) <<
		exportType(exportType::PEM_unrevoked, "pem",
			tr("PEM unrevoked")) <<
		exportType(exportType::PEM_all, "pem",
			tr("PEM all")) <<
		exportType(exportType::Index, "txt",
			tr("Certificate Index file"));
	if (crt->getNotAfter() > a1time())
		types << exportType(exportType::vcalendar, "ics",
			tr("vCalendar"));

	if (crt->isCA())
		types << exportType(exportType::vcalendar_ca, "ics",
			tr("CA vCalendar"));

	types = usual << exportType() << types;
	ExportDialog *dlg = new ExportDialog(NULL, tr("Certificate export"),
		tr("X509 Certificates ( *.pem *.cer *.crt *.p12 *.pfx *.p7b )"), crt,
		QPixmap(":certImg"), types, "certexport");
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QStringList vcal;
	QList<pki_x509*> certs;
	QList<pki_base*> items;
	enum exportType::etype type = dlg->type();
	try {
		XFile file(dlg->filename->text());
		file.open_write();
		pki_base::pem_comment = dlg->pemComment->isChecked();

		switch (type) {
		case exportType::PEM:
			crt->writeCert(file, true);
			break;
		case exportType::PEM_chain:
			while (crt && crt != oldcrt) {
				crt->writeCert(file, true);
				oldcrt = crt;
				crt = crt->getSigner();
			}
			break;
		case exportType::PEM_selected:
			foreach(QModelIndex idx, list) {
				crt = fromIndex<pki_x509>(idx);
				if (crt)
					crt->writeCert(file, true);
			}
			break;
		case exportType::PEM_unrevoked:
			foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
				if (!pki->isRevoked())
					pki->writeCert(file, true);
			}
			break;
		case exportType::PEM_all:
			foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
				pki->writeCert(file, true);
			}
			break;
		case exportType::DER:
			crt->writeCert(file, false);
			break;
		case exportType::PKCS7:
		case exportType::PKCS7_chain:
		case exportType::PKCS7_unrevoked:
		case exportType::PKCS7_selected:
		case exportType::PKCS7_all:
			writePKCS7(crt, file, type, list);
			break;
		case exportType::PKCS12:
			writePKCS12(crt, file, false);
			break;
		case exportType::PKCS12_chain:
			writePKCS12(crt, file, true);
			break;
		case exportType::PEM_cert_pk8:
		case exportType::PEM_cert_key:
			pkey = (pki_evp *)crt->getRefKey();
			if (!pkey || pkey->isPubKey()) {
				XCA_WARN(tr("There was no key found for the Certificate: '%1'").
					arg(crt->getIntName()));
				break;
			}
			if (pkey->isToken()) {
				XCA_WARN(tr("Not possible for a token key: '%1'").
					arg(crt->getIntName()));
				break;
			}

			if (type == exportType::PEM_cert_pk8) {
				pkey->writePKCS8(file, EVP_des_ede3_cbc(),
						PwDialog::pwCallback, true);
			} else {
				pkey->writeKey(file, NULL, NULL, true);
			}
			crt->writeCert(file, true);
			break;
		case exportType::Index:
			foreach(QModelIndex idx, list) {
				crt = fromIndex<pki_x509>(idx);
				if (crt)
					certs << crt;
			}
			writeIndex(file, certs);
			break;
		case exportType::vcalendar:
			foreach(QModelIndex idx, list) {
				crt = fromIndex<pki_x509>(idx);
				if (crt)
					vcal += crt->icsVEVENT();
			}
			writeVcalendar(file, vcal);
			break;
		case exportType::vcalendar_ca:
			foreach(QModelIndex idx, list) {
				crt = fromIndex<pki_x509>(idx);
				if (crt)
					vcal += crt->icsVEVENT_ca();
			}
			writeVcalendar(file, vcal);
			break;
		default:
			exit(1);
		}
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	pki_base::pem_comment = false;
	delete dlg;
}

void db_x509::writeIndex(XFile &file, QList<pki_x509*> items) const
{
	QString index;
	foreach(pki_x509 *cert, items) {
		if (cert)
			index += cert->getIndexEntry();
	}
	file.write(index.toUtf8());
}

void db_x509::writePKCS12(pki_x509 *cert, XFile &file, bool chain) const
{
	QStringList filt;
	pki_pkcs12 *p12 = NULL;
	try {
		pki_evp *privkey = (pki_evp *)cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			XCA_WARN(tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
			return;
		}
		if (privkey->isToken()) {
			XCA_WARN(tr("Not possible for the token-key Certificate '%1'").arg(cert->getIntName()));
			return;
		}
		p12 = new pki_pkcs12(cert->getIntName(), cert, privkey);
		pki_x509 *signer = cert->getSigner();
		while ((signer != NULL ) && (signer != cert) && chain) {
			p12->append_item(signer);
			cert = signer;
			signer = signer->getSigner();
		}
		p12->writePKCS12(file);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p12;
}

void db_x509::writePKCS7(pki_x509 *cert, XFile &file, exportType::etype type,
			QModelIndexList list) const
{
	pki_pkcs7 *p7 = NULL;

	try {
		p7 = new pki_pkcs7(QString());
		switch (type) {
		case exportType::PKCS7_chain:
			while (cert != NULL) {
				p7->append_item(cert);
				if (cert->getSigner() == cert)
					cert = NULL;
				else
					cert = cert->getSigner();
			}
			break;
		case exportType::PKCS7:
			p7->append_item(cert);
			break;
		case exportType::PKCS7_selected:
			foreach(QModelIndex idx, list) {
				cert = fromIndex<pki_x509>(idx);
				if (cert)
					p7->append_item(cert);
			}
			break;
		case exportType::PKCS7_unrevoked:
		case exportType::PKCS7_all:
			foreach(pki_x509 *cer, Store.getAll<pki_x509>()) {
				if ((type == exportType::PKCS7_all) ||
				    (!cer->isRevoked()))
					p7->append_item(cer);
			}
			break;
		default:
			exit(1);
		}
		p7->writeP7(file, false);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete p7;
}

void db_x509::certRenewal(QModelIndexList indexes)
{
	pki_x509 *oldcert = NULL, *signer = NULL, *newcert =NULL;
	pki_key *signkey = NULL;
	a1time time;
	a1int serial;
	CertExtend *dlg = NULL;
	x509rev r;
	bool doRevoke = false;

	if (indexes.size() == 0)
		return;
	QModelIndex idx = indexes[0];

	try {
		oldcert = fromIndex<pki_x509>(idx);
		if (!oldcert || !(signer = oldcert->getSigner()) ||
				!(signkey = signer->getRefKey()) ||
				signkey->isPubKey())
			return;
		bool renew_myself = signer == oldcert;
		CertExtend *dlg = new CertExtend(NULL,
					renew_myself ? NULL : signer);
		dlg->revoke->setEnabled(!renew_myself);
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		if (dlg->revoke->isChecked() && !renew_myself) {
			Revocation *revoke = new Revocation(indexes);
			doRevoke = revoke->exec();
			r = revoke->getRevocation();
			delete revoke;
		}
		foreach(idx, indexes) {
			oldcert = fromIndex<pki_x509>(idx);
			if (!oldcert)
				continue;
			newcert = new pki_x509(oldcert);
			newcert->pkiSource = renewed;
			serial = dlg->keepSerial->isChecked() ?
				oldcert->getSerial() : getUniqueSerial(signer);
			newcert->setRevoked(x509rev());

			// change date and serial
			newcert->setSerial(serial);
			newcert->setNotBefore(dlg->notBefore->getDate());
			a1time a;
			if (dlg->noWellDefinedExpDate->isChecked())
				a.setUndefined();
			else
				a = dlg->notAfter->getDate();

			newcert->setNotAfter(a);

			// and finally sign the cert
			newcert->sign(signkey, oldcert->getDigest());
			newcert = dynamic_cast<pki_x509 *>(insert(newcert));
			createSuccess(newcert);
		}
		if (doRevoke)
			do_revoke(indexes, r);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
		delete newcert;
	}
	delete dlg;
	emit columnsContentChanged();
}


void db_x509::revoke(QModelIndexList indexes)
{
	if (indexes.size() == 0)
		return;
	Revocation *revoke = new Revocation(indexes);
	if (revoke->exec()) {
		do_revoke(indexes, revoke->getRevocation());
	}
	emit columnsContentChanged();
}

void db_x509::do_revoke(QModelIndexList indexes, const x509rev &r)
{
	pki_x509 *parent = NULL, *cert, *iss;
	x509revList revlist;

	foreach(QModelIndex idx, indexes) {
		cert = fromIndex<pki_x509>(idx);
		if (!cert)
			continue;
		iss = cert->getSigner();
		if (parent == NULL) {
			parent = iss;
		} else if (parent != iss) {
			parent = NULL;
			break;
		}
	}
	if (!parent) {
		qWarning("%s(%d): Certs have different/no signer",
			 __func__, __LINE__);
	}
	foreach(QModelIndex idx, indexes) {
		cert = fromIndex<pki_x509>(idx);
		if (!cert)
			continue;
		x509rev rev(r);
		rev.setSerial(cert->getSerial());
		cert->setRevoked(rev);
		revlist << rev;
	}
	parent->mergeRevList(revlist);
}

void db_x509::unRevoke(QModelIndexList indexes)
{
	pki_x509 *parent = NULL;
	x509revList revList;

	foreach(QModelIndex idx, indexes) {
		pki_x509 *cert = fromIndex<pki_x509>(idx);
		if (!cert)
			continue;
		pki_x509 *iss = cert->getSigner();
		if (parent == NULL) {
			parent = iss;
		} else if (parent != iss) {
			parent = NULL;
			break;
		}
	}
	if (!parent) {
		qWarning("%s(%d): Certs have different/no issuer\n",
			 __func__, __LINE__);
		return;
	}
	revList = parent->getRevList();

	foreach(QModelIndex idx, indexes) {
		int i;
		x509rev rev;
		pki_x509 *cert = fromIndex<pki_x509>(idx);

		if (!cert)
			continue;

		cert->setRevoked(x509rev());
		rev.setSerial(cert->getSerial());
		i = revList.indexOf(rev);
		if (i != -1)
			revList.takeAt(i);
	}
	parent->setRevocations(revList);
	emit columnsContentChanged();
}

void db_x509::toCertificate(QModelIndex index)
{
	pki_x509 *cert = fromIndex<pki_x509>(index);
	if (!cert)
		return;
	if (!cert->getRefKey() && cert->getSigner() != cert)
		extractPubkey(index);
	cert->pkiSource = transformed;
	newCert(cert);
}

void db_x509::toRequest(QModelIndex idx)
{
	db_x509req *reqs = Database.model<db_x509req>();
	pki_x509 *cert = fromIndex<pki_x509>(idx);
	if (!cert)
		return;

	try {
		pki_x509req *req = new pki_x509req();
		check_oom(req);
		req->pkiSource = transformed;
		req->setIntName(cert->getIntName());
		req->createReq(cert->getRefKey(), cert->getSubject(),
			cert->getDigest(), cert->getV3ext());
		createSuccess(reqs->insert(req));
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void db_x509::toToken(QModelIndex idx, bool alwaysSelect)
{
	pki_x509 *cert = fromIndex<pki_x509>(idx);
	if (!cert)
		return;
	try {
		cert->store_token(alwaysSelect);
	} catch (errorEx &err) {
		XCA_ERROR(err);
        }
}

void db_x509::caProperties(QModelIndex idx)
{
	QStringList actions;
	Ui::CaProperties ui;

	pki_x509 *cert = fromIndex<pki_x509>(idx);
	if (!cert)
		return;

	QDialog *dlg = new QDialog(NULL);
	ui.setupUi(dlg);
	ui.days->setSuffix(QString(" ") + tr("days"));
	ui.days->setMaximum(1000000);
	ui.days->setValue(cert->getCrlDays());
	ui.image->setPixmap(QPixmap(":certImg"));

	QVariant tmplId = cert->getTemplateSqlId();
	pki_temp *templ = Store.lookupPki<pki_temp>(tmplId);

	ui.temp->insertPkiItems(Store.getAll<pki_temp>());
        ui.temp->setNullItem(tr("No template"));
	ui.temp->setCurrentIndex(0);
	if (templ)
		ui.temp->setCurrentPkiItem(templ);

	ui.certName->setTitle(cert->getIntName());
	mainwin->helpdlg->register_ctxhelp_button(dlg, "ca_properties");

	if (dlg->exec()) {
		XSqlQuery q;
		QSqlError e;
		Transaction;
		TransThrow();

		templ = ui.temp->currentPkiItem();
		tmplId = templ ? templ->getSqlItemId() : QVariant();

		cert->setTemplateSqlId(tmplId);
		cert->setCrlDays(ui.days->value());

		SQL_PREPARE(q, "UPDATE authority SET crlDays=?, "
				"template=? WHERE item=?");

		q.bindValue(0, cert->getCrlDays());
		q.bindValue(1, tmplId);
		q.bindValue(2, cert->getSqlItemId());
		AffectedItems(cert->getSqlItemId());
		q.exec();
	        TransDone(q.lastError());
		XCA_SQLERROR(q.lastError());
	}
	delete dlg;
}
