/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pass_info.h"
#include "widgets/CertExtend.h"
#include "widgets/ExportDialog.h"
#include "widgets/MainWindow.h"
#include "widgets/PwDialog.h"
#include "widgets/RevocationList.h"
#include "ui_CaProperties.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include <QAction>

#include <openssl/rand.h>

bool db_x509::treeview = true;

db_x509::db_x509(MainWindow *mw)
	:db_x509super(mw)
{
	class_name = "certificates";
	sqlHashTable = "certs";
	pkitype << x509;
	updateHeaders();
	loadContainer();
	dereferenceIssuer();
}

void db_x509::dereferenceIssuer()
{
	XSqlQuery q("SELECT item, issuer FROM certs");
	while (q.next()) {
		pki_base *root = rootItem;
		pki_x509 *cert = static_cast<pki_x509*>(
					lookupPki(q.value(0)));
		pki_x509 *issuer = static_cast<pki_x509*>(
					lookupPki(q.value(1)));
		if (cert && issuer) {
			cert->setSigner(issuer);
			if (cert != issuer)
				root = issuer;
		}
		if (cert && cert->getParent() != root) {
			fprintf(stderr, "MOVE '%s' from '%s' to '%s'\n",
				CCHAR(cert->getIntName()),
				CCHAR(cert->getParent()->getIntName()),
				CCHAR(root->getIntName()));
			cert->getParent()->takeChild(cert);
			insertChild(root, cert);
		}
	}
}

dbheaderList db_x509::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_cert_ca,	true, tr("CA"),
			tr("reflects the basic Constraints extension")) <<
		new dbheader(HD_cert_serial,	true, tr("Serial")) <<
		new dbheader(HD_cert_md5fp,	false,tr("MD5 fingerprint")) <<
		new dbheader(HD_cert_sha1fp,	false,tr("SHA1 fingerprint")) <<
		new dbheader(HD_cert_sha256fp,	false,tr("SHA256 fingerprint")) <<
		new dbheader(HD_cert_notBefore, false,tr("Start date"),
				tr("Not before")) <<
		new dbheader(HD_cert_notAfter,	true, tr("Expiry date"),
				tr("Not after")) <<
		new dbheader(HD_cert_revocation,false, tr("Revocation")) <<
		new dbheader(HD_cert_crl_expire,true, tr("CRL Expiration"));
	return h;
}

pki_base *db_x509::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_x509();
}

QList<pki_base *> db_x509::getAllIssuers()
{
	/* Select X509 CA certificates with available private key */
	return sqlSELECTpki("SELECT x509super.item FROM x509super "
		"JOIN private_keys ON x509super.key = private_keys.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1");
}

void db_x509::remFromCont(QModelIndex &idx)
{
	db_x509super::remFromCont(idx);
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	pki_x509 *child;
	pki_base *new_parent;
	QModelIndex new_idx;

	while (pki->childCount()) {
		child = (pki_x509*)pki->childItems.takeFirst();
		child->delSigner((pki_x509*)pki);
		new_parent = child->findIssuer();
		insertChild(new_parent, child);
	}
	mainwin->crls->removeSigner(pki);
}

void db_x509::changeView()
{
	pki_base *temproot;
	int rows = rowCount(QModelIndex());

	if (!rows)
		return;

	temproot = new pki_base();
	beginRemoveRows(QModelIndex(), 0, rows -1);
	pki_base *pki = rootItem;
	pki_base *parent;
	while (pki->childCount()) {
		pki = pki->takeFirst();
		while (pki != rootItem && !pki->childCount()) {
			parent = pki->getParent();
			temproot->append(pki);
			pki = parent;
		}
	}
	endRemoveRows();

	treeview = !treeview;
	if (treeview)
		mainwin->BNviewState->setText(tr("Plain View"));
	else
		mainwin->BNviewState->setText(tr("Tree View"));

	while ((temproot->childCount())) {
		pki_base *parent = rootItem;
		pki = temproot->takeFirst();
		if (treeview)
			parent = static_cast<pki_x509*>(pki)->getSigner();
		insertChild(parent, pki);
	}
	delete temproot;
}

static bool recursiveSigning(pki_x509 *cert, pki_x509 *client)
{
	/* recursive signing check */
	for (pki_x509 *s = cert->getSigner(); s; s = s->getSigner()) {
		if (s == s->getSigner()) {
			return false;
		}
		if (s == client) {
			printf("Recursive signing: '%s' <-> '%s'\n",
				CCHAR(s->getIntName()),
				CCHAR(cert->getIntName()));
			return true;
		}
	}
	return false;
}

void db_x509::inToCont(pki_base *pki)
{
	pki_x509 *cert = (pki_x509*)pki;
	cert->setParent(NULL);
	pki_base *root = cert->getSigner();
	if (!treeview || root == cert || root == NULL)
		root = rootItem;

	insertChild(root, cert);

	QList<pki_x509 *> childs;
	QList<pki_base *> items;
	unsigned pubhash = cert->pubHash();
	unsigned namehash = cert->getSubject().hashNum();

	/* Search for another certificate (name and key)
	 * and use its childs if we are newer */
	items = sqlSELECTpki(
		"SELECT x509super.item FROM x509super "
		"JOIN public_keys ON x509super.key = public_keys.item "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1 AND x509super.subj_hash=? "
		"AND x509super.key_hash=?",
			QList<QVariant>() << namehash << pubhash);
	foreach(pki_base *b, items) {
		pki_x509 *other = static_cast<pki_x509*>(b);
		if (other == cert)
			continue;
		if (!other->compareNameAndKey(cert))
			continue;
		if (cert->getNotAfter() < other->getNotAfter())
			continue;
		foreach(pki_base *b, other->childItems) {
			pki_x509 *child = static_cast<pki_x509*>(b);
			child->delSigner(other);
			childs << child;
		}
	}
	/* Search rootItem childs, whether they are ours */
	foreach(pki_base *b, rootItem->childItems) {
		pki_x509 *child = static_cast<pki_x509*>(b);
		if (child == cert || child->getSigner() == child)
			continue;
		if (child->verify_only(cert))
			childs << child;
	}
	/* move collected childs to us */
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE certs SET issuer=? WHERE item=?");
	q.bindValue(0, cert->getSqlItemId());
	foreach(pki_x509 *child, childs) {
		int row;
		if (recursiveSigning(cert, child))
			continue;
		if (!child->verify(cert))
			continue;
		row = child->row();
		if (treeview) {
			beginRemoveRows(index(child->getParent()), row, row);
			child->getParent()->takeChild(child);
			endRemoveRows();
			insertChild(cert, child);
		}
		q.bindValue(1, child->getSqlItemId());
		q.exec();
		mainwin->dbSqlError(q.lastError());
	}
	/* Update CRLs */
	items = sqlSELECTpki( "SELECT item FROM crls WHERE iss_hash=?",
			QList<QVariant>() << namehash);
	SQL_PREPARE(q, "UPDATE crls SET issuer=? WHERE item=?");
	foreach(pki_base *b, items) {
		pki_crl *crl = static_cast<pki_crl*>(b);
		crl->verify(cert);
		cert = crl->getIssuer();
		if (!cert)
			continue;
		q.bindValue(0, cert->getSqlItemId());
		q.bindValue(1, crl->getSqlItemId());
		q.exec();
		mainwin->dbSqlError(q.lastError());
	}
}

void db_x509::writeAllCerts(const QString fname, bool unrevoked)
{
	bool append = false;
	FOR_ALL_pki(pki, pki_x509) {
		if (unrevoked && pki->isRevoked())
			 continue;
		pki->writeCert(fname.toLatin1(), true, append);
		append = true;
	}
}

QList<pki_x509*> db_x509::getCerts(bool unrevoked)
{
	QList<pki_x509*> c;
	c.clear();
	FOR_ALL_pki(pki, pki_x509) {
		if (unrevoked && pki->isRevoked())
			continue;
		c.append(pki);
	}
	return c;
}

void db_x509::writeIndex(const QString fname, bool hierarchy)
{
	bool append = false;
	if (hierarchy) {
		FOR_ALL_pki(pki, pki_x509) {
			if (pki->childCount()) {

				QString newfname = fname + "." + pki->getIntName().replace(QRegExp("[^a-zA-Z0-9]"),QString(""));;

				append = false;
				foreach(pki_base *_child, pki->childItems) {
					pki_x509 *child = static_cast<pki_x509*>(_child);
					child->writeIndexEntry(newfname, append);
					append = true;
				}
			}
		}
	} else {
		FOR_ALL_pki(pki, pki_x509) {
			pki->writeIndexEntry(fname, append);
			append = true;
		}
	}
}

#define SERIAL_LEN 8
static a1int randomSerial()
{
	unsigned char buf[SERIAL_LEN];
	RAND_bytes(buf, SERIAL_LEN);
	a1int serial;
	serial.setRaw(buf, SERIAL_LEN);
	return serial;
}

a1int db_x509::getUniqueSerial(pki_x509 *signer)
{
	// returns an unused unique serial
	a1int serial;
	x509rev rev;
	while (true) {
		serial = randomSerial();
		if (!signer)
			break;
		rev.setSerial(serial);
		if (signer->revList.contains(rev))
			continue;
		if (signer->getBySerial(serial))
			continue;
		break;
	}
	return serial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = (pki_x509 *)item;
	pki_x509 *oldcert = (pki_x509 *)getByReference(cert);
	if (oldcert) {
		XCA_INFO(tr("The certificate already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcert->getIntName()));
		delete(cert);
		return NULL;
	}
	insertPKI(cert);
	return cert;
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
	if (index == QModelIndex())
		return NULL;
	return static_cast<pki_x509*>(index.internalPointer());
}

void db_x509::newItem()
{
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);
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
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);
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
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);
	dlg->setCert();
	dlg->defineTemplate(temp);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_x509 *cert)
{
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);
	dlg->setCert();
	dlg->fromX509super(cert, false);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL, *tempkey = NULL;
	a1int serial;
	x509name subject;
	QString intname;

    try {

	// Step 1 - Subject and key
	if (!dlg->fromReqCB->isChecked()) {
		clientkey = dlg->getSelectedKey();
		if (!clientkey)
			return;
		subject = dlg->getX509name();
		intname = dlg->description->text();
	} else {
		// A PKCS#10 Request was selected
		req = dlg->getSelectedReq();
		if (!req)
			return;
		clientkey = req->getRefKey();
		if (clientkey == NULL) {
			clientkey = req->getPubKey();
			tempkey = clientkey;
		}
		if (dlg->reqSubChange->isChecked())
			subject = dlg->getX509name();
		else
			subject = req->getSubject();
		intname = req->getIntName();
	}
	if (clientkey == NULL)
		throw errorEx(tr("Invalid public key"));
	// initially create cert
	cert = new pki_x509();
	cert->setIntName(intname);
	cert->setSubject(subject);
	cert->setPubKey(clientkey);

	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = dlg->getSelectedSigner();
		if (!signcert)
			return;
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
	cert = (pki_x509*)insert(cert);
	createSuccess(cert);
	if (cert && clientkey->isToken()) {
		pki_scard *card = (pki_scard*)clientkey;
		if (XCA_YESNO(tr("Store the certificate to the key on the token '%1 (#%2)' ?").
			arg(card->getCardLabel()).arg(card->getSerial())))
		{
			try {
				cert->store_token(false);
			} catch (errorEx &err) {
				mainwin->Error(err);
			}
		}
	}
	if (tempkey != NULL)
		delete(tempkey);
    }

    catch (errorEx &err) {
		mainwin->Error(err);
		delete cert;
		if (tempkey != NULL)
			delete(tempkey);
    }
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
	bool append, chain;
	QList<exportType> types, usual;

	if (list.size() == 0)
		return;

	pki_x509 *crt = static_cast<pki_x509*>(list[0].internalPointer());
	pki_x509 *oldcrt = NULL;
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
			usual << exportType(exportType::PKCS12_chain, "p12",
				tr("PKCS#12 chain"));
			types << exportType(exportType::PKCS12, "p12",
				"PKCS #12");
		} else {
			usual << exportType(exportType::PKCS12, "p12",
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

	types = usual << exportType() << types;
	ExportDialog *dlg = new ExportDialog(mainwin, tr("Certificate export"),
		tr("X509 Certificates ( *.pem *.cer *.crt *.p12 *.p7b )"), crt,
		MainWindow::certImg, types);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	enum exportType::etype type = dlg->type();
	delete dlg;
	try {
		switch (type) {
		case exportType::PEM:
			crt->writeCert(fname, true, false);
			break;
		case exportType::PEM_chain:
			append = false;
			while(crt && crt != oldcrt) {
				crt->writeCert(fname, true, append);
				append = true;
				oldcrt = crt;
				crt = crt->getSigner();
			}
			break;
		case exportType::PEM_selected:
			append = false;
			foreach(QModelIndex idx, list) {
				crt = static_cast<pki_x509*>(idx.internalPointer());
				crt->writeCert(fname, true, append);
				append = true;
			}
			break;
		case exportType::PEM_unrevoked:
			writeAllCerts(fname,true);
			break;
		case exportType::PEM_all:
			writeAllCerts(fname,false);
			break;
		case exportType::DER:
			crt->writeCert(fname,false,false);
			break;
		case exportType::PKCS7:
		case exportType::PKCS7_chain:
		case exportType::PKCS7_unrevoked:
		case exportType::PKCS7_selected:
		case exportType::PKCS7_all:
			writePKCS7(crt, fname, type, list);
			break;
		case exportType::PKCS12:
			writePKCS12(crt, fname,false);
			break;
		case exportType::PKCS12_chain:
			writePKCS12(crt, fname,true);
			break;
		case exportType::PEM_cert_pk8:
		case exportType::PEM_cert_key:
			pkey = (pki_evp *)crt->getRefKey();
			if (!pkey || pkey->isPubKey()) {
				XCA_WARN(tr("There was no key found for the Certificate: '%1'").
					arg(crt->getIntName()));
				return;
			}
			if (pkey->isToken()) {
				XCA_WARN(tr("Not possible for a token key: '%1'").
					arg(crt->getIntName()));
                                return;
                        }

			if (type == exportType::PEM_cert_pk8) {
				pkey->writePKCS8(fname, EVP_des_ede3_cbc(),
						PwDialog::pwCallback, true);
			} else {
				pkey->writeKey(fname, NULL, NULL, true);
			}
			crt->writeCert(fname, true, true);
			break;
		case exportType::Index:
			append = false;
			foreach(QModelIndex idx, list) {
				crt = static_cast<pki_x509*>(idx.internalPointer());
				crt->writeIndexEntry(fname, append);
				append = true;
			}
			break;
		default:
			exit(1);
		}
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}


void db_x509::writePKCS12(pki_x509 *cert, QString s, bool chain)
{
	QStringList filt;
    try {
		pki_evp *privkey = (pki_evp *)cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			XCA_WARN(tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
			return;
		}
		if (privkey->isToken()) {
			XCA_WARN(tr("Not possible for the token-key Certificate '%1'").
				arg(cert->getIntName()));
			return;
		}
		if (s.isEmpty())
			return;
		s = nativeSeparator(s);
		pki_pkcs12 *p12 = new pki_pkcs12(cert->getIntName(), cert, privkey);
		pki_x509 *signer = cert->getSigner();
		while ((signer != NULL ) && (signer != cert) && chain) {
			p12->addCaCert(signer);
			cert=signer;
			signer=signer->getSigner();
		}
		p12->writePKCS12(s);
		delete p12;
    }
    catch (errorEx &err) {
		MainWindow::Error(err);
    }
}

void db_x509::writePKCS7(pki_x509 *cert, QString s, exportType::etype type,
			QModelIndexList list)
{
	pki_pkcs7 *p7 = NULL;

	try {
		p7 = new pki_pkcs7("");
		switch (type) {
		case exportType::PKCS7_chain:
			while (cert != NULL) {
				p7->addCert(cert);
				if (cert->getSigner() == cert)
					cert = NULL;
				else
					cert = cert->getSigner();
			}
			break;
		case exportType::PKCS7:
			p7->addCert(cert);
			break;
		case exportType::PKCS7_selected:
			foreach(QModelIndex idx, list) {
				cert = static_cast<pki_x509*>(idx.internalPointer());
				p7->addCert(cert);
			}
			break;
		case exportType::PKCS7_unrevoked:
		case exportType::PKCS7_all:
			FOR_ALL_pki(cer, pki_x509) {
				if ((type == exportType::PKCS7_all) ||
				    (!cer->isRevoked()))
					p7->addCert(cer);
			}
			break;
		default:
			exit(1);
		}
		p7->writeP7(s, false);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
	if (p7 != NULL )
		delete p7;

}

void db_x509::storeRevocations(pki_x509 *cert)
{
	QSqlDatabase *db = mainwin->getDb();
	if (db->transaction()) {
		QSqlError e;
		e = cert->revList.sqlUpdate(cert->getSqlItemId());
		if (e.isValid())
			db->rollback();
		else
			db->commit();
	}
	cert->revList.merged = false;
}

void db_x509::manageRevocations(QModelIndex idx)
{
	pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
	if (!cert)
		return;
	RevocationList *dlg = new RevocationList(mainwin);
	dlg->setRevList(cert->revList, cert);
	connect(dlg, SIGNAL(genCRL(pki_x509*)),
		mainwin->crls, SLOT(newItem(pki_x509*)));
	if (dlg->exec()) {
		cert->setRevocations(dlg->getRevList());
		storeRevocations(cert);
		emit columnsContentChanged();
	}
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
		oldcert = static_cast<pki_x509*>(idx.internalPointer());
		if (!oldcert ||
				!(signer = oldcert->getSigner()) ||
				!(signkey = signer->getRefKey()) ||
				signkey->isPubKey())
			return;

		CertExtend *dlg = new CertExtend(mainwin, signer);
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		if (dlg->revoke->isChecked()) {
			Revocation *revoke = new Revocation(mainwin, indexes);
			doRevoke = revoke->exec();
			r = revoke->getRevocation();
			delete revoke;
		}
		foreach(idx, indexes) {
			oldcert = static_cast<pki_x509*>
					(idx.internalPointer());
			newcert = new pki_x509(oldcert);
			serial = getUniqueSerial(signer);
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
			newcert = (pki_x509 *)insert(newcert);
			createSuccess(newcert);
		}
		if (doRevoke)
			do_revoke(indexes, r);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (newcert)
			delete newcert;
	}
	if (dlg)
		delete dlg;
	emit columnsContentChanged();
}


void db_x509::revoke(QModelIndexList indexes)
{
	if (indexes.size() == 0)
		return;
	Revocation *revoke = new Revocation(mainwin, indexes);
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
		cert = static_cast<pki_x509*>(idx.internalPointer());
		iss = cert->getSigner();
		if (parent == NULL) {
			parent = iss;
		} else if (parent != iss) {
			parent = NULL;
			break;
		}
	}
	if (!parent) {
		qWarning("%s(%d): Certs have different/no signer\n",
			 __func__, __LINE__);
	}
	foreach(QModelIndex idx, indexes) {
		pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
		x509rev rev(r);
		rev.setSerial(cert->getSerial());
		cert->setRevoked(rev);
		revlist << rev;
	}
	parent->mergeRevList(revlist);
	storeRevocations(parent);
}

void db_x509::unRevoke(QModelIndexList indexes)
{
	pki_x509 *parent = NULL;
	foreach(QModelIndex idx, indexes) {
		pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
		if (!cert)
			return;
		pki_x509 *iss = cert->getSigner();
		if (parent == NULL) {
			parent = iss;
		} else if (parent != iss) {
			parent = NULL;
			break;
		}
	}
	if (!parent) {
		qWarning("%s(%d): Certs have different/no signer\n",
			 __func__, __LINE__);
	}
	foreach(QModelIndex idx, indexes) {
		pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
		int i;
		x509rev rev;

		cert->setRevoked(x509rev());
		rev.setSerial(cert->getSerial());
		i = parent->revList.indexOf(rev);
		if (i != -1)
			parent->revList.takeAt(i);
	}
	storeRevocations(parent);
	emit columnsContentChanged();
}

void db_x509::toCertificate(QModelIndex index)
{
	pki_x509 *cert = static_cast<pki_x509*>(index.internalPointer());
	if (!cert)
		return;
	if (!cert->getRefKey() && cert->getSigner() != cert)
		extractPubkey(index);
	cert->pkiSource = transformed;
	newCert(cert);
}

void db_x509::toRequest(QModelIndex idx)
{
	pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
	if (!cert)
		return;

	try {
		pki_x509req *req = new pki_x509req();
		check_oom(req);
		req->pkiSource = transformed;
		req->setIntName(cert->getIntName());
		req->createReq(cert->getRefKey(), cert->getSubject(),
			cert->getDigest(), cert->getV3ext());
		createSuccess(mainwin->reqs->insert(req));
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_x509::toToken(QModelIndex idx, bool alwaysSelect)
{
	pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
	if (!cert)
		return;
	try {
		cert->store_token(alwaysSelect);
	} catch (errorEx &err) {
		mainwin->Error(err);
        }
}

void db_x509::caProperties(QModelIndex idx)
{
	QStringList actions;
	Ui::CaProperties ui;
	QString policy;
	int i;

	pki_x509 *cert = static_cast<pki_x509*>(idx.internalPointer());
	if (!cert)
		return;

	QDialog *dlg = new QDialog(mainwin);
	ui.setupUi(dlg);
	ui.days->setSuffix(tr(" days"));
	ui.days->setMaximum(1000000);
	ui.days->setValue(cert->getCrlDays());
	ui.image->setPixmap(*MainWindow::certImg);

	QVariant tmplId = cert->getTemplateSqlId();
	pki_base *templ = mainwin->temps->lookupPki(tmplId);

	ui.temp->insertPkiItems(mainwin->temps->getAll());
        ui.temp->setNullItem(tr("No template"));
	ui.temp->setCurrentIndex(0);
	if (templ)
		ui.temp->setCurrentPkiItem(templ);

	ui.certName->setTitle(cert->getIntName());

	QStringList sl;
	sl << tr("Type") << tr("Action");
	ui.subjectManager->initCols(sl);

	sl.clear();
	foreach(int nid, *MainWindow::dn_nid)
                sl << QString(OBJ_nid2ln(nid));
	ui.subjectManager->setKeys(sl, 0);

	actions << "From request" << "From template" << "Erase" << "Match";
	ui.subjectManager->setKeys(actions, 1);

	sl = cert->getDnPolicy().split(",");

	printf("Policy: '%s'\n", CCHAR(cert->getDnPolicy()));
	ui.subjectManager->deleteAllRows();
	foreach(policy, sl) {
		QStringList polKV, l = policy.split(":");
		if (l.size() != 2)
			continue;
		printf("Option: %d\n", l[1].toInt());
		polKV << QString(OBJ_nid2ln(OBJ_sn2nid(CCHAR(l[0]))));
		polKV << actions[l[1].toInt()];
		ui.subjectManager->addRow(polKV);
        }

	if (dlg->exec()) {
		int rows = ui.subjectManager->rowCount();
		XSqlQuery q;
		QSqlError e;
		templ = ui.temp->currentPkiItem();
		tmplId = templ ? templ->getSqlItemId() : QVariant();

		sl.clear();
		for (i=0; i<rows; i++) {
			QStringList l = ui.subjectManager->getRow(i);
			int idx = actions.indexOf(l[1]);
			if (idx == -1)
				continue;
			sl << QString("%1:%2")
				.arg(OBJ_nid2sn(OBJ_ln2nid(CCHAR(l[0]))))
				.arg(idx);
                }
		policy = sl.join(",");
		cert->setTemplateSqlId(tmplId);
		cert->setCrlDays(ui.days->value());
		cert->setDnPolicy(policy);

		SQL_PREPARE(q, "UPDATE authority SET crlDays=?, dnPolicy=?, "
				"template=? WHERE item=?");

		q.bindValue(0, cert->getCrlDays());
		q.bindValue(1, policy);
		q.bindValue(2, tmplId);
		q.bindValue(3, cert->getSqlItemId());
		q.exec();
		mainwin->dbSqlError(q.lastError());
	}
	delete dlg;
}
