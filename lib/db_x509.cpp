/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pass_info.h"
#include "widgets/CertDetail.h"
#include "widgets/CertExtend.h"
#include "widgets/ExportDialog.h"
#include "widgets/MainWindow.h"
#include "widgets/PwDialog.h"
#include "ui_TrustState.h"
#include "ui_CaProperties.h"
#include "ui_About.h"
#include "ui_Revoke.h"
#include <QtGui/QMessageBox>
#include <QtGui/QContextMenuEvent>
#include <QtGui/QAction>

bool db_x509::treeview = true;

db_x509::db_x509(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{
	rootItem->setIntName("[x509 root]");
	allHeaders <<
		new dbheader(HD_cert_ca,	true, tr("CA"),
			tr("reflects the basic Constraints extension")) <<
		new dbheader(HD_cert_serial,	true, tr("Serial")) <<
		new dbheader(HD_cert_md5fp,	false,tr("md5 fingerprint")) <<
		new dbheader(HD_cert_sha1fp,	false,tr("sha1 fingerprint")) <<
		new dbheader(HD_cert_notBefore, false,tr("Start date"),
				tr("not Before")) <<
		new dbheader(HD_cert_notAfter,	true, tr("Expiry date"),
				tr("not After")) <<
		new dbheader(HD_cert_trust,	false,tr("Trust state")) <<
		new dbheader(HD_cert_revokation,true, tr("Revocation"));

	class_name = "certificates";
	pkitype << x509;
	loadContainer();
}

pki_base *db_x509::newPKI(db_header_t *)
{
	return new pki_x509();
}

pki_x509 *db_x509::findSigner(pki_x509 *client)
{
	pki_x509 *signer;
	if ((signer = client->getSigner()) != NULL)
		return signer;
	// first check for self-signed
	if (client->verify(client)) {
		return client;
	}
	FOR_ALL_pki(pki, pki_x509) {
		if (client->verify(pki)) {
			return pki;
		}
	}
	return NULL;
}

QStringList db_x509::getPrivateDesc()
{
	QStringList x;
	FOR_ALL_pki(pki, pki_x509)
		if (pki->getRefKey())
			x.append(pki->getIntName());
	return x;
}

QStringList db_x509::getSignerDesc()
{
	QStringList x;
	FOR_ALL_pki(pki, pki_x509)
		if (pki->canSign())
			x.append(pki->getIntName());
	return x;
}


void db_x509::remFromCont(QModelIndex &idx)
{
	int row;
	pki_base *pki = static_cast<pki_base*>(currentIdx.internalPointer());
	pki_base *parent_pki = pki->getParent();
	row = pki->row();
	pki_x509 *child;
	pki_base *new_parent;
	QModelIndex new_idx;

	beginRemoveRows(parent(idx), row, row);
	parent_pki->takeChild(pki);
	endRemoveRows();

	while (pki->childCount()) {
		child = (pki_x509*)pki->childItems.takeFirst();
		child->delSigner((pki_x509*)pki);
		new_parent = findSigner(child);
		insertChild(new_parent, child);
	}
	mainwin->crls->removeSigner(pki);
	pki_key *pub = ((pki_x509*)pki)->getPubKey();
	if (pub) {
		if (mainwin->certs->findByPubKey(pub).count() == 0) {
			QList<pki_x509super *> reqs;
			reqs = mainwin->reqs->findByPubKey(pub);
			foreach(pki_x509super *r, reqs)
				((pki_x509req*)r)->setDone(false);
		}
		delete pub;
	}
	return;
}

void db_x509::changeView()
{
	pki_base *temproot;
	int rows = rowCount(QModelIndex());

	if (!rows)
		return;

	temproot = new pki_base();
	mainwin->certView->hide();
	mainwin->certView->setModel(NULL);
	beginRemoveRows(QModelIndex(), 0, rows -1);
	pki_base *pki = rootItem;
	pki_base *parent;
	while(pki->childCount()) {
		pki = pki->takeFirst();
		while(pki != rootItem && !pki->childCount()) {
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
		pki = temproot->takeFirst();
		inToCont(pki);
	}
	delete temproot;
	mainwin->certView->setModel(this);
	mainwin->certView->show();
}

void db_x509::calcEffTrust()
{
	FOR_ALL_pki(pki, pki_x509)
		pki->calcEffTrust();
}

void db_x509::inToCont(pki_base *pki)
{
	pki_x509 *cert = (pki_x509*)pki;
	cert->setParent(NULL);
	cert->delSigner(cert->getSigner());
	findSigner(cert);
	pki_base *root = cert->getSigner();
	if (!treeview || root == cert)
		root = rootItem;

	insertChild(root, pki);
	/* search for dangling certificates, which signer this is */
	FOR_ALL_pki(client, pki_x509) {
		if (client->getSigner() == NULL) {
			if (client->verify(cert) && treeview ) {
				int row = client->row();
				pki_x509 *s;
				/* recursive signing check */
				for (s = cert; s; s = s->getSigner()) {
					if (s == s->getSigner()) {
						s = NULL;
						break;
					}
					if (s == client) {
						printf("Recursive signing: '%s' <-> '%s'\n",
									CCHAR(client->getIntName()),
									CCHAR(cert->getIntName()));
						break;
					}
				}
				if (s)
					continue;
				beginRemoveRows(QModelIndex(), row, row);
				rootItem->takeChild(client);
				endRemoveRows();

				insertChild(pki, client);
				client = (pki_x509*)rootItem;
			}
		}
	}
	findKey(cert);
	pki_key *pub = cert->getPubKey();
	if (pub) {
		QList<pki_x509super *> reqs = mainwin->reqs->findByPubKey(pub);
		delete pub;

		foreach (pki_x509super *r, reqs) {
			((pki_x509req*)r)->setDone();
		}
	}
	calcEffTrust();
}


QList<pki_x509*> db_x509::getIssuedCerts(const pki_x509 *issuer)
{
	QList<pki_x509*> c;
	c.clear();
	if (!issuer)
		return c;
	FOR_ALL_pki(pki, pki_x509) {
		if (pki->getSigner() == issuer)
			c.append(pki);
	}
	return c;
}

pki_x509 *db_x509::getBySubject(const x509name &xname, pki_x509 *last)
{
	bool lastfound = false;
	if (last == NULL) lastfound = true;

	FOR_ALL_pki(pki, pki_x509) {
		if ( pki->getSubject() ==  xname) {
			if (lastfound) {
				return pki;
			}
		}
		if (pki == last) {
			lastfound = true;
		}
	}
	return NULL;
}

void db_x509::revokeCert(const x509rev &revok, const pki_x509 *iss)
{
	pki_x509 *crt = getByIssSerial(iss, revok.getSerial());
	if (crt)
		crt->setRevoked(revok.getDate());
}

pki_x509 *db_x509::getByIssSerial(const pki_x509 *issuer, const a1int &a)
{
	if (!issuer ) return NULL;
	FOR_ALL_pki(pki, pki_x509) {
		if ((pki->getSigner() == issuer) && (a == pki->getSerial()))
			return pki;
	}
	return NULL;
}

void db_x509::writeAllCerts(const QString fname, bool onlyTrusted)
{
	bool append = false;
	FOR_ALL_pki(pki, pki_x509) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		pki->writeCert(fname.toAscii(), true, append);
		append = true;
	}
}

QList<pki_x509*> db_x509::getCerts(bool onlyTrusted)
{
	QList<pki_x509*> c;
	c.clear();
	FOR_ALL_pki(pki, pki_x509) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		c.append(pki);
	}
	return c;
}

a1int db_x509::searchSerial(pki_x509 *signer)
{
	// returns the highest certificate serial
	// of all certs with this signer (itself too)
	a1int sserial, myserial;
	if (!signer)
		return sserial;
	sserial = signer->getCaSerial();
	FOR_ALL_pki(pki, pki_x509)
		if (pki->getSigner() == signer)  {
			myserial = pki->getSerial();
			if (sserial < myserial) {
				sserial = myserial;
			}
		}
	return sserial;
}

a1int db_x509::getUniqueSerial(pki_x509 *signer)
{
	// returnes an unused unique serial
	a1int serial;
	bool dup;
	do {
		dup = false;
		serial = signer->getIncCaSerial();
		FOR_ALL_pki(pki, pki_x509)
			if (pki->getSigner() == signer)  {
				if (serial == pki->getSerial()) {
					dup = true;
					break;
				}
			}
	} while (dup);
	if (!signer->usesRandomSerial())
		updatePKI(signer);
	return serial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = (pki_x509 *)item;
	pki_x509 *oldcert = (pki_x509 *)getByReference(cert);
	if (oldcert) {
		QMessageBox::information(mainwin, XCA_TITLE,
		tr("The certificate already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcert->getIntName()));
		delete(cert);
		return NULL;
	}
	cert->setCaSerial((cert->getSerial()));
	insertPKI(cert);
	a1int serial;

	// check the CA serial of the CA of this cert to avoid serial doubles
	if (cert->getSigner() != cert && cert->getSigner()) {
		serial = cert->getSerial();
		if (cert->getSigner()->getCaSerial() < ++serial ) {
			cert->getSigner()->setCaSerial(serial);
			updatePKI(cert->getSigner());
		}
	}

	// check CA serial of this cert
	serial = searchSerial(cert);
	if ( ++serial > cert->getCaSerial()) {
		cert->setCaSerial(serial);
	}
	updatePKI(cert);
	return cert;
}

void db_x509::load(void)
{
	load_cert c;
	load_default(c);
}

void db_x509::loadPKCS12()
{
	load_pkcs12 l;
	load_default(l);
}

void db_x509::loadPKCS7()
{
	load_pkcs7 l;
	load_default(l);
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
	dlg->defineSigner((pki_x509*)sigcert);
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
	dlg->defineSigner(sigcert);
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
		cert->setTrust(1);
#ifdef WG_QA_SERIAL
	} else if (dlg->selfQASignRB->isChecked()){
		Passwd pass;
		pass_info p(XCA_TITLE, tr("Please enter the new hexadecimal secret number for the QA process."));
#if 0
		ui.passA->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]*"),
				ui.passA));
		ui.passB->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]*"),
				ui.passB));
#endif
		if (PwDialog::execute(&p, &pass, true) != 1)
			throw errorEx(tr("The QA process has been terminated by the user."));
		signcert = cert;
		signkey = clientkey;
		serial.setHex(pass);
		cert->setTrust(2);
#endif
	} else {
		signcert = cert;
		signkey = clientkey;
		serial.setHex(dlg->serialNr->text());
		cert->setTrust(2);
	}

	dlg->initCtx(cert, signcert, NULL);
	// if we can not sign
	if (! signkey || signkey->isPubKey()) {
		free(cert);
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
	if (dlg->copyReqExtCB->isChecked() && dlg->fromReqCB->isChecked()) {
		extList el = req->getV3ext();
		int m = el.count();
		for (int i=0; i<m; i++)
			cert->addV3ext(el[i]);
	}

	// apply all extensions to the subject cert in the context
	dlg->getAllExt();

	const EVP_MD *hashAlgo = dlg->hashAlgo->currentHash();
#ifdef WG_QA_SERIAL
	if (dlg->selfQASignRB->isChecked()) {
		// sign the request intermediately in order to finally fill
		// up the cert_info substructure.
		cert->sign(signkey, hashAlgo);
		// now set the QA serial.
		cert->setSerial(cert->hashInfo(EVP_md5()));
	}
#endif
	// and finally sign the request
	cert->sign(signkey, hashAlgo);

	cert = (pki_x509*)insert(cert);
	createSuccess(cert);
	updatePKI(signcert);
	if (cert && clientkey->isToken()) {
		pki_scard *card = (pki_scard*)clientkey;
		if (QMessageBox::information(mainwin, XCA_TITLE,
			tr("Store the certificate to the key on the token '%1 (#%2)' ?").
			arg(card->getCardLabel()).arg(card->getSerial()),
			QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
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
		tempkey = NULL;
    }

    catch (errorEx &err) {
		mainwin->Error(err);
		delete cert;
		if (tempkey != NULL)
			delete(tempkey);
    }
}

void db_x509::showPki(pki_base *pki)
{
	pki_x509 *crt = (pki_x509 *)pki;
	CertDetail *dlg;
	dlg = new CertDetail(mainwin);
	if (dlg) {
		dlg->setCert(crt);
		connect( dlg->privKey, SIGNAL( doubleClicked(QString) ),
			mainwin->keys, SLOT( showItem(QString) ));
		connect( dlg->signature, SIGNAL( doubleClicked(QString) ),
			this, SLOT( showItem(QString) ));
		dlg->exec();
		delete dlg;
	}
}

void db_x509::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport, *subCa;
	QAction *itemReq, *itemRevoke, *itemExtend, *itemTrust, *action;
	QList<QAction*> scardItems;

	bool parentCanSign, canSign, hasScard;
	currentIdx = index;
	pki_key *privkey;

	pki_x509 *cert = static_cast<pki_x509*>(index.internalPointer());

	menu->addAction(tr("New Certificate"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	menu->addAction(tr("Import PKCS#12"), this, SLOT(loadPKCS12()));
	menu->addAction(tr("Import from PKCS#7"), this, SLOT(loadPKCS7()));
	if (index != QModelIndex()) {
		privkey = cert->getRefKey();
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		if (!privkey)
			menu->addAction(tr("Extract public Key"),
				this, SLOT(extractPubkey()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("Clipboard"), this,
					SLOT(pem2clipboard()));
		subExport->addAction(tr("File"), this, SLOT(store()));
		itemReq = subExport->addAction(tr("Request"),
				this, SLOT(toRequest()));
		scardItems += subExport->addAction(tr("Security token"),
				this, SLOT(toToken()));
		scardItems += subExport->addAction(tr("Other token"),
				this, SLOT(toOtherToken()));
		subExport->addAction(tr("Template"), this, SLOT(toTemplate()));
		subExport->addAction(tr("OpenSSL config"),
				this, SLOT(toOpenssl()));

		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
		scardItems += menu->addAction(
				tr("Delete from Security token"),
				this, SLOT(deleteFromToken()));
		itemTrust = menu->addAction(tr("Trust"), this,SLOT(setTrust()));
		menu->addSeparator();
		subCa = menu->addMenu(tr("CA"));
		subCa->addAction(tr("Properties"), this, SLOT(caProperties()));
		subCa->addAction(tr("Generate CRL"), this, SLOT(genCrl()));
#if 0
		QMenu *subP7 = menu->addMenu(tr("PKCS#7"));
		subP7->addAction(tr("Sign"), this, SLOT(signP7()));
		subP7->addAction(tr("Encrypt"), this, SLOT(encryptP7()));
#endif
		menu->addSeparator();
		itemExtend = menu->addAction(tr("Renewal"),
				this, SLOT(extendCert()));
		if (cert->isRevoked()) {
			itemRevoke = menu->addAction(tr("Unrevoke"),
				this, SLOT(unRevoke()));
			itemTrust->setEnabled(false);
		} else {
			itemRevoke = menu->addAction(tr("Revoke"),
				this, SLOT(revoke()));
		}
		parentCanSign = (cert->getSigner() && cert->getSigner()->canSign()
					&& (cert->getSigner() != cert));
		canSign = cert->canSign();
		hasScard = pkcs11::loaded();

		itemRevoke->setEnabled(parentCanSign);
		itemExtend->setEnabled(parentCanSign);
		subCa->setEnabled(canSign);
		itemReq->setEnabled(privkey && privkey->isPrivKey());

		foreach(action, scardItems)
			action->setEnabled(hasScard);
#if 0
		subP7->setEnabled(privkey);
#endif
	}
	contextMenu(e, menu);
	currentIdx = QModelIndex();
	return;
}


#define P7_ONLY 0
#define P7_CHAIN 1
#define P7_TRUSTED 2
#define P7_ALL 3

void db_x509::store()
{
	QStringList filt;
	bool pkcs8 = false, append;

	if (!currentIdx.isValid())
		return;

	pki_x509 *crt = static_cast<pki_x509*>(currentIdx.internalPointer());
	pki_x509 *oldcrt = NULL;
	if (!crt)
		return;
	pki_key *privkey = crt->getRefKey();
	QString fn = mainwin->getPath() + QDir::separator() +
			crt->getUnderlinedName() + ".crt";
	ExportCert *dlg = new ExportCert(mainwin, fn,
		(privkey && privkey->isPrivKey()) && !privkey->isToken());
	dlg->image->setPixmap(*MainWindow::certImg);
	int dlgret = dlg->exec();

	if (!dlgret) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	if (fname == "") {
		delete dlg;
		return;
	}
	mainwin->setPath(fname.mid(0, fname.lastIndexOf(QRegExp("[/\\\\]")) ));
	try {
		switch (dlg->exportFormat->currentIndex()) {
		case 0: // PEM
			crt->writeCert(fname,true,false);
			break;
		case 1: // PEM with chain
			append = false;
			while(crt && crt != oldcrt) {
				crt->writeCert(fname, true, append);
				append = true;
				oldcrt = crt;
				crt = crt->getSigner();
			}
			break;
		case 2: // PEM all trusted Certificates
			writeAllCerts(fname,true);
			break;
		case 3: // PEM all Certificates
			writeAllCerts(fname,false);
			break;
		case 4: // DER
			crt->writeCert(fname,false,false);
			break;
		case 5: // P7 lonely
			writePKCS7(crt,fname, P7_ONLY);
			break;
		case 6: // P7
			writePKCS7(crt,fname, P7_CHAIN);
			break;
		case 7: // P7
			writePKCS7(crt,fname, P7_TRUSTED);
			break;
		case 8: // P7
			writePKCS7(crt,fname, P7_ALL);
			break;
		case 9: // P12
			writePKCS12(crt,fname,false);
			break;
		case 10: // P12 + cert chain
			writePKCS12(crt,fname,true);
			break;
		case 12: // Certificate and Key in PKCS8 format
			pkcs8 = true;
		case 11: // Certificate and Key in PEM format for apache
			pki_evp *privkey = (pki_evp *)crt->getRefKey();
			if (!privkey || privkey->isPubKey()) {
				QMessageBox::warning(mainwin, XCA_TITLE,
					tr("There was no key found for the Certificate: '%1'").
					arg(crt->getIntName()));
				return;
			}
			if (privkey->isToken()) {
				QMessageBox::warning(mainwin, XCA_TITLE,
					tr("Not possible for a token key: '%1'").
					arg(crt->getIntName()));
                                return;
                        }

			if (pkcs8) {
				privkey->writePKCS8(fname, NULL, NULL, true);
			} else {
				privkey->writeKey(fname, NULL, NULL, true);
			}
			crt->writeCert(fname, true, true);
		}
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
	delete dlg;
}


void db_x509::writePKCS12(pki_x509 *cert, QString s, bool chain)
{
	QStringList filt;
    try {
		pki_evp *privkey = (pki_evp *)cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			QMessageBox::warning(mainwin, XCA_TITLE,
				tr("There was no key found for the Certificate: '%1'").arg(cert->getIntName()));
			return;
		}
		if (privkey->isToken()) {
			QMessageBox::warning(mainwin, XCA_TITLE,
				tr("Not possible for the token-key Certificate '%1'").
				arg(cert->getIntName()));
			return;
		}
		if (s.isEmpty())
			return;
		s = QDir::convertSeparators(s);
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

void db_x509::writePKCS7(pki_x509 *cert, QString s, int type)
{
    pki_pkcs7 *p7 = NULL;
    QList<pki_base> list;

    try {
		p7 =  new pki_pkcs7("");
		switch (type) {
		case P7_CHAIN:
			while (cert != NULL) {
				p7->addCert(cert);
				if (cert->getSigner() == cert)
					cert = NULL;
				else
					cert = cert->getSigner();
			}
			break;
		case P7_ONLY:
			p7->addCert(cert);
			break;
		case P7_TRUSTED:
		case P7_ALL:
			FOR_ALL_pki(cer, pki_x509) {
				if ((type == P7_ALL) || (cer->getTrust() == 2))
					p7->addCert(cer);
			}
		}
		p7->writeP7(s, false);
    }
    catch (errorEx &err) {
		MainWindow::Error(err);
    }
    if (p7 != NULL )
		delete p7;

}
# if 0
void ::signP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
				tr("There was no key found for the Certificate: ") +
			cert->getIntName());
		return;
	}
		filt.append("All Files ( * )");
	QString s="";
	QStringList slist;
	Q3FileDialog *dlg = new Q3FileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( Q3FileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->signFile(cert, s);
		p7->writeP7((s + ".p7s"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
	Qt::SocketError(err);
    }
}

void CertView::encryptP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
			tr("There was no key found for the Certificate: ") +
			cert->getIntName()) ;
		return;
	}
	filt.append("All Files ( * )");
	QString s="";
	QStringList slist;
	Q3FileDialog *dlg = new Q3FileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( Q3FileDialog::ExistingFiles );
	dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->encryptFile(cert, s);
		p7->writeP7((s + ".p7m"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
		Qt::SocketError(err);
    }
}
#endif

void db_x509::setMultiTrust(QAbstractItemView* view)
{
	QItemSelectionModel *selectionModel = view->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QString items;

	foreach(currentIdx, indexes) {
		   setTrust();
	}
	currentIdx = QModelIndex();
}

void db_x509::deleteFromToken()
{
	if (!currentIdx.isValid())
		return;
	pki_x509 *pki = static_cast<pki_x509*>(currentIdx.internalPointer());
	try {
		pki->deleteFromToken();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_x509::setTrust()
{
	int state, newstate = 0;
	Ui::TrustState ui;
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;
	QDialog *dlg = new QDialog(mainwin);
	ui.setupUi(dlg);

	ui.image->setPixmap(*MainWindow::certImg);
	state = cert->getTrust();
	if (cert->getSigner() == cert) {
		if (state == 1)
			state = 0;
		ui.trust1->setDisabled(true);
	}
	if (state == 0 ) ui.trust0->setChecked(true);
	if (state == 1 ) ui.trust1->setChecked(true);
	if (state == 2 ) ui.trust2->setChecked(true);
	ui.certName->setText(cert->getIntName());
	if (dlg->exec()) {
		if (ui.trust0->isChecked()) newstate = 0;
		if (ui.trust1->isChecked()) newstate = 1;
		if (ui.trust2->isChecked()) newstate = 2;
		if (newstate!=state) {
			cert->setTrust(newstate);
			updatePKI(cert);
		}
	}
	delete dlg;
}

void db_x509::extendCert()
{
	pki_x509 *oldcert = NULL, *signer = NULL, *newcert =NULL;
	pki_key *signkey = NULL;
	a1time time;
	a1int serial;
	CertExtend *dlg = NULL;

	try {
		oldcert = static_cast<pki_x509*>(currentIdx.internalPointer());
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
		newcert = new pki_x509(oldcert);
		serial = getUniqueSerial(signer);

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
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (newcert)
			delete newcert;
	}
	if (dlg)
		delete dlg;
}


void db_x509::revoke()
{
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;
	Ui::Revoke ui;
	QDialog *revoke = new QDialog(mainwin, 0);
	ui.setupUi(revoke);
	ui.invalid->setNow();
	ui.reason->addItems(x509rev::crlreasons());
	if (revoke->exec()) {
		cert->setRevoked(true, ui.invalid->getDate(),
					ui.reason->currentText());
		updatePKI(cert);
	}
}

void db_x509::unRevoke()
{
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;
	cert->setRevoked(false);
	updatePKI(cert);
}

void db_x509::genCrl()
{
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	mainwin->crls->newItem(cert);
}


void db_x509::toRequest()
{
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;

	try {
		pki_x509req *req = new pki_x509req();
		check_oom(req);
		req->setIntName(cert->getIntName());
		req->createReq(cert->getRefKey(), cert->getSubject(),
			cert->getRefKey()->getDefaultMD(), cert->getV3ext());
		createSuccess(mainwin->reqs->insert(req));
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void db_x509::myToToken(bool alwaysSelect)
{
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;
	try {
		cert->store_token(alwaysSelect);
	} catch (errorEx &err) {
		mainwin->Error(err);
        }
}

void db_x509::toToken()
{
	myToToken(false);
}

void db_x509::toOtherToken()
{
	myToToken(true);
}

void db_x509::caProperties()
{
	Ui::CaProperties ui;
	int i;
	pki_x509 *cert = static_cast<pki_x509*>(currentIdx.internalPointer());
	if (!cert)
		return;
	QDialog *dlg = new QDialog(mainwin);
	ui.setupUi(dlg);
	ui.serial->setText(cert->getCaSerial().toHex());
	ui.serial->setDisabled(cert->usesRandomSerial());
	ui.randomSerial->setChecked(cert->usesRandomSerial());
	ui.days->setSuffix(tr(" days"));
	ui.days->setMaximum(1000000);
	ui.days->setValue(cert->getCrlDays());
	ui.image->setPixmap(*MainWindow::certImg);
	QString templ = cert->getTemplate();
	QStringList tempList = mainwin->temps->getDesc();
	for (i=0; i<tempList.count(); i++) {
		if (tempList[i] == templ)
			break;
	}
	ui.temp->addItems(tempList);
	ui.temp->setCurrentIndex(i);
	ui.certName->setTitle(cert->getIntName());
	if (dlg->exec()) {
		a1int nserial;
		cert->setCrlDays(ui.days->value());
		nserial.setHex(ui.serial->text());
		cert->setCaSerial(nserial);
		cert->setTemplate(ui.temp->currentText());
		cert->setUseRandomSerial(ui.randomSerial->isChecked());
		updatePKI(cert);
	}
	delete dlg;
}

