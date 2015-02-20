/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include "widgets/CrlDetail.h"
#include "widgets/NewCrl.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include <QInputDialog>
#include "ui_NewCrl.h"

db_crl::db_crl(QString db, MainWindow *mw)
	:db_x509name(db,mw)
{
	class_name = "crls";
	pkitype << revocation;
	updateHeaders();
	loadContainer();
}

dbheaderList db_crl::getHeaders()
{
	dbheaderList h = db_x509name::getHeaders();
	h <<	new dbheader(HD_crl_signer,	true, tr("Signer"),
			tr("Internal name of the signer")) <<
		new dbheader(HD_crl_revoked,	true, tr("No. revoked"),
			tr("Number of revoked certificates")) <<
		new dbheader(HD_crl_lastUpdate, false,tr("Last update")) <<
		new dbheader(HD_crl_nextUpdate,	true, tr("Next update")) <<
		new dbheader(HD_crl_crlnumber,	false,tr("CRL number"));
	return h;
}

pki_base *db_crl::newPKI(db_header_t *)
{
	return new pki_crl();
}

void db_crl::load()
{
	load_crl l;
	load_default(l);
}

void db_crl::revokeCerts(pki_crl *crl)
{
	x509revList revlist;

	if (!mainwin->certs)
		return;
	pki_x509 *signer = crl->getIssuer();
	if (!signer)
		return;
	revlist = crl->getRevList();
	signer->mergeRevList(revlist);
	foreach(x509rev revok, revlist) {
		pki_x509 *crt = signer->getBySerial(revok.getSerial());
		if (crt)
			crt->setRevoked(revok);
	}
}

void db_crl::removeSigner(pki_base *signer)
{
	FOR_ALL_pki(crl, pki_crl) {
		if (crl->getIssuer() == signer)
			crl->setIssuer(NULL);
	}
}

void db_crl::inToCont(pki_base *pki)
{
	pki_crl *crl = (pki_crl *)pki;
	if (crl->getIssuer() == NULL) {
		pki_x509 *iss = NULL, *last = NULL, *newest = NULL;
		x509name issname = crl->getSubject();
		while (1) {
			iss = mainwin->certs->getBySubject(issname, last);
			if (!iss)
				break;
			last = iss;
			pki_key *key = iss->getPubKey();
			if (!key)
				continue;

			if (!crl->verify(key)) {
				delete key;
				continue;
			}
			delete key;
			if (!newest) {
				newest = iss;
			} else {
				if (newest->getNotAfter() < iss->getNotAfter())
					newest = iss;
			}
		}
		crl->setIssuer(newest);
	}
	db_base::inToCont(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl *crl = (pki_crl *)item;
	pki_crl *oldcrl = (pki_crl *)getByReference(crl);
	if (oldcrl) {
		XCA_INFO(tr("The revocation list already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcrl->getIntName()));
		delete(crl);
		return NULL;
	}
	insertPKI(crl);
	revokeCerts(crl);
	pki_x509 *issuer = crl->getIssuer();
	if (issuer)
		mainwin->certs->updateAfterCrlLoad(issuer);
	return crl;
}

void db_crl::showPki(pki_base *pki)
{
	pki_crl *crl = (pki_crl *)pki;
	CrlDetail *dlg;

	dlg = new CrlDetail(mainwin);
	if (dlg) {
		dlg->setCrl(crl);
		connect( dlg->issuerIntName, SIGNAL( doubleClicked(QString) ),
		            mainwin->certs, SLOT( showItem(QString) ));
		dlg->exec();
		delete dlg;
	}
}

void db_crl::store(QModelIndex index)
{
	QList<exportType> types;

	if (!index.isValid())
		return;
	pki_crl *crl = static_cast<pki_crl*>(index.internalPointer());
	if (!crl)
		return;

	types << exportType(exportType::PEM, "pem", "PEM") <<
			exportType(exportType::DER, "der", "DER");
	ExportDialog *dlg = new ExportDialog(mainwin,
			tr("Revocation list export"),
			tr("CRL ( *.pem *.der *.crl )"), crl,
			MainWindow::revImg, types);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();

	try {
		crl->writeCrl(fname, dlg->type() == exportType::PEM);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
	delete dlg;
}

void db_crl::updateRevocations(pki_x509 *cert)
{
	x509name issname = cert->getSubject();
	x509revList revlist;
	pki_crl *latest = NULL;

	FOR_ALL_pki(crl, pki_crl) {
		if (!(issname == crl->getSubject()))
			continue;
		pki_key *key = cert->getPubKey();
		if (!key)
			continue;
		if (!crl->verify(key)) {
			delete key;
			continue;
		}
		delete key;
		pki_x509 *old = crl->getIssuer();
		if (!old) {
			crl->setIssuer(cert);
		} else if (old != cert) {
			if (old->getNotAfter() < cert->getNotAfter())
				crl->setIssuer(cert);
		}
		if (!latest || (latest->getCrlNumber() < crl->getCrlNumber()))
			latest = crl;
	}
	if (latest) {
		revlist = latest->getRevList();
		cert->mergeRevList(revlist);
		cert->setCrlNumber(latest->getCrlNumber());
	}
}

void db_crl::newItem()
{
	bool ok = false;
	QStringList sl = mainwin->certs->getSignerDesc();
	QString ca;

	switch (sl.size()) {
	case 0:
		XCA_INFO(tr("There are no CA certificates for CRL generation"));
		break;
	case 1:
		ca = sl[0];
		ok = true;
		break;
	default:
		ca = QInputDialog::getItem(mainwin, XCA_TITLE,
			tr("Select CA certificate"), sl, 0, false, &ok, 0);
	}
	if (!ok)
		return;

	pki_x509 *cert = static_cast<pki_x509*>
		(mainwin->certs->getByName(ca));
	newItem(cert);
}

void db_crl::newItem(pki_x509 *cert)
{
	if (!cert)
		return;

	pki_crl *crl = NULL;
	NewCrl *dlg = new NewCrl(mainwin, cert);

	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	try {
		x509v3ext e;
		X509V3_CTX ext_ctx;
		X509V3_set_ctx(&ext_ctx, cert->getCert(), NULL, NULL, NULL, 0);
		X509V3_set_ctx_nodb(&ext_ctx);

		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);

		bool withReason = dlg->revocationReasons->isChecked();
		foreach(x509rev rev, cert->revList)
			crl->addRev(rev, withReason);

		if (dlg->authKeyId->isChecked()) {
			crl->addV3ext(e.create(NID_authority_key_identifier,
				"keyid,issuer", &ext_ctx));
		}
		if (dlg->subAltName->isChecked()) {
			if (cert->hasExtension(NID_subject_alt_name)) {
				crl->addV3ext(e.create(NID_issuer_alt_name,
					"issuer:copy", &ext_ctx));
			}
		}
		if (dlg->setCrlNumber->isChecked()) {
			a1int num;
			num.setDec(dlg->crlNumber->text());
			crl->setCrlNumber(num);
			cert->setCrlNumber(num);
		}
		crl->setLastUpdate(dlg->lastUpdate->getDate());
		crl->setNextUpdate(dlg->nextUpdate->getDate());
		crl->sign(cert->getRefKey(), dlg->hashAlgo->currentHash());
		cert->setCrlExpiry(dlg->nextUpdate->getDate());
		mainwin->certs->updatePKI(cert);
		createSuccess(insert(crl));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (crl)
			delete crl;
		crl = NULL;
	}
	delete dlg;
	return;
}
