/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include "widgets/CrlDetail.h"
#include "widgets/NewCrl.h"
#include <QtGui/QMessageBox>
#include <QtGui/QContextMenuEvent>
#include "ui_NewCrl.h"

db_crl::db_crl(QString db, MainWindow *mw)
	:db_x509name(db,mw)
{
	allHeaders <<
		new dbheader(HD_crl_signer,	true, tr("Signer"),
			tr("Internal name of the signer")) <<
		new dbheader(HD_crl_revoked,	true, tr("No. revoked"),
			tr("Number of revoked certificates")) <<
		new dbheader(HD_crl_lastUpdate, false,tr("Last update")) <<
		new dbheader(HD_crl_nextUpdate,	true, tr("Next update")) <<
		new dbheader(HD_crl_crlnumber,	false,tr("CRL number"));

	class_name = "crls";
	pkitype << revokation;
	loadContainer();
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
	int numc, i;
	if (!mainwin->certs)
		return;
	x509rev revok;
	pki_x509 *signer = crl->getIssuer();
	if (!signer)
		return;
	numc = crl->numRev();
	for (i=0; i<numc; i++) {
		revok = crl->getRev(i);
		mainwin->certs->revokeCert(revok, signer);
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
		pki_x509 *iss = NULL, *last = NULL;
		x509name issname = crl->getSubject();
		while ((iss = mainwin->certs->getBySubject(issname, last)) != NULL) {
			pki_key *key = iss->getPubKey();
			if (key) {
				if (crl->verify(key)) {
					delete key;
					break;
				}
				delete key;
			}
			last = iss;
		}
		crl->setIssuer(iss);
	}
	revokeCerts(crl);
	db_base::inToCont(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl *crl = (pki_crl *)item;
	pki_crl *oldcrl = (pki_crl *)getByReference(crl);
	if (oldcrl) {
		QMessageBox::information(mainwin, XCA_TITLE,
			tr("The revokation list already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcrl->getIntName()));
		delete(crl);
		return NULL;
	}
	insertPKI(crl);
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

void db_crl::store()
{
	if (!currentIdx.isValid())
		return;

	pki_crl *crl = static_cast<pki_crl*>(currentIdx.internalPointer());
	if (!crl)
		return;

	QString fn = mainwin->getPath() + QDir::separator() +
		crl->getUnderlinedName() + ".pem";
	ExportDer *dlg = new ExportDer(mainwin, fn,
			tr("CRL ( *.pem *.der *.crl )"));
	dlg->image->setPixmap(*MainWindow::revImg);
	dlg->label->setText(tr("Revokation list export"));
	int dlgret = dlg->exec();

	if (!dlgret) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	bool pem = dlg->exportFormat->currentIndex() == 0 ? true : false;
	delete dlg;
	if (fname == "") {
		return;
	}
	mainwin->setPath(fname.mid(0, fname.lastIndexOf(QRegExp("[/\\\\]")) ));
	try {
		crl->writeCrl(fname, pem);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

pki_crl *db_crl::newItem(pki_x509 *cert)
{
	if (!cert)
		return NULL;

	pki_crl *crl = NULL;
	NewCrl *dlg = new NewCrl(mainwin, cert);

	if (!dlg->exec()) {
		delete dlg;
		return NULL;
	}
	try {
		x509v3ext e;
		X509V3_CTX ext_ctx;
		X509V3_set_ctx(&ext_ctx, cert->getCert(), NULL, NULL, NULL, 0);
		X509V3_set_ctx_nodb(&ext_ctx);

		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);

		QList<pki_x509*> list = mainwin->certs->getIssuedCerts(cert);
		bool reason = dlg->revokationReasons->isChecked();
		for (int i =0; i<list.size(); i++) {
			if (list.at(i)->isRevoked() ) {
				crl->addRev(list.at(i)->getRev(reason));
			}
		}

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
		if (dlg->crlNumber->isChecked()) {
			crl->setCrlNumber(cert->getIncCrlNumber());
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
	return crl;
}

void db_crl::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	currentIdx = index;
	QMenu *subExport;

	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("Clipboard"), this,
					SLOT(pem2clipboard()));
		subExport->addAction(tr("File"), this, SLOT(store()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
	}
	contextMenu(e, menu);
	currentIdx = QModelIndex();
	return;
}
