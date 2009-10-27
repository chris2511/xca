/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include "widgets/CrlDetail.h"
#include <qmessagebox.h>
#include <qevent.h>
#include "ui_NewCrl.h"

db_crl::db_crl(QString db, MainWindow *mw)
	:db_base(db,mw)
{
	headertext << tr("Name") << tr("Signer") << tr("Common name") <<
		tr("No. revoked") << tr("Next update");
	delete_txt = tr("Delete the revokation list(s)");
	view = mw->crlView;
	class_name = "crls";
	pkitype[0] = revokation;
	loadContainer();
}

pki_base *db_crl::newPKI(db_header_t *head)
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
	certs = mainwin->certs;
	if (! certs)
		return;
	x509rev revok;
	pki_x509 *rev;
	numc = crl->numRev();

	for (i=0; i<numc; i++) {
		revok = crl->getRev(i);
		rev = certs->getByIssSerial(crl->getIssuer(), revok.getSerial());
		if (rev) {
			rev->setRevoked(revok.getDate());
		}
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
	revokeCerts(crl);
	if (crl->getIssuer() == NULL) {
		pki_x509 *iss = NULL, *last = NULL;
		x509name issname = crl->getIssuerName();
		while ((iss = mainwin->certs->getBySubject(issname, last)) != NULL) {
			pki_key *key = iss->getPubKey();
			if (crl->verify(key)) {
				delete key;
				break;
			}
			delete key;
			last = iss;
		}
		crl->setIssuer(iss);
	}
	db_base::inToCont(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl *crl = (pki_crl *)item;
	pki_crl *oldcrl = (pki_crl *)getByReference(crl);
	if (oldcrl) {
		QMessageBox::information(NULL, XCA_TITLE,
			tr("The revokation list already exists in the database as") +
			":\n'" + oldcrl->getIntName() +
			"'\n" + tr("and so it was not imported"), "OK");
		delete(crl);
		return oldcrl;
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
	QList<pki_x509*> list;
	a1time time;
	pki_crl *crl = NULL;
	Ui::NewCrl ui;

	x509v3ext e;
	X509V3_CTX ext_ctx;
	X509V3_set_ctx(&ext_ctx, cert->getCert() , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));
	QDialog *dlg = new QDialog(mainwin);

	ui.setupUi(dlg);
	ui.image->setPixmap(*MainWindow::revImg);
	ui.lastUpdate->setDate(time.now());
	ui.nextUpdate->setDate(time.now(cert->getCrlDays() *60*60*24));

	ui.hashAlgo->setKeyType(cert->getRefKey()->getKeyType());

	if (cert->hasExtension(NID_subject_alt_name))
		ui.subAltName->setEnabled(true);
	else
		ui.subAltName->setEnabled(false);
	if (!dlg->exec()) {
		delete dlg;
		return NULL;
	}
	try {
		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);

		list = mainwin->certs->getIssuedCerts(cert);
		for (int i =0; i<list.size(); i++) {
			if (list.at(i)->isRevoked() ) {
				crl->addRev(list.at(i)->getRev());
			}
		}

		if (ui.authKeyId->isChecked()) {
			crl->addV3ext(e.create(NID_authority_key_identifier,
				"keyid,issuer", &ext_ctx));
		}
		if (ui.subAltName->isChecked()) {
			if (cert->hasExtension(NID_subject_alt_name)) {
				crl->addV3ext(e.create(NID_issuer_alt_name,
					"issuer:copy", &ext_ctx));
			}
		}

		crl->setLastUpdate(ui.lastUpdate->getDate());
		crl->setNextUpdate(ui.nextUpdate->getDate());
		cert->setCrlExpiry(ui.nextUpdate->getDate());

		crl->sign(cert->getRefKey(), ui.hashAlgo->currentHash());
		mainwin->certs->updatePKI(cert);
		insert(crl);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
	return crl;
}

void db_crl::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	currentIdx = index;

	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Export"), this, SLOT(store()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}
