/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "db_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include "widgets/CrlDetail.h"
#include <Qt/qmessagebox.h>
#include <Qt/qevent.h>
#include <ui/NewCrl.h>

db_crl::db_crl(QString db, MainWindow *mw)
	:db_base(db,mw)
{
	delete rootItem;
	rootItem = newPKI();
	headertext << "Name" << "Common name" << "revoked";
	delete_txt = tr("Delete the revokation list(s)");
	view = mw->crlView;
	class_name = "crls";
	loadContainer();
}

pki_base *db_crl::newPKI(){
	return new pki_crl();
}

void db_crl::preprocess()
{
#if 0
	if ( container.isEmpty() ) return ;
	FOR_ALL_pki(crl, pki_crl) {
		pki_x509 *iss = MainWindow::certs->getBySubject(crl->getIssuerName());
		crl->setIssuer(iss);
		revokeCerts(crl);
	}
#endif
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

void db_crl::inToCont(pki_base *pki)
{
	revokeCerts((pki_crl *)pki);
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

void db_crl::showItem(const QModelIndex &index)
{
	pki_crl *crl = static_cast<pki_crl*>(index.internalPointer());
	CrlDetail *dlg;

	dlg = new CrlDetail(mainwin);
	if (dlg) {
		dlg->setCrl(crl);
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

	ExportDer *dlg = new ExportDer(mainwin, crl->getUnderlinedName() + ".pem",
			  mainwin->getPath(), tr("CRL ( *.pem *.der *.crl )") );
	dlg->image->setPixmap(*MainWindow::revImg);
	dlg->label->setText(tr("Revokation list export"));
	int dlgret = dlg->exec();

	if (!dlgret) {
		delete dlg;
		return;
	}
	mainwin->setPath(dlg->dirPath);
	QString fname = dlg->filename->text();
	bool pem = dlg->exportFormat->currentIndex() == 0 ? true : false;
	delete dlg;
	if (fname == "") {
		return;
	}
	crl->writeCrl(fname, pem);
}

pki_crl *db_crl::newItem(pki_x509 *cert)
{
	if (!cert)
		return NULL;
	QList<pki_x509*> list;
	a1time time;
	pki_crl *crl = NULL;
	Ui::NewCrl ui;
	const EVP_MD *dgst;
	const EVP_MD *algolist[] = { EVP_md2(), EVP_md5(), EVP_sha1()
#ifdef HAS_SHA256
			,EVP_sha256(), EVP_sha512()
#endif
	};
	x509v3ext e;
	X509V3_CTX ext_ctx;
	X509V3_set_ctx(&ext_ctx, cert->getCert() , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));
	QDialog *dlg = new QDialog(mainwin);
	ui.setupUi(dlg);
	ui.image->setPixmap(*MainWindow::revImg);
#ifdef HAS_SHA256
	ui.hashAlgo->addItem(tr("SHA 256"));
	ui.hashAlgo->addItem(tr("SHA 512"));
	ui.hashAlgo->setCurrentIndex(3);
#endif
	ui.lastUpdate->setDate(time.now());
	ui.nextUpdate->setDate(time.now(cert->getCrlDays() *60*60*24));

	if (cert->getRefKey()->getType() == EVP_PKEY_DSA)
		ui.hashAlgo->setEnabled(false);
	else
		ui.hashAlgo->setEnabled(true);

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
		cert->setLastCrl(ui.nextUpdate->getDate());
		if (cert->getRefKey()->getType() == EVP_PKEY_DSA)
			dgst = EVP_dss1();
		else
			dgst = algolist[ui.hashAlgo->currentIndex()];

		crl->sign(cert->getRefKey(), dgst);
		mainwin->certs->updatePKI(cert);
#warning  FIXME: set Last update
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
