/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_x509req.h"
#include "pki_x509req.h"
#include "widgets/CertDetail.h"
#include "widgets/MainWindow.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include <QAction>


db_x509req::db_x509req(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{
	class_name = "requests";
	pkitype << x509_req;
	updateHeaders();
	loadContainer();
}

dbheaderList db_x509req::getHeaders()
{
	dbheaderList h = db_x509super::getHeaders();
	h <<	new dbheader(HD_req_signed, true, tr("Signed"),
			tr("whether the request is already signed or not")) <<
		new dbheader(HD_req_unstr_name, false, tr("Unstructured name"),
			QString(OBJ_nid2ln(NID_pkcs9_unstructuredName))) <<
		new dbheader(HD_req_chall_pass, false, tr("Challenge password"),
			 QString(OBJ_nid2ln(NID_pkcs9_challengePassword)));
	return h;
}

pki_base *db_x509req::newPKI(db_header_t *)
{
	return new pki_x509req();
}

pki_base *db_x509req::insert(pki_base *item)
{
	pki_x509req *oldreq, *req;
	req = (pki_x509req *)item;
	oldreq = (pki_x509req *)getByReference(req);
	if (oldreq) {
		XCA_INFO(tr("The certificate signing request already exists in the database as\n'%1'\nand thus was not stored").arg(oldreq->getIntName()));
		delete(req);
		return NULL;
	}
	insertPKI(req);
	return req;
}

void db_x509req::newItem()
{
	newItem(NULL, NULL);
}

void db_x509req::newItem(pki_temp *temp, pki_x509req *orig)
{
	pki_x509req *req = NULL;
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);

	if (temp) {
		dlg->defineTemplate(temp);
	} else if (orig) {
		dlg->fromX509super(orig);
	}
	dlg->setRequest();
	if (!dlg->exec()){
		delete dlg;
		return;
	}
	try {
		pki_key *key = dlg->getSelectedKey();
		x509name xn = dlg->getX509name();
		req = new pki_x509req();

		req->setIntName(dlg->description->text());

		dlg->initCtx(NULL, NULL, req);
		dlg->getReqAttributes(req);
		req->createReq(key, xn, dlg->hashAlgo->currentHash(), dlg->getAllExt());
		createSuccess(insert(req));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (req)
			delete req;
	}
}

void db_x509req::toRequest(QModelIndex index)
{
	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());
	if (!req)
		return;
	newItem(NULL, req);
}

void db_x509req::inToCont(pki_base *pki)
{
	pki_x509req *req = (pki_x509req *)pki;
	db_base::inToCont(pki);
	findKey(req);
	if (!mainwin->certs)
		return;
	pki_key *pub = req->getPubKey();
	if (pub) {
		int certs = mainwin->certs->findByPubKey(pub).count();
		delete pub;
		if (certs > 0) {
			req->setDone();
		}
	}
}

void db_x509req::load(void)
{
	load_req l;
	load_default(l);
}

void db_x509req::showPki(pki_base *pki)
{
	pki_x509req *req = (pki_x509req *)pki;
	CertDetail *dlg;
	dlg = new CertDetail(mainwin);
	if (dlg) {
		dlg->setReq(req);
		connect(dlg->privKey, SIGNAL( doubleClicked(QString) ),
			mainwin->keys, SLOT( showItem(QString) ));
		dlg->exec();
		delete dlg;
	}
}

void db_x509req::store(QModelIndex index)
{
	QList<exportType> types;

	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());
	if (!req)
		return;

	types << exportType(exportType::PEM, "pem", "PEM") <<
			exportType(exportType::DER, "der", "DER");

	ExportDialog *dlg = new ExportDialog(mainwin,
		tr("Certificate request export"),
		tr("Certificate request ( *.pem *.der *.csr )"), req,
		MainWindow::csrImg, types);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
	try {
		req->writeReq(fname, dlg->type() == exportType::PEM);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
	delete dlg;
}

void db_x509req::signReq(QModelIndex index)
{
	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());
	emit newCert(req);
}
