/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_x509req.h"
#include "pki_x509req.h"
#include "widgets/CertDetail.h"
#include "widgets/MainWindow.h"
#include <QtGui/QMessageBox>
#include <QtGui/QContextMenuEvent>
#include <QtGui/QAction>


db_x509req::db_x509req(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{
	allHeaders << new dbheader(HD_req_signed, true, tr("Signed"),
			tr("whether the request is already signed or not")) <<
		new dbheader(HD_req_unstr_name, false, tr("Unstructured name"),
			QString(OBJ_nid2ln(NID_pkcs9_unstructuredName))) <<
		new dbheader(HD_req_chall_pass, false, tr("Challenge password"),
			 QString(OBJ_nid2ln(NID_pkcs9_challengePassword)));
	class_name = "requests";
	pkitype << x509_req;
	loadContainer();
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
		QMessageBox::information(mainwin, XCA_TITLE,
		tr("The certificate signing request already exists in the database as\n'%1'\nand thus was not stored").arg(oldreq->getIntName()));
		delete(req);
		return NULL;
	}
	insertPKI(req);
	return req;
}

void db_x509req::newItem(pki_temp *temp)
{
	pki_x509req *req = NULL;
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);

	if (temp) {
		dlg->defineTemplate(temp);
	}
	dlg->setRequest();
	if (! dlg->exec()){
		delete dlg;
		return;
	}
	try {
		pki_key *key = dlg->getSelectedKey();
		x509name xn = dlg->getX509name();
		req = new pki_x509req();

		req->setIntName(dlg->description->text());

		dlg->initCtx(NULL, NULL, req);
		dlg->addReqAttributes(req);
		req->createReq(key, xn, dlg->hashAlgo->currentHash(), dlg->getAllExt());
		createSuccess(insert(req));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (req)
			delete req;
	}
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

void db_x509req::store()
{
	if (!currentIdx.isValid())
		return;

	pki_x509req *req = static_cast<pki_x509req*>(currentIdx.internalPointer());
	if (!req)
		return;

	QString fn = mainwin->getPath() + QDir::separator() +
		req->getUnderlinedName() + ".pem";
	ExportDer *dlg = new ExportDer(mainwin, fn,
			tr("Certificate request ( *.pem *.der *.crl )") );
	dlg->image->setPixmap(*MainWindow::csrImg);
	dlg->label->setText(tr("Certificate request export"));
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
		req->writeReq(fname, pem);
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}


void db_x509req::signReq()
{
	if (!currentIdx.isValid())
		return;

	pki_x509req *req = static_cast<pki_x509req*>(currentIdx.internalPointer());
	emit newCert(req);
}

void db_x509req::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport;
	currentIdx = index;

	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());

	menu->addAction(tr("New Request"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		if (!req->getRefKey())
			menu->addAction(tr("Extract public Key"),
				this, SLOT(extractPubkey()));
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		menu->addAction(tr("Sign"), this, SLOT(signReq()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("Clipboard"), this,
					SLOT(pem2clipboard()));
		subExport->addAction(tr("File"), this, SLOT(store()));
		subExport->addAction(tr("Template"), this, SLOT(toTemplate()));
		subExport->addAction(tr("OpenSSL config"), this,
					SLOT(toOpenssl()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));

		subExport->setEnabled(!req->isSpki());
	}
	contextMenu(e, menu);
	currentIdx = QModelIndex();
	return;
}
