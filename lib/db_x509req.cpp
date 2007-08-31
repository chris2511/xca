/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_x509req.h"
#include "pki_x509req.h"
#include "widgets/ReqDetail.h"
#include "widgets/MainWindow.h"
#include <qmessagebox.h>
#include <qevent.h>
#include <qaction.h>


db_x509req::db_x509req(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{
	headertext << "Name" << "Subject";
	delete_txt = tr("Delete the request(s)");
	loadContainer();
	view = mw->reqView;
	class_name = "requests";
}

pki_base *db_x509req::newPKI()
{
	return new pki_x509req();
}

pki_base *db_x509req::insert(pki_base *item)
{
	pki_x509req *oldreq, *req;
	req = (pki_x509req *)item;
	oldreq = (pki_x509req *)getByReference(req);
	if (oldreq) {
		QMessageBox::information(NULL,tr(XCA_TITLE),
		tr("The certificate signing request already exists in the database as") +":\n'" +
		oldreq->getIntName() +
		"'\n" + tr("and thus was not stored"), "OK");
		delete(req);
		return oldreq;
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
		insert(req);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (req)
			delete req;
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
	ReqDetail *dlg;
	dlg = new ReqDetail(mainwin);
	if (dlg) {
		dlg->setReq(req);
		connect( dlg->privKey, SIGNAL( doubleClicked(QString) ),
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
	QAction *expItem;
	currentIdx = index;

	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());

	menu->addAction(tr("New Request"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		menu->addAction(tr("Sign"), this, SLOT(signReq()));
		expItem = menu->addAction(tr("Export"), this, SLOT(store()));
		expItem->setEnabled(! req->isSpki());
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}
