/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ImportMulti.h"
#include "MainWindow.h"
#include "lib/pki_base.h"
#include "lib/pki_pkcs7.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_crl.h"
#include "lib/pki_multi.h"
#include "lib/pki_scard.h"
#include "lib/pki_evp.h"
#include "widgets/CrlDetail.h"
#include "widgets/CertDetail.h"
#include "widgets/KeyDetail.h"
#include "widgets/ReqDetail.h"
#include <qpushbutton.h>
#include <qmessagebox.h>
#include <qlabel.h>

ImportMulti::ImportMulti(MainWindow *parent)
	:QDialog(parent)
{
	mainwin = parent;
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::certImg);
	listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mcont = new db_base("/dev/null", parent);
	listView->setModel(mcont);
	listView->setIconSize(pki_evp::icon[0]->size());
	listView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	connect( listView, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(on_butDetails_clicked()));

}

void ImportMulti::addItem(pki_base *pki)
{
	if (!pki)
		return;
	QString cn = pki->getClassName();

	if (cn == "pki_x509" || cn == "pki_evp"  || cn == "pki_x509req" ||
	    cn == "pki_crl"  || cn == "pki_temp" || cn == "pki_scard")
	{
		mcont->inToCont(pki);
	}
	else if (cn == "pki_pkcs7") {
		pki_pkcs7 *p7 = ( pki_pkcs7 *)pki;
		for (int i=0; i<p7->numCert(); i++) {
			addItem(p7->getCert(i));
		}
		delete p7;
	}
	else if (cn == "pki_pkcs12") {
		pki_pkcs12 *p12 = ( pki_pkcs12 *)pki;
		addItem(p12->getKey());
		addItem(p12->getCert());
		for (int i=0; i<p12->numCa(); i++) {
			addItem(p12->getCa(i));
		}
		delete p12;
	}
	else if (cn == "pki_multi") {
		pki_multi *pm = (pki_multi*)pki;
		pki_base *inner;
		while ((inner = pm->pull()))
			addItem(inner);
		delete pm;
	}
	else  {
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized: ") + cn, tr("OK"));
	}
}

void ImportMulti::on_butRemove_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		mcont->remFromCont(index);
		pki_base *pki = static_cast<pki_base*>(index.internalPointer());
		delete pki;
	}
}

void ImportMulti::on_butOk_clicked()
{
	while (mcont->rootItem->childCount()) {
		QModelIndex idx = mcont->index(0, 0, QModelIndex());
		import(idx);
	}
	accept();
}

void ImportMulti::on_butImport_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		import(index);
	}
}

void ImportMulti::import(QModelIndex &idx)
{

	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());

	if (!pki)
		return;
	if (!mainwin->keys) {
		mainwin->load_database();
	}

	QString cn = pki->getClassName();
	mcont->remFromCont(idx);
	if (!mainwin->keys) {
		delete pki;
		return;
	}

	if (cn == "pki_x509") {
		MainWindow::certs->insert(pki);
	} else if (cn == "pki_evp") {
		((pki_evp*)pki)->setOwnPass(pki_evp::ptCommon);
		MainWindow::keys->insert(pki);
	} else if (cn == "pki_scard") {
		MainWindow::keys->insert(pki);
	} else if (cn == "pki_x509req") {
		MainWindow::reqs->insert(pki);
	} else if (cn == "pki_crl") {
		MainWindow::crls->insert(pki);
	} else if (cn == "pki_temp") {
		MainWindow::temps->insert(pki);
	} else  {
		QMessageBox::warning(this, XCA_TITLE,
			tr("The type of the Item is not recognized: ") + cn, tr("OK"));
		delete pki;
	}
}

void ImportMulti::on_butDetails_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndex index;

	if (!selectionModel->selectedIndexes().count())
	        return;

	index = selectionModel->selectedIndexes().first();
	pki_base *pki = static_cast<pki_base*>(index.internalPointer());

	if (!pki)
		return;
	QString cn = pki->getClassName();
	try {
		if (cn == "pki_x509"){
			CertDetail *dlg;
			dlg = new CertDetail(mainwin);
			dlg->setCert((pki_x509 *)pki);
			dlg->exec();
			delete dlg;
		} else if (cn == "pki_evp" || cn == "pki_scard") {
			KeyDetail *dlg;
			dlg = new KeyDetail(mainwin);
			dlg->setKey((pki_key *)pki);
			dlg->exec();
			delete dlg;
		} else if (cn == "pki_x509req") {
			ReqDetail *dlg;
			dlg = new ReqDetail(mainwin);
			dlg->setReq((pki_x509req *)pki);
			dlg->exec();
			delete dlg;
		} else if (cn == "pki_crl") {
			CrlDetail *dlg;
			dlg = new CrlDetail(mainwin);
			dlg->setCrl((pki_crl *)pki);
			dlg->exec();
			delete dlg;
		} else if (cn == "pki_temp") {
			QMessageBox::warning(this, XCA_TITLE,
				tr("Details of this item cannot be shown: ") + cn, tr("OK"));
		} else
			QMessageBox::warning(this, XCA_TITLE,
				tr("The type of the Item is not recognized ") + cn, tr("OK"));
	}
	catch (errorEx &err) {
		QMessageBox::warning(this, XCA_TITLE,
			tr("Error") + pki->getClassName() +
			err.getString(), tr("OK"));
	}

}

ImportMulti::~ImportMulti()
{
	QModelIndex idx = listView->currentIndex();
	while (idx != QModelIndex()) {
		mcont->remFromCont(idx);
		pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
		delete pki;
		idx = listView->currentIndex();
	}
	listView->setModel(NULL);
	delete mcont;
}

int ImportMulti::entries()
{
	return mcont->rootItem->childCount();
}

void ImportMulti::execute(int force)
{
	/* if there is nothing to import don't pop up */
	if (entries() == 0)
		return;
	/* if there is only 1 item and force is 0 import it silently */
	if (entries() == 1 && force == 0) {
		on_butOk_clicked();
		return;
	}
	/* the behavoiour for more than one item */
	exec();
}
