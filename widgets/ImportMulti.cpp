/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
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
#include <QPushButton>
#include <QMessageBox>
#include <QLabel>
#include <QInputDialog>
#include <QUrl>
#include <QMimeData>

ImportMulti::ImportMulti(MainWindow *parent)
	:QDialog(parent)
{
	mainwin = parent;
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::certImg);
	listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mcont = new db_token(QString(), parent);
	listView->setModel(mcont);
	listView->setIconSize(pki_evp::icon[0]->size());
	listView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	connect( listView, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(on_butDetails_clicked()));
	deleteToken->hide();
	renameToken->hide();
	slotInfo->hide();
	setAcceptDrops(true);
}

void ImportMulti::tokenInfo(slotid s)
{
	slot = s;
	mcont->setSlot(slot);
	deleteToken->show();
	renameToken->show();
	slotInfo->show();
	listView->setEditTriggers(QAbstractItemView::EditKeyPressed);

	pkcs11 p11;

	QString info = p11.driverInfo(slot);
	tkInfo ti = p11.tokenInfo(slot);
	info += tr("\nName: %1\nModel: %2\nSerial: %3").
		arg(ti.label()).arg(ti.model()).arg(ti.serial());

	slotInfo->setText(info);
	image->setPixmap(*MainWindow::scardImg);
	heading->setText(tr("Manage security token"));
	setAcceptDrops(false);
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
		XCA_WARN(tr("The type of the Item '%1' is not recognized").
			arg(cn));
	}
}

void ImportMulti::dragEnterEvent(QDragEnterEvent *event)
{
	if (event->mimeData()->hasUrls())
		event->acceptProposedAction();
}

void ImportMulti::dropEvent(QDropEvent *event)
{
	QList<QUrl> urls = event->mimeData()->urls();
	QUrl u;
	QStringList failed;
	pki_multi *pki = new pki_multi();

	foreach(u, urls) {
		QString s = u.toLocalFile();
		int count = pki->count();
		pki->probeAnything(s);
		if (pki->count() == count)
			failed << s;
	}
	importError(failed);
	addItem(pki);
	event->acceptProposedAction();
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

void ImportMulti::on_deleteToken_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki_base *pki = static_cast<pki_base*>(index.internalPointer());
		try {
			pki->deleteFromToken(slot);
			mcont->remFromCont(index);
			delete pki;
		} catch (errorEx &err) {
			mainwin->Error(err);
		}
	}
}
void ImportMulti::on_renameToken_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;

        foreach(index, indexes) {
                if (index.column() != 0)
                        continue;
		listView->edit(index);
		break;
	}
}

static db_base *select_db(QString cn)
{
	if (cn == "pki_x509")
		return MainWindow::certs;
	if (cn == "pki_evp")
		return MainWindow::keys;
	if (cn == "pki_scard")
		return MainWindow::keys;
	if (cn == "pki_x509req")
		return MainWindow::reqs;
	if (cn == "pki_crl")
		return MainWindow::crls;
	if (cn == "pki_temp")
		return MainWindow::temps;
	return NULL;
}

pki_base *ImportMulti::import(QModelIndex &idx)
{

	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	db_base *db;

	if (!pki)
		return NULL;
	if (!mainwin->keys) {
		mainwin->load_database();
	}

	QString cn = pki->getClassName();
	mcont->remFromCont(idx);
	if (!mainwin->keys) {
		delete pki;
		return NULL;
	}

	if (cn == "pki_evp")
		((pki_evp*)pki)->setOwnPass(pki_evp::ptCommon);

	db = select_db(cn);
	if (!db) {
		XCA_WARN(tr("The type of the Item '%1' is not recognized").
			arg(cn));
		delete pki;
		return NULL;
	}
	return db->insert(pki);
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
			CertDetail *dlg;
			dlg = new CertDetail(mainwin);
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
			XCA_WARN(tr("Details of the item '%1' cannot be shown").
				arg(cn));
		} else
			XCA_WARN(tr("The type of the item '%1' is not recognized").arg(cn));
	}
	catch (errorEx &err) {
		mainwin->Error(err);
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

void ImportMulti::importError(QStringList failed)
{
	if (failed.count() == 1) {
		XCA_INFO(tr("The file '%1' did not contain PKI data").
			arg(failed[0]));
	} else if (failed.count() > 1) {
		XCA_INFO(tr("The %1 files: '%2' did not contain PKI data").
			arg(failed.count()).
			arg(failed.join("', '")));
	}
}

void ImportMulti::execute(int force, QStringList failed)
{
	importError(failed);

	/* if there is nothing to import don't pop up */
	if (entries() == 0) {
		accept();
		return;
	}
	/* if there is only 1 item and force is 0 import it silently */
	if (entries() == 1 && force == 0) {
		QModelIndex idx = mcont->index(0, 0, QModelIndex());
		pki_base *pki = import(idx);
		if (pki && !pki_base::suppress_messages)
			XCA_INFO(pki->getMsg(pki_base::msg_import).
				arg(pki->getIntName()));
		accept();
		return;
	}
	/* the behaviour for more than one item */
	exec();
}
