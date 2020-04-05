/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ImportMulti.h"
#include "XcaWarning.h"
#include "MainWindow.h"
#include "lib/pki_base.h"
#include "lib/pki_pkcs7.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_crl.h"
#include "lib/pki_multi.h"
#include "lib/pki_scard.h"
#include "lib/pki_evp.h"
#include "lib/pki_temp.h"
#include "CrlDetail.h"
#include "CertDetail.h"
#include "KeyDetail.h"

#include <QPushButton>
#include <QMessageBox>
#include <QLabel>
#include <QInputDialog>
#include <QUrl>
#include <QMimeData>
#include <typeinfo>

ImportMulti::ImportMulti(MainWindow *parent)
	:QDialog(parent)
{
	mainwin = parent;
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":certImg"));
	listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mcont = new db_token(parent->getModels());
	listView->setModel(mcont);
	listView->setIconSize(QPixmap(":key").size());
	listView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	connect( listView, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(on_butDetails_clicked()));
	deleteToken->hide();
	renameToken->hide();
	slotInfo->hide();
	setAcceptDrops(true);
}

void ImportMulti::tokenInfo(const slotid &s)
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
	image->setPixmap(QPixmap(":scardImg"));
	heading->setText(tr("Manage security token"));
	setAcceptDrops(false);
}

void ImportMulti::addItem(pki_base *pki)
{
	if (!pki)
		return;

	if (pki->pkiSource == unknown)
		pki->pkiSource = imported;
	pki_multi *pm = dynamic_cast<pki_multi*>(pki);
	if (pm) {
		QList<pki_base*> items = pm->pull();
		foreach(pki_base *inner, items)
			addItem(inner);
		delete pm;
		return;
	}

	pki_x509 *cert = dynamic_cast<pki_x509 *>(pki);
	pki_crl *crl = dynamic_cast<pki_crl *>(pki);
	pki_x509super *cert_or_req = dynamic_cast<pki_x509super *>(pki);

	if (cert)
		cert->setSigner(cert->findIssuer());
	if (cert_or_req)
		cert_or_req->lookupKey();
	if (crl)
		crl->lookupIssuer();

	if (!dynamic_cast<pki_key*>(pki) &&
	    !dynamic_cast<pki_x509name*>(pki))
	{
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(pki->getClassName()));
		delete pki;
		return;
	}
	mcont->inToCont(pki);
	mcont->rename_token_in_database(dynamic_cast<pki_scard*>(pki));
}

bool ImportMulti::openDB() const
{
	if (currentDB.isEmpty()) {
		if (mainwin->init_database(QString()) == 2)
			return false;
		if (currentDB.isEmpty())
			mainwin->load_database();
	}
	return !currentDB.isEmpty();
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

	foreach(u, urls)
		pki->probeAnything(u.toLocalFile());

	failed << pki->failed_files;
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
	if (!openDB())
		return;

	Transaction;
	if (!TransBegin())
		return;
	while (mcont->rootItem->childCount()) {
		qDebug() << "childCount" << mcont->rootItem->childCount();
		foreach(pki_base *p, mcont->rootItem->childItems)
			qDebug() << "Child" << p->getIntName();
		QModelIndex idx = mcont->index(0, 0, QModelIndex());
		import(idx);
	}
	TransCommit();
	accept();
}

void ImportMulti::on_butImport_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();

	if (!openDB())
		return;

	Transaction;
	if (!TransBegin())
		return;
	foreach(QModelIndex index, indexes) {
		if (index.column() != 0)
			continue;
		import(index);
	}
	TransCommit();
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
			XCA_ERROR(err);
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

pki_base *ImportMulti::import(QModelIndex &idx)
{
	database_model *models = mainwin->getModels();
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());

	if (!pki)
		return NULL;

	mcont->remFromCont(idx);

	if (!models) {
		delete pki;
		return NULL;
	}
	return models->insert(pki);
}

void ImportMulti::on_butDetails_clicked()
{
	QItemSelectionModel *selectionModel = listView->selectionModel();
	QModelIndex index;
	db_key *keys = mainwin->model<db_key>();
	db_x509 *certs = mainwin->model<db_x509>();

	if (!selectionModel->selectedIndexes().count())
	        return;

	index = selectionModel->selectedIndexes().first();
	pki_base *pki = static_cast<pki_base*>(index.internalPointer());

	if (!pki)
		return;
	try {
		pki_x509super *pki_super = dynamic_cast<pki_x509super*>(pki);
		if (pki_super) {
			CertDetail *dlg = new CertDetail(mainwin);
			dlg->setX509super(pki_super);
			connect(dlg->privKey, SIGNAL(doubleClicked(QString)),
				keys, SLOT(showItem(QString)));
			connect(dlg->signature,
				SIGNAL(doubleClicked(QString)),
				certs, SLOT(showItem(QString)));
			if (dlg->exec())
				pki->setIntName(dlg->descr->text());
			delete dlg;
			return;
		}
		pki_key *key = dynamic_cast<pki_key*>(pki);
		if (key) {
			KeyDetail *dlg = new KeyDetail(mainwin);
			dlg->setKey(key);
			if (dlg->exec())
				pki->setIntName(dlg->keyDesc->text());
			delete dlg;
			return;
		}
		pki_crl *crl = dynamic_cast<pki_crl*>(pki);
		if (crl) {
			CrlDetail *dlg = new CrlDetail(mainwin);
			dlg->setCrl(crl);
			connect(dlg->issuerIntName,
				SIGNAL(doubleClicked(QString)),
				certs, SLOT(showItem(QString)));
			if (dlg->exec())
				pki->setIntName(dlg->descr->text());
			delete dlg;
			return;
		}
		pki_temp *temp = dynamic_cast<pki_temp*>(pki);
		if (temp) {
			XCA_WARN(tr("Details of the item '%1' cannot be shown")
				.arg("XCA template"));
			return;
		}
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(pki->getClassName()));
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
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
	if (entries() == 1 && force == 0 && openDB()) {
		QModelIndex idx = mcont->index(0, 0, QModelIndex());
		pki_base *pki = import(idx);
		if (pki && !Settings["suppress_messages"])
			XCA_INFO(pki->getMsg(pki_base::msg_import).
				arg(pki->getIntName()));
		accept();
		return;
	}
	/* the behaviour for more than one item */
	exec();
}
