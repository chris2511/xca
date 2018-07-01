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
#include <typeinfo>

ImportMulti::ImportMulti(MainWindow *parent)
	:QDialog(parent)
{
	mainwin = parent;
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::certImg);
	listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
	mcont = new db_token(parent);
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

	if (pki->pkiSource == unknown)
		pki->pkiSource = imported;

	const std::type_info &t = typeid(*pki);
	if (t == typeid(pki_x509)) {
		pki_x509 *x = static_cast<pki_x509 *>(pki);
		x->setSigner(x->findIssuer());
		x->lookupKey();
		mcont->inToCont(pki);
	}
	else if (t == typeid(pki_x509req)) {
		pki_x509req *x = static_cast<pki_x509req *>(pki);
		x->lookupKey();
		mcont->inToCont(pki);
	}
	else if (t == typeid(pki_crl)) {
		pki_crl *x = static_cast<pki_crl *>(pki);
		x->lookupIssuer();
		mcont->inToCont(pki);
	}
	else if (t == typeid(pki_evp) || t == typeid(pki_temp) ||
		 t == typeid(pki_scard))
	{
		mcont->inToCont(pki);
	}
	else if (t == typeid(pki_pkcs7)) {
		pki_pkcs7 *p7 = static_cast<pki_pkcs7 *>(pki);
		for (int i=0; i<p7->numCert(); i++) {
			addItem(p7->getCert(i));
		}
		delete p7;
	}
	else if (t == typeid(pki_pkcs12)) {
		pki_pkcs12 *p12 = static_cast<pki_pkcs12 *>(pki);
		addItem(p12->getKey());
		addItem(p12->getCert());
		for (int i=0; i<p12->numCa(); i++) {
			addItem(p12->getCa(i));
		}
		delete p12;
	}
	else if (t == typeid(pki_multi)) {
		pki_multi *pm = static_cast<pki_multi*>(pki);
		pki_base *inner;
		while ((inner = pm->pull()))
			addItem(inner);
		delete pm;
	}
	else  {
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(t.name()));
	}
	if (t == typeid(pki_scard))
		mcont->rename_token_in_database(dynamic_cast<pki_scard*>(pki));
}

void ImportMulti::openDB()
{
	if (!mainwin->keys)
		mainwin->load_database();
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
	openDB();

	Transaction;
	if (!TransBegin())
		return;
	while (mcont->rootItem->childCount()) {
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

	openDB();

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

static db_base *select_db(const std::type_info &t)
{
	if (t == typeid(pki_x509))    return MainWindow::certs;
	if (t == typeid(pki_evp))     return MainWindow::keys;
	if (t == typeid(pki_scard))   return MainWindow::keys;
	if (t == typeid(pki_x509req)) return MainWindow::reqs;
	if (t == typeid(pki_crl))     return MainWindow::crls;
	if (t == typeid(pki_temp))    return MainWindow::temps;
	return NULL;
}

pki_base *ImportMulti::import(QModelIndex &idx)
{

	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	db_base *db;

	if (!pki || !mainwin->keys)
		return NULL;

	const std::type_info &t = typeid(*pki);

	mcont->remFromCont(idx);
	if (!mainwin->keys) {
		delete pki;
		return NULL;
	}

	if (t == typeid(pki_evp))
		static_cast<pki_evp*>(pki)->setOwnPass(pki_evp::ptCommon);

	db = select_db(t);
	if (!db) {
		XCA_WARN(tr("The type of the item '%1' is not recognized").
			arg(t.name()));
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
	const std::type_info &t = typeid(*pki);
	try {
		if (t == typeid(pki_x509)){
			CertDetail *dlg = new CertDetail(mainwin);
			dlg->setCert(static_cast<pki_x509 *>(pki));
			connect(dlg->privKey, SIGNAL(doubleClicked(QString)),
				mainwin->keys, SLOT(showItem(QString)));
			connect(dlg->signature,
				SIGNAL(doubleClicked(QString)),
				mainwin->certs, SLOT(showItem(QString)));
			if (dlg->exec())
				pki->setIntName(dlg->descr->text());
			delete dlg;
		} else if (t == typeid(pki_evp) || t == typeid(pki_scard)) {
			KeyDetail *dlg = new KeyDetail(mainwin);
			dlg->setKey(static_cast<pki_key *>(pki));
			if (dlg->exec())
				pki->setIntName(dlg->keyDesc->text());
			delete dlg;
		} else if (t == typeid(pki_x509req)) {
			CertDetail *dlg = new CertDetail(mainwin);
			dlg->setReq(static_cast<pki_x509req *>(pki));
			connect(dlg->privKey, SIGNAL(doubleClicked(QString)),
				mainwin->keys, SLOT(showItem(QString)));
			if (dlg->exec())
				pki->setIntName(dlg->descr->text());
			delete dlg;
		} else if (t == typeid(pki_crl)) {
			CrlDetail *dlg = new CrlDetail(mainwin);
			dlg->setCrl(static_cast<pki_crl *>(pki));
			connect(dlg->issuerIntName,
				SIGNAL(doubleClicked(QString)),
				mainwin->certs, SLOT(showItem(QString)));
			if (dlg->exec())
				pki->setIntName(dlg->descr->text());
			delete dlg;
		} else if (t == typeid(pki_temp)) {
			XCA_WARN(tr("Details of the item '%1' cannot be shown")
				.arg("XCA template"));
		} else
			XCA_WARN(tr("The type of the item '%1' is not recognized").arg(t.name()));
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
		openDB();
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
