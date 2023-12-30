/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "ui_CaProperties.h"
#include "CertTreeView.h"
#include "XcaWarning.h"
#include "XcaDialog.h"
#include "MainWindow.h"
#include "RevocationList.h"
#include "ExportDialog.h"
#include "NewCrl.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"
#include "lib/load_obj.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void CertTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	QMenu *subCa;
	bool parentCanSign, multi, hasScard, sameParent,
		allRevoked, allUnrevoked;
	pki_key *privkey;

	X509SuperTreeView::fillContextMenu(menu, subExport, index, indexes);

	menu->addAction(tr("Import PKCS#12"), this, SLOT(loadPKCS12()));
	menu->addAction(tr("Import from PKCS#7"), this, SLOT(loadPKCS7()));

	pki_x509 *cert = db_base::fromIndex<pki_x509>(index);
	pki_x509 *parent;

	if (indexes.size() == 0 || !cert)
		return;

	privkey = cert->getRefKey();
	parent = cert->getSigner();
	parentCanSign = parent && parent->canSign() && (parent != cert);
	hasScard = pkcs11::libraries.loaded();

	multi = indexes.size() > 1;

	allUnrevoked = allRevoked = sameParent = true;
	foreach(QModelIndex i, indexes) {
		pki_x509 *c = db_base::fromIndex<pki_x509>(i);
		if (!c)
			continue;
		if (c->getSigner() != parent)
			sameParent = false;
		if (c->isRevoked())
			allUnrevoked = false;
		else
			allRevoked = false;
	}

	if (!multi) {
		transform->addAction(tr("Request"), this, SLOT(toRequest()))->
			setEnabled(privkey && privkey->isPrivKey());
		subExport->addAction(tr("Security token"), this,
			SLOT(toToken()))->setEnabled(hasScard);
		subExport->addAction(tr("Other token"), this,
			SLOT(toOtherToken()))->setEnabled(
					hasScard && privkey && privkey->isToken());

		transform->addAction(tr("Similar Certificate"), this,
			SLOT(toCertificate()));

		menu->addAction(tr("Delete from Security token"), this,
			SLOT(deleteFromToken()))->setEnabled(hasScard);

		subCa = menu->addMenu(tr("CA"));
		subCa->addAction(tr("Properties"), this, SLOT(caProperties()));
		subCa->addAction(tr("Generate CRL"), this, SLOT(genCrl()));
		subCa->addAction(tr("Manage revocations"), this,
			 SLOT(manageRevocations()));
		subCa->setEnabled(cert->canSign());
	}
	if (parent == cert && parent->canSign())
		menu->addAction(tr("Renewal"), this, SLOT(certRenewal()));
	if (sameParent && parentCanSign) {
		QString n = multi ? QString(" [%1]").arg(indexes.size()) : "";
		menu->addAction(tr("Renewal") +n, this, SLOT(certRenewal()));
		if (allUnrevoked)
			menu->addAction(tr("Revoke") +n, this, SLOT(revoke()));
		if (allRevoked)
			menu->addAction(tr("Unrevoke") +n, this,
				SLOT(unRevoke()));
	}
}

void CertTreeView::toRequest()
{
	if (basemodel)
		certs()->toRequest(currentIndex());
}

void CertTreeView::toToken()
{
	if (basemodel)
		certs()->toToken(currentIndex(), false);
}

void CertTreeView::toOtherToken()
{
	if (basemodel)
		certs()->toToken(currentIndex(), true);
}

void CertTreeView::loadPKCS12()
{
	load_pkcs12 l;
	load_default(&l);
}

void CertTreeView::loadPKCS7()
{
	load_pkcs7 l;
	load_default(&l);
}

void CertTreeView::genCrl()
{
	pki_x509 *ca = db_base::fromIndex<pki_x509>(currentIndex());

	NewCrl::newCrl(this, ca);
}

void CertTreeView::toCertificate()
{
	if (basemodel)
		certs()->toCertificate(currentIndex());
}

void CertTreeView::deleteFromToken()
{
	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	try {
		cert->deleteFromToken();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void CertTreeView::changeView()
{
	if (!basemodel)
		return;
	XcaTreeView::changeView();
	mainwin->BNviewState->setText(basemodel->treeViewMode() ?
		tr("Plain View") : tr("Tree View"));
}

void CertTreeView::manageRevocations()
{
	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	if (!cert)
		return;

	RevocationList *dlg = new RevocationList();
	dlg->setRevList(cert->getRevList(), cert);
	if (dlg->exec()) {
		cert->setRevocations(dlg->getRevList());
		columnsChanged();
	}
}

void CertTreeView::caProperties()
{
	Ui::CaProperties ui;
	XcaDialog *dlg;
	QWidget *w;

	pki_x509 *cert = db_base::fromIndex<pki_x509>(currentIndex());
	if (!cert || !basemodel)
		return;

	w = new QWidget();
	ui.setupUi(w);
	ui.days->setSuffix(QString(" ") + tr("days"));
	ui.days->setMaximum(1000000);
	ui.days->setValue(cert->getCrlDays());

	QVariant tmplId = cert->getTemplateSqlId();
	pki_temp *templ = Store.lookupPki<pki_temp>(tmplId);

	ui.temp->insertPkiItems(Store.getAll<pki_temp>());
	ui.temp->setNullItem(tr("No template"));
	ui.temp->setCurrentIndex(0);
	if (templ)
		ui.temp->setCurrentPkiItem(templ);

	dlg = new XcaDialog(this, x509, w, tr("CA Properties"),
		cert->getIntName(), "ca_properties");

	if (dlg->exec()) {
		templ = ui.temp->currentPkiItem();
		tmplId = templ ? templ->getSqlItemId() : QVariant();
		cert->setTemplateSqlId(tmplId);
		cert->setCrlDays(ui.days->value());

		certs()->updateCaProperties(cert);
		columnsChanged();
	}
	delete dlg;
}

void CertTreeView::certRenewal()
{
	if (basemodel)
		certs()->certRenewal(getSelectedIndexes());
}

void CertTreeView::revoke()
{
	if (basemodel)
		certs()->revoke(getSelectedIndexes());
}

void CertTreeView::unRevoke()
{
	if (basemodel)
		certs()->unRevoke(getSelectedIndexes());
}

void CertTreeView::load()
{
	load_cert c;
	load_default(&c);
}

ExportDialog *CertTreeView::exportDialog(const QModelIndexList &indexes)
{
	return new ExportDialog(this,
		tr("Certificate export"),
		tr("X509 Certificates ( *.pem *.cer *.crt *.p12 *.pfx *.p7b )"),
		indexes, QPixmap(":certImg"),
		pki_export::select(x509, basemodel->exportFlags(indexes)),
		                   "certexport");
}
