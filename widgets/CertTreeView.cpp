/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "CertTreeView.h"
#include "XcaWarning.h"
#include "MainWindow.h"
#include "lib/database_model.h"
#include "lib/db_crl.h"

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

	pki_x509 *cert = dynamic_cast<pki_x509*>(db_base::fromIndex(index));
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
		pki_x509 *c = static_cast<pki_x509*>
				(i.internalPointer());
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

void CertTreeView::changeView()
{
	if (!basemodel)
		return;

	hide();
	setModel(NULL);

	certs()->changeView();

	setModel(certs());
	show();
	setRootIsDecorated(db_x509::treeview);
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
	if (basemodel) {
		load_pkcs12 l;
		certs()->load_default(l);
	}
}

void CertTreeView::loadPKCS7()
{
	if (basemodel) {
		load_pkcs7 l;
		certs()->load_default(l);
	}
}

void CertTreeView::genCrl()
{
	pki_x509 *ca = static_cast<pki_x509*>
			(currentIndex().internalPointer());

	if (mainwin && ca)
		mainwin->crlView->newItem(ca);
}

void CertTreeView::toCertificate()
{
	if (basemodel)
		certs()->toCertificate(currentIndex());
}

void CertTreeView::deleteFromToken()
{
	pki_x509 *cert = static_cast<pki_x509*>
			(currentIndex().internalPointer());
	try {
		cert->deleteFromToken();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void CertTreeView::manageRevocations()
{
	if (basemodel)
		certs()->manageRevocations(currentIndex());
}

void CertTreeView::caProperties()
{
	if (basemodel)
		certs()->caProperties(currentIndex());
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
