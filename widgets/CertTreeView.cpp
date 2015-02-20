/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_x509.h"
#include "CertTreeView.h"
#include "MainWindow.h"
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

	if (indexes.size() == 0)
		return;

	pki_x509 *cert = static_cast<pki_x509*>(index.internalPointer());
	pki_x509 *parent;

	privkey = cert->getRefKey();
	parent = cert->getSigner();
	parentCanSign = parent && parent->canSign() && (parent != cert);
	hasScard = pkcs11::loaded();

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
	menu->addAction(tr("Trust"), this,
		SLOT(setTrust()))->setEnabled(allUnrevoked);
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
	if (!certs)
		return;

	db_x509 *c = certs;

	hide();
	setModel();

	c->changeView();

	setModel(c);
	show();
	setRootIsDecorated(db_x509::treeview);
}

void CertTreeView::toRequest()
{
	if (certs)
		certs->toRequest(currentIndex());
}

void CertTreeView::toToken()
{
	if (certs)
		certs->toToken(currentIndex(), false);
}

void CertTreeView::toOtherToken()
{
	if (certs)
		certs->toToken(currentIndex(), true);
}

void CertTreeView::loadPKCS12()
{
	if (certs) {
		load_pkcs12 l;
		certs->load_default(l);
	}
}

void CertTreeView::loadPKCS7()
{
	if (certs) {
		load_pkcs7 l;
		certs->load_default(l);
	}
}

void CertTreeView::genCrl()
{
	pki_x509 *cert = static_cast<pki_x509*>
			(currentIndex().internalPointer());
	mainwin->crls->newItem(cert);
}

void CertTreeView::toCertificate()
{
	if (certs)
		certs->toCertificate(currentIndex());
}

void CertTreeView::deleteFromToken()
{
	pki_x509 *cert = static_cast<pki_x509*>
			(currentIndex().internalPointer());
	try {
		cert->deleteFromToken();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void CertTreeView::manageRevocations()
{
	if (certs)
		certs->manageRevocations(currentIndex());
}

void CertTreeView::caProperties()
{
	if (certs)
		certs->caProperties(currentIndex());
}

void CertTreeView::certRenewal()
{
	if (certs)
		certs->certRenewal(getSelectedIndexes());
}

void CertTreeView::revoke()
{
	if (certs)
		certs->revoke(getSelectedIndexes());
}

void CertTreeView::unRevoke()
{
	if (certs)
		certs->unRevoke(getSelectedIndexes());
}

void CertTreeView::setTrust()
{
	if (certs)
		certs->setTrust(getSelectedIndexes());
	proxy->invalidate();
}

