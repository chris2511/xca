/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/db_x509super.h"
#include "lib/database_model.h"
#include "X509SuperTreeView.h"
#include "CertDetail.h"
#include "MainWindow.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void X509SuperTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	pki_x509super *x = dynamic_cast<pki_x509super*>(
					db_base::fromIndex(index));
	transform = NULL;

	if (indexes.size() != 1 || !x)
		return;

	subExport->addAction(tr("OpenSSL config"), this, SLOT(toOpenssl()));
	transform = menu->addMenu(tr("Transform"));
	transform->addAction(tr("Template"), this, SLOT(toTemplate()));
	transform->addAction(tr("Public key"), this,
		SLOT(extractPubkey()))->setEnabled(!x->getRefKey());
}

void X509SuperTreeView::extractPubkey()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && basemodel)
		x509super()->extractPubkey(idx);
}

void X509SuperTreeView::toTemplate()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && basemodel)
		x509super()->toTemplate(idx);
}

void X509SuperTreeView::toOpenssl()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && basemodel)
		x509super()->toOpenssl(idx);
}


void X509SuperTreeView::showPki(pki_base *pki)
{
	pki_x509super *x = dynamic_cast<pki_x509super *>(pki);
	CertDetail::showCert(this, x);
}
