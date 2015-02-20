/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_x509req.h"
#include "X509SuperTreeView.h"
#include "MainWindow.h"
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void X509SuperTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	pki_x509super *x = static_cast<pki_x509super *>
				(index.internalPointer());
	transform = NULL;

	if (indexes.size() != 1)
		return;

	subExport->addAction(tr("OpenSSL config"), this, SLOT(toOpenssl()));
	subExport->setEnabled(!x->isSpki());
	transform = menu->addMenu(tr("Transform"));
	transform->addAction(tr("Template"), this,
		SLOT(toTemplate()))->setEnabled(!x->isSpki());
	transform->addAction(tr("Public Key"), this,
		SLOT(extractPubkey()))->setEnabled(!x->getRefKey());
}

void X509SuperTreeView::extractPubkey()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && x509super)
		x509super->extractPubkey(idx);
}

void X509SuperTreeView::toTemplate()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && x509super)
		x509super->toTemplate(idx);
}

void X509SuperTreeView::toOpenssl()
{
	QModelIndex idx = currentIndex();

	if (idx.isValid() && x509super)
		x509super->toOpenssl(idx);
}
