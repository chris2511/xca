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


void X509SuperTreeView::showPki(pki_base *pki) const
{
	pki_x509super *x = dynamic_cast<pki_x509super *>(pki);
	if (!x)
		return;
	CertDetail *dlg = new CertDetail(NULL);
	if (!dlg)
		return;

	dlg->setX509super(x);

	connect(dlg->privKey, SIGNAL(doubleClicked(QString)),
		mainwin->keyView, SLOT(showItem(QString)));
	connect(dlg->signature, SIGNAL(doubleClicked(QString)),
		this, SLOT(showItem(QString)));
	connect(basemodel, SIGNAL(pkiChanged(pki_base*)),
		dlg, SLOT(itemChanged(pki_base*)));
	connect(Database.model<db_key>(), SIGNAL(pkiChanged(pki_base*)),
		dlg, SLOT(itemChanged(pki_base*)));

	if (dlg->exec() && basemodel) {
		x509super()->updateItem(pki, dlg->descr->text(),
					dlg->comment->toPlainText());
	}
	delete dlg;
}
