/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_x509req.h"
#include "ReqTreeView.h"
#include "MainWindow.h"
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void ReqTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	X509SuperTreeView::fillContextMenu(menu, subExport, index, indexes);

	pki_x509req *req = db_base::fromIndex<pki_x509req>(index);

	if (indexes.size() != 1 || !req)
		return;

	menu->addAction(tr("Sign"), this, SLOT(signReq()));
	if (req->getDone())
		menu->addAction(tr("Unmark signed"),
				this, SLOT(unmarkSigned()));
	else
		menu->addAction(tr("Mark signed"),
				this, SLOT(markSigned()));
	if (transform) {
		transform->addAction(tr("Similar Request"), this,
				SLOT(toRequest()));
	}
}

void ReqTreeView::signReq()
{
	pki_x509req *req = db_base::fromIndex<pki_x509req>(currentIndex());
	db_x509 *certs = Database.model<db_x509>();
	certs->newCert(req);
}

void ReqTreeView::toRequest()
{
	pki_x509req *req = db_base::fromIndex<pki_x509req>(currentIndex());
	if (basemodel)
		reqs()->newItem(NULL, req);
}

void ReqTreeView::markSigned()
{
	if (basemodel)
		reqs()->setSigned(currentIndex(), true);
}

void ReqTreeView::unmarkSigned()
{
	if (basemodel)
		reqs()->setSigned(currentIndex(), false);
}
