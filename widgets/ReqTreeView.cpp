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

	if (indexes.size() != 1)
		return;

	pki_x509req *req = static_cast<pki_x509req*>(index.internalPointer());

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

void ReqTreeView::toRequest()
{
	pki_x509req *req = static_cast<pki_x509req*>(currentIndex()
							.internalPointer());
	db_x509 *certs = models()->model<db_x509>();
	certs->newCert(req);
}

void ReqTreeView::signReq()
{
	pki_x509req *req = static_cast<pki_x509req*>(currentIndex()
							.internalPointer());
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
