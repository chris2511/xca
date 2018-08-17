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
	if (reqs)
		reqs->toRequest(currentIndex());
}

void ReqTreeView::signReq()
{
	if (reqs)
		reqs->signReq(currentIndex());
}

void ReqTreeView::markSigned()
{
	if (reqs)
		reqs->setSigned(currentIndex(), true);
}

void ReqTreeView::unmarkSigned()
{
	if (reqs)
		reqs->setSigned(currentIndex(), false);
}
