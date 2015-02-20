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

	menu->addAction(tr("Sign"), this, SLOT(signReq()));
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
