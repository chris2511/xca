/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_temp.h"
#include "XcaTreeView.h"
#include "MainWindow.h"
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QMenu>

void TempTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
		const QModelIndex &index, QModelIndexList indexes)
{
	(void)subExport;
	(void)index;
	if (indexes.size() != 1)
		return;
	menu->addAction(tr("Duplicate"), this, SLOT(duplicateTemp()));
	menu->addAction(tr("Create certificate"), this, SLOT(certFromTemp()));
	menu->addAction(tr("Create request"), this, SLOT(reqFromTemp()));
}

void TempTreeView::duplicateTemp()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	pki_temp *newtemp = new pki_temp(temp);
	newtemp->setIntName(newtemp->getIntName() + " " + tr("copy"));
	temps->insertPKI(newtemp);
}

void TempTreeView::certFromTemp()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	emit newCert(temp);
}

void TempTreeView::reqFromTemp()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	emit newReq(temp);
}
