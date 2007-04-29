/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "XcaTreeView.h"
#include "lib/db_base.h"
#include <qabstractitemmodel.h>
#include <qabstractitemview.h>
#include <qheaderview.h>
#include <qevent.h>
#include <qvariant.h>


XcaTreeView::XcaTreeView(QWidget *parent)
	:QTreeView(parent)
{
	setAlternatingRowColors(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setEditTriggers(QAbstractItemView::EditKeyPressed);
	setRootIsDecorated(false);
	setUniformRowHeights (true);
	//setAnimated(true);

	proxy = new QSortFilterProxyModel(this);
#if QT_VERSION >= 0x040200
	setSortingEnabled(true);
	proxy->setDynamicSortFilter(true);
	sortByColumn(0, Qt::AscendingOrder);
#else
	header()->setClickable(true);
	header()->setSortIndicatorShown(true);
	sortByColumn(0);
#endif
	basemodel = NULL;
}

XcaTreeView::~XcaTreeView()
{
	delete proxy;
}

void XcaTreeView::contextMenuEvent(QContextMenuEvent * e )
{
	if (basemodel)
		basemodel->showContextMenu(e, getIndex(indexAt(e->pos())));
}

void XcaTreeView::setModel(QAbstractItemModel *model)
{
	basemodel = (db_base *)model;
	proxy->setSourceModel(model);
	QTreeView::setModel(proxy);
	columnsResize();
}

QModelIndex XcaTreeView::getIndex(const QModelIndex &index)
{
	return proxy->mapToSource(index);
}

QModelIndex XcaTreeView::getProxyIndex(const QModelIndex &index)
{
	return proxy->mapFromSource(index);
}

QModelIndexList XcaTreeView::getSelectedIndexes()
{
	QItemSelection indexes = selectionModel()->selection();
	return proxy->mapSelectionToSource(indexes).indexes();
}

void XcaTreeView::columnsResize()
{
	int cnt, i;
	if (basemodel) {
		cnt = basemodel->columnCount(QModelIndex());
		for (i=0; i<cnt; i++)
			resizeColumnToContents(i);
	}
}

CertTreeView::CertTreeView(QWidget *parent)
	:XcaTreeView(parent)
{
	delete proxy;
	proxy = new XcaProxyModel(this);
}

XcaProxyModel::XcaProxyModel(QWidget *)
{
}

bool XcaProxyModel::lessThan(const QModelIndex &left,
		const QModelIndex &right) const
{
	if (left.column() == 2 && right.column() == 2) {
		int diff;
		QString l = sourceModel()->data(left).toString();
		QString r = sourceModel()->data(right).toString();
		diff = l.size() - r.size();
		if (diff<0)
			return true;
		else if (diff>0)
			return false;
		else
			return l < r;
	}
	return QSortFilterProxyModel::lessThan(left, right);
}
