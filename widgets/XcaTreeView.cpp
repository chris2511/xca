/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "XcaTreeView.h"
#include "lib/db_base.h"
#include <QtCore/QAbstractItemModel>
#include <QtGui/QAbstractItemView>
#include <QtGui/QHeaderView>
#include <QtGui/QContextMenuEvent>
#include <QtCore/QVariant>


XcaTreeView::XcaTreeView(QWidget *parent)
	:QTreeView(parent)
{
	setHeader(new XcaHeaderView());
	setAlternatingRowColors(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setEditTriggers(QAbstractItemView::EditKeyPressed);
	setRootIsDecorated(false);
	setUniformRowHeights (true);
	//setAnimated(true);

	proxy = new XcaProxyModel(this);
	setSortingEnabled(true);
	proxy->setDynamicSortFilter(true);
	sortByColumn(0, Qt::AscendingOrder);
	basemodel = NULL;
	connect(header(), SIGNAL(sectionHandleDoubleClicked(int)),
		this, SLOT(resizeColumnToContents(int)));
	header()->setClickable(true);
}

XcaTreeView::~XcaTreeView()
{
	delete proxy;
}

void XcaTreeView::contextMenuEvent(QContextMenuEvent * e)
{
	if (!basemodel)
		return;
	basemodel->showContextMenu(e, getIndex(indexAt(e->pos())));
}

void XcaTreeView::showHideSections()
{
	if (!basemodel)
		return;
	int i, max = basemodel->columnCount(QModelIndex());
	for (i=0; i<max; i++) {
		if (basemodel->columnHidden(i))
			header()->hideSection(i);
		else
			header()->showSection(i);
	}
	columnsResize();
	header()->update();
}

void XcaTreeView::setModel(QAbstractItemModel *model)
{
	QByteArray ba;
	if (basemodel)
		basemodel->saveHeaderState(header());

	basemodel = (db_base *)model;

	if (basemodel) {
		connect(basemodel, SIGNAL(resetHeader()),
			header(), SLOT(resetMoves()));
		connect(basemodel, SIGNAL(resetHeader()),
			this, SLOT(columnsForceResize()));
		connect(basemodel, SIGNAL(updateHeader()),
			this, SLOT(showHideSections()));
		basemodel->loadHeaderState(header());
	}
	proxy->setSourceModel(model);
	QTreeView::setModel(proxy);
	showHideSections();
}

void XcaTreeView::headerEvent(QContextMenuEvent *e, int col)
{
	basemodel->showHeaderMenu(e, col);
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

void XcaTreeView::columnsForceResize()
{
	int cnt, i;
	if (basemodel) {
		cnt = basemodel->columnCount(QModelIndex());
		for (i=0; i<cnt; i++)
			resizeColumnToContents(i);
	}
}

void XcaTreeView::columnsResize()
{
	if (basemodel && !basemodel->fixedHeaders)
		columnsForceResize();
}

XcaProxyModel::XcaProxyModel(QWidget *parent)
	:QSortFilterProxyModel(parent)
{
}

bool XcaProxyModel::lessThan(const QModelIndex &left,
		const QModelIndex &right) const
{
	db_base *db = (db_base *)sourceModel();
	if (!db)
		return QSortFilterProxyModel::lessThan(left, right);

	if (db->isNumericCol(left.column()) &&
	    db->isNumericCol(right.column()))
	{
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

void XcaHeaderView::contextMenuEvent(QContextMenuEvent * e)
{
	XcaTreeView *tv = (XcaTreeView *)parentWidget();
	if (tv)
		tv->headerEvent(e, logicalIndexAt(e->pos()));
}

void XcaHeaderView::resetMoves()
{
	for (int i=0; i<count(); i++) {
		if (i != visualIndex(i)) {
			moveSection(visualIndex(i), i);
			i=0;
		}
	}
}

bool XcaHeaderView::setState(const QByteArray &state)
{
	setting = state;
	return QHeaderView::restoreState(setting);
}

void XcaHeaderView::showEvent(QShowEvent *event)
{
	if (setting.size()) {
		if (QHeaderView::restoreState(setting))
			setting.clear();
		setStretchLastSection(false);
	}
}
