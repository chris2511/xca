/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCATREEVIEW_H
#define __XCATREEVIEW_H

#include <QtGui/QTreeView>
#include <QtGui/QItemSelectionModel>
#include <QtGui/QSortFilterProxyModel>
#include <QtGui/QHeaderView>
#include "lib/db_base.h"

class db_base;

class XcaHeaderView: public QHeaderView
{
	Q_OBJECT
    public:
	XcaHeaderView()
		:QHeaderView(Qt::Horizontal)
	{
		setMovable(true);
	}
	void contextMenuEvent(QContextMenuEvent *e);
    public slots:
	void resetMoves();
};

class XcaTreeView: public QTreeView
{
	Q_OBJECT
   protected:
	db_base *basemodel;
	QSortFilterProxyModel *proxy;
   public:
	XcaTreeView(QWidget *parent = 0);
	~XcaTreeView();
	void contextMenuEvent(QContextMenuEvent *e);
	void setModel(QAbstractItemModel *model);
	QModelIndex getIndex(const QModelIndex &index);
	QModelIndex getProxyIndex(const QModelIndex &index);
	QModelIndexList getSelectedIndexes();
	void headerEvent(QContextMenuEvent *e, int col);

   public slots:
	void showHideSections();
	void sectionMoved(int idx, int oldI, int newI);
	void columnsResize();
	void editIdx(const QModelIndex &idx);
};

class XcaProxyModel: public QSortFilterProxyModel
{
	Q_OBJECT
   public:
	XcaProxyModel(QWidget *parent = 0);
	bool lessThan(const QModelIndex &left, const QModelIndex &right) const;
};

#endif
