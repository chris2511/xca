/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAPROXYMODEL_H
#define __XCAPROXYMODEL_H

#include <QWidget>
#include <QItemSelectionModel>
#include <QSortFilterProxyModel>

class XcaProxyModel: public QSortFilterProxyModel
{
	Q_OBJECT
   public:
	XcaProxyModel(QWidget *parent = 0)
		:QSortFilterProxyModel(parent) { }
	bool lessThan(const QModelIndex &left, const QModelIndex &right) const;
	bool filterAcceptsRow(int sourceRow,
			const QModelIndex &sourceParent) const;
	QVariant data(const QModelIndex &index, int role) const;
};

#endif
