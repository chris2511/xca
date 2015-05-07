/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaProxyModel.h"
#include "lib/db_base.h"

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

bool XcaProxyModel::filterAcceptsRow(int sourceRow,
         const QModelIndex &sourceParent) const
{
	QModelIndex idx = sourceModel()->index(sourceRow, 0, sourceParent);
	return sourceModel()->data(idx, Qt::UserRole).toBool();
}

QVariant XcaProxyModel::data(const QModelIndex &index, int role) const
{
	QModelIndex i;
	QString number;

	if (index.column() != 1)
		return QSortFilterProxyModel::data(index, role);

	/* Row number */
	switch (role) {
		case Qt::EditRole:
		case Qt::DisplayRole:
			for (i = index; i.isValid(); i = i.parent())
				number += QString(" %1").arg(i.row()+1);
			return QVariant(number);
		default:
			return QSortFilterProxyModel::data(index, role);
	}
	return QVariant();
}

