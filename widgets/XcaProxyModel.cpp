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
	db_base *db = dynamic_cast<db_base *>(sourceModel());
	if (!db)
		return QSortFilterProxyModel::lessThan(left, right);

	dbheaderList headers = db->getAllHeaders();
	if (left.column() < 0 || left.column() >= headers.size() ||
	    right.column() < 0 || right.column() >= headers.size())
	{
		qDebug("BAD COLUMN: %d %d\n", left.column(), right.column());
		return true;
	}
	dbheader *hd_left = headers[left.column()];
	dbheader *hd_right = headers[right.column()];
	if (hd_left->isNumeric() && hd_right->isNumeric()) {
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
	if (hd_left->type == dbheader::hd_asn1time &&
	    hd_right->type == dbheader::hd_asn1time)
	{
		pki_base *l = db_base::fromIndex(left);
		pki_base *r = db_base::fromIndex(right);
		if (l && r)
			return  l->column_a1time(hd_left) <
				r->column_a1time(hd_right);
	}
	return QSortFilterProxyModel::lessThan(left, right);
}

bool XcaProxyModel::filterAcceptsRow(int sourceRow,
         const QModelIndex &sourceParent) const
{
	if (!sourceModel())
		return false;
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

