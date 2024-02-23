/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_BASE_H
#define __DB_BASE_H

#include <typeinfo>
#include "base.h"
#include "pki_base.h"
#include "headerlist.h"

#include <QStringList>
#include <QAbstractItemModel>
#include <QHash>

#define X_XCA_DRAG_DATA "application/x-xca-drag-data"

class QContextMenuEvent;
class XcaTreeView;
class NewX509;

class db_base: public QAbstractItemModel
{
	Q_OBJECT

	protected:
		a1time minuteMarker{}, hourMarker{};
		QTimer maintenanceTimer{};
		QList<enum pki_type> pkitype{};
		QList<enum pki_type> pkitype_depends{};
		QString class_name{};
		/* Sql table containing the 'hash' of this items */
		QString sqlHashTable{};
		dbheaderList allHeaders{};
		int colResizing{};
		bool treeview{ true };
		pki_base *rootItem{};
		pki_base *treeItem{};
		QVariant selected{};

		void _writePKI(pki_base *pki, bool overwrite);
		virtual dbheaderList getHeaders();
		QString sqlItemSelector();
		bool isValidCol(int col) const;

	public:
		void restart_timer();
		void updateItem(pki_base *pki);

		virtual pki_base *newPKI(enum pki_type type = none);
		db_base(const char *classname);
		virtual void updateHeaders();
		virtual ~db_base();
		virtual pki_base *insertPKI(pki_base *pki);
		pki_base *getByName(QString desc);
		pki_base *getByReference(pki_base *refpki);
		virtual void loadContainer();
		void reloadContainer(const QList<enum pki_type> &typelist);
		virtual pki_base* insert(pki_base *item);
		virtual void inToCont(pki_base *pki);
		virtual void remFromCont(const QModelIndex &idx);
		void changeView();
		int exportFlags(const QModelIndexList &indexes) const;
		virtual int exportFlags(const QModelIndex &) const
		{
			return 0;
		}
		virtual void exportItem(const QModelIndex &,
			const pki_export *, XFile &) const { };
		virtual void exportItems(const QModelIndexList &indexes,
			const pki_export *xport, XFile &file) const;

		void dump(const QString &dirname) const;
		QModelIndex index(int row, int column,
				const QModelIndex &parent = QModelIndex()) const;
		QModelIndex index(pki_base *pki) const;
		QModelIndex parent(const QModelIndex &index) const;
		int rowCount(const QModelIndex &parent = QModelIndex()) const;
		int allItemsCount() const
		{
			return rootItem->childCount();
		}
		int columnCount(const QModelIndex &parent) const;
		QVariant data(const QModelIndex &index, int role) const;
		QVariant headerData(int section, Qt::Orientation orientation,
				int role) const;
		Qt::ItemFlags flags(const QModelIndex &index) const;
		bool setData(const QModelIndex &index, const QVariant &value, int role);
		void deleteSelectedItems(QModelIndexList indexes);
		static pki_base *fromIndex(const QModelIndex &index)
		{
			if (!index.isValid())
				return NULL;
			return static_cast<pki_base*>(index.internalPointer());
		}
		template <class T>
		static T *fromIndex(const QModelIndex &index)
		{
			return dynamic_cast<T*>(fromIndex(index));
		}
		void insertChild(pki_base *child, pki_base *parent = NULL);
		int rownumber(const pki_base *child) const;
		void createSuccess(const pki_base *pki) const;
		bool columnHidden(int col) const;
		virtual void saveHeaderState();
		void initHeaderView(QHeaderView *hv);
		void setVisualIndex(int i, int visualIndex);
		bool fixedHeaderSize(int sect);
		bool treeViewMode()
		{
			return treeview;
		}
		void colResizeStart()
		{
			colResizing++;
		}
		void colResizeEnd()
		{
			colResizing--;
		}
		dbheaderList getAllHeaders() {
			return allHeaders;
		}
		QString pem2QString(QModelIndexList indexes) const;

		void deletePKI(QModelIndex idx);
		QMimeData *mimeData(const QModelIndexList &indexes) const;
		void emitDataChanged(pki_base *pki);
		bool containsType(enum pki_type t) const;
		void writeVcalendar(XFile &file, QStringList vcal) const;

	public slots:
		virtual void newItem() { }
		void columnResetDefaults();
		void sectionResized(int i, int, int newSize);
		void sortIndicatorChanged(int, Qt::SortOrder);
		void setSelected(const QVariant &v);
		void timerMaintenance();

	signals:
		void resetHeader() const;
		void updateHeader() const;
		void columnsContentChanged() const;
		void pkiChanged(pki_base *pki) const;
};

#endif
