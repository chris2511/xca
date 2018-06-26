/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_BASE_H
#define __DB_BASE_H

#include <typeinfo>
#include "db.h"
#include "base.h"
#include "load_obj.h"
#include <QListView>
#include <QPixmap>
#include <QContextMenuEvent>
#include <QStringList>
#include <QAbstractItemModel>
#include <QHash>
#include "widgets/ExportDialog.h"
#include "pki_base.h"
#include "headerlist.h"

#define FOR_ALL_pki(pki, pki_type) \
	for(pki_type *pki=(pki_type*)rootItem->iterate(); pki; pki=(pki_type*)pki->iterate())

#define X_XCA_DRAG_DATA "application/x-xca-drag-data"

class MainWindow;
class QContextMenuEvent;
class XcaTreeView;
class NewX509;

class db_base: public QAbstractItemModel
{
	Q_OBJECT

	protected:
		static QHash<quint64, pki_base*> lookup;
		QModelIndex currentIdx;
		int secondsTimer, minutesTimer, hoursTimer;
		void _writePKI(pki_base *pki, bool overwrite);
		void _removePKI(pki_base *pki );
		void removeItem(QString k);
		QList<enum pki_type> pkitype;
		MainWindow *mainwin;
		QString class_name;
		/* Sql table containing the 'hash' of this items */
		QString sqlHashTable;
		dbheaderList allHeaders;
		virtual dbheaderList getHeaders();
		int colResizing;
		QString sqlItemSelector();
		void updateItem(pki_base *pki, QString name, QString comment);
		virtual exportType::etype clipboardFormat(QModelIndexList) const
		{
			return exportType::Separator;
		}
		bool isValidCol(int col) const;
		static XSqlQuery sqlSELECTpki(QString query,
				QList<QVariant> values = QList<QVariant>());
		void timerEvent(QTimerEvent * event);
		void restart_timer();

	public:
		template <class T> static T *lookupPki(quint64 i)
		{
			T *pki = dynamic_cast<T*>(lookup[i]);
			if (!pki && i > 0) {
				pki_base *p = lookup[i];
				QString f = QString("Invalid Type of ItemId(%1) %2 %3."
						" Expected to be %4.")
						.arg(i).arg(typeid(p).name())
						.arg(p?p->getIntName() : "<NULL item>")
						.arg(typeid(T*).name());
				qCritical("%s", CCHAR(f));
			}
			return pki;
		}
		template <class T> static T *lookupPki(QVariant v)
		{
			return lookupPki<T>(v.toULongLong());
		}
		static void flushLookup()
		{
			lookup.clear();
		}
		template <class T> static QList<T *>
				sqlSELECTpki(QString query,
				QList<QVariant> values = QList<QVariant>())
		{
			XSqlQuery q = sqlSELECTpki(query, values);
			QList<T *> x;
			while (q.next()) {
				T *pki = lookupPki<T>(q.value(0));
				if (pki)
					x << pki;
			}
			return x;
		}

		virtual pki_base *newPKI(enum pki_type type = none);
		pki_base *rootItem;
		db_base(MainWindow *mw);
		virtual void updateHeaders();
		virtual ~db_base();
		virtual void insertPKI(pki_base *pki);
		pki_base *getByName(QString desc);
		pki_base *getByReference(pki_base *refpki);
		pki_base *getByPtr(void *);
		virtual void loadContainer();
		template <class T> QList<T *> getAll()
		{
			return sqlSELECTpki<T>(
		                QString("SELECT item FROM %1")
					.arg(sqlHashTable));
		}
		virtual pki_base* insert(pki_base *item);
		virtual void inToCont(pki_base *pki);
		virtual void remFromCont(const QModelIndex &idx);

		QPixmap *loadImg(const char *name);
		void writeAll(void);
		void dump(QString dirname);
		QModelIndex index(int row, int column, const QModelIndex &parent)const;
		QModelIndex index(pki_base *pki)const;
		QModelIndex parent(const QModelIndex &index) const;
		int rowCount(const QModelIndex &parent) const;
		int columnCount(const QModelIndex &parent) const;
		QVariant data(const QModelIndex &index, int role) const;
		QVariant headerData(int section, Qt::Orientation orientation,
				int role) const;
		Qt::ItemFlags flags(const QModelIndex &index) const;
		bool setData(const QModelIndex &index, const QVariant &value, int role);
		void deleteSelectedItems(QModelIndexList indexes);
		void load_default(load_base &load);
		void insertChild(pki_base *parent, pki_base *child);
		void createSuccess(pki_base *pki);
		bool columnHidden(int col) const;
		virtual void saveHeaderState();
		void initHeaderView(QHeaderView *hv);
		void setVisualIndex(int i, int visualIndex);
		bool fixedHeaderSize(int sect);
		void colResizeStart()
		{
			colResizing++;
		}
		void colResizeEnd()
		{
			colResizing--;
		}
		virtual void store(QModelIndexList indexes);
		virtual void store(QModelIndex index) { (void)index; };
		dbheaderList getAllHeaders() {
			return allHeaders;
		}
		void pem2clipboard(QModelIndexList indexes) const;
		QString pem2QString(QModelIndexList indexes) const;

		void deletePKI(QModelIndex idx);
		QMimeData *mimeData(const QModelIndexList &indexes) const;
		void editComment(const QModelIndex &index);
		void emitDataChanged(pki_base *pki);
		bool containsType(enum pki_type t) const;
		void writeVcalendar(const QString &fname, QStringList vcal);

	public slots:
		virtual void newItem() { }
		virtual void load() { }
		void columnResetDefaults();
		virtual void showPki(pki_base *) {};
		virtual void showItem(const QModelIndex &index);
		virtual void showItem(const QString keyname);
		void sectionResized(int i, int, int newSize);
		void sortIndicatorChanged(int, Qt::SortOrder);

	signals:
		void connNewX509(NewX509 *dlg);
		void resetHeader();
		void updateHeader();
		void columnsContentChanged();
		void pkiChanged(pki_base *pki);
};

#endif
