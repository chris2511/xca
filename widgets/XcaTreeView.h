/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCATREEVIEW_H
#define __XCATREEVIEW_H

#include "lib/db_base.h"
#include <QtGui/QTreeView>
#include <QtGui/QItemSelectionModel>
#include <QtGui/QSortFilterProxyModel>
#include <QtGui/QHeaderView>

class MainWindow;
class QLineEdit;

class XcaTreeView: public QTreeView
{
	Q_OBJECT
   protected:
	db_base *basemodel;
	QSortFilterProxyModel *proxy;
	MainWindow *mainwin;

   public:
	XcaTreeView(QWidget *parent = 0);
	virtual ~XcaTreeView();
	void contextMenuEvent(QContextMenuEvent *e);
	virtual void setModel(QAbstractItemModel *model=NULL);
	void setMainwin(MainWindow *mw, QLineEdit *filter);
	QModelIndex getIndex(const QModelIndex &index);
	QModelIndex getProxyIndex(const QModelIndex &index);
	QModelIndexList getSelectedIndexes();
	void headerEvent(QContextMenuEvent *e, int col);
	QModelIndex currentIndex();
	void showContextMenu(QContextMenuEvent *e,
				const QModelIndex &index);
	virtual void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes) {}
	void contextMenu(QContextMenuEvent *e,
			QMenu *parent = NULL, int sect = -1);

   public slots:
	void showHideSections();
	void sectionMoved(int idx, int oldI, int newI);
	void columnsResize();
	void editIdx();
	void setFilter(const QString &pattern);
	void deleteItems(void);
	void storeItems(void);
	void showItems(void);
	void newItem(void);
	void doubleClick(const QModelIndex &m);
	void load(void);
	void pem2clipboard(void);
};
#endif
