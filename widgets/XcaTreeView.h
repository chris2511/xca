/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCATREEVIEW_H
#define __XCATREEVIEW_H

#include <QTreeView>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QSortFilterProxyModel>
#include <QTimer>

class database_model;
class MainWindow;
class db_base;
class dbheader;
class pki_base;
class QKeyEvent;
class QContextMenuEvent;
class QMenu;
class load_base;
class ExportDialog;

class XcaTreeView: public QTreeView
{
	Q_OBJECT

	dbheader *curr_hd{};
	QTimer throttle{};

  protected:
	db_base *basemodel{};
	QSortFilterProxyModel *proxy{};
	MainWindow *mainwin{};

  public:
	XcaTreeView(QWidget *parent = nullptr);
	virtual ~XcaTreeView();
	void contextMenuEvent(QContextMenuEvent *e);
	void setModel(QAbstractItemModel *model);
	void setMainwin(MainWindow *mw, QLineEdit *filter);
	QModelIndex getIndex(const QModelIndex &index);
	QModelIndex getProxyIndex(const QModelIndex &index);
	QModelIndexList getSelectedIndexes();
	void headerEvent(QContextMenuEvent *e, int col);
	QModelIndex currentIndex();
	void showContextMenu(QContextMenuEvent *e,
				const QModelIndex &index);
	virtual void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes)
	{
		(void)menu; (void)subExport; (void)index; (void)indexes;
	}
	void contextMenu(QContextMenuEvent *e,
			QMenu *parent = NULL, int sect = -1);
	void keyPressEvent(QKeyEvent *event);
	void changeEvent(QEvent *event);
	virtual void showPki(pki_base *) {};
	virtual void exportItems(const QModelIndexList &indexes);
	virtual void load_default(load_base *load);
	virtual ExportDialog *exportDialog(const QModelIndexList &indexes);

   public slots:
	void changeView();
	void showHideSections();
	void sectionMoved(int idx, int oldI, int newI);
	void columnsResize();
	void editIdx();
	void setFilter(const QString &pattern);
	void deleteItems();
	void exportItems();
	void showItems();
	void newItem();
	void doubleClick(const QModelIndex &m);
	void pem2clipboard();
	void headerDetails();
	void columnRemove();
	void columnsChanged();
	void editComment();
	void showItem(pki_base *);
	void showItem(const QModelIndex &index);
	void showItem(const QString &name);
	void itemSelectionChanged(const QModelIndex &m, const QModelIndex &);
};
#endif
