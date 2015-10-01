/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "XcaHeaderView.h"
#include "XcaTreeView.h"
#include "XcaProxyModel.h"
#include "MainWindow.h"
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QVariant>
#include <QRegExp>


XcaTreeView::XcaTreeView(QWidget *parent)
	:QTreeView(parent)
{
	mainwin = NULL;
	setHeader(new XcaHeaderView());
	setAlternatingRowColors(true);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setEditTriggers(QAbstractItemView::EditKeyPressed);
	setRootIsDecorated(false);
	setUniformRowHeights(true);
	//setAnimated(true);

	proxy = new XcaProxyModel(this);
	setSortingEnabled(true);
	proxy->setDynamicSortFilter(true);
	sortByColumn(0, Qt::AscendingOrder);
	basemodel = NULL;
	connect(header(), SIGNAL(sectionHandleDoubleClicked(int)),
		this, SLOT(resizeColumnToContents(int)));
	connect(this, SIGNAL(doubleClicked(const QModelIndex &)),
		this, SLOT(doubleClick(const QModelIndex &)));
#if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
	header()->setSectionsClickable(true);
#else
	header()->setClickable(true);
#endif
}

XcaTreeView::~XcaTreeView()
{
	delete proxy;
}

void XcaTreeView::contextMenuEvent(QContextMenuEvent * e)
{
	QModelIndex index;
	if (!basemodel)
		return;
	index = indexAt(e->pos());
	showContextMenu(e, getIndex(index));
}

void XcaTreeView::showHideSections()
{
	if (!basemodel)
		return;
	int i, max = basemodel->columnCount(QModelIndex());
	basemodel->colResizeStart();
	for (i=0; i<max; i++) {
		if (basemodel->columnHidden(i))
			header()->hideSection(i);
		else
			header()->showSection(i);
	}
	basemodel->colResizeEnd();
	columnsResize();
}

void XcaTreeView::setMainwin(MainWindow *mw, QLineEdit *filter)
{
	mainwin = mw;
	connect(filter, SIGNAL(textChanged(const QString &)),
		this, SLOT(setFilter(const QString&)));
}

void XcaTreeView::setModel(QAbstractItemModel *model)
{
	QByteArray ba;

	basemodel = (db_base *)model;
	proxy->setSourceModel(model);
	QTreeView::setModel(proxy);

	if (basemodel) {
		connect(basemodel, SIGNAL(resetHeader()),
			header(), SLOT(resetMoves()));
		connect(basemodel, SIGNAL(resetHeader()),
			this, SLOT(columnsResize()));
		connect(header(), SIGNAL(sectionMoved(int,int,int)),
			this, SLOT(sectionMoved(int,int,int)));
		connect(header(), SIGNAL(sectionResized(int,int,int)),
			basemodel, SLOT(sectionResized(int,int,int)));
		connect(header(), SIGNAL(sortIndicatorChanged(int,Qt::SortOrder)),
			basemodel, SLOT(sortIndicatorChanged(int,Qt::SortOrder)));
		connect(basemodel, SIGNAL(columnsContentChanged()),
			this, SLOT(columnsResize()));
		connect(basemodel, SIGNAL(columnsContentChanged()),
			proxy, SLOT(invalidate()));

		basemodel->initHeaderView(header());
	}
	showHideSections();
}

void XcaTreeView::headerEvent(QContextMenuEvent *e, int col)
{
	contextMenu(e, NULL, col);
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
	QModelIndexList list;
	QItemSelection indexes = selectionModel()->selection();
	list = proxy->mapSelectionToSource(indexes).indexes();

	/* Reduce list to column 0 items */
	QModelIndexList::iterator it = list.begin();
	while (it != list.end()) {
		if ((*it).column() != 0)
			it = list.erase(it);
		else
			++it;
	}
	return list;
}

void XcaTreeView::columnsResize()
{
	int cnt, i;
	if (!basemodel)
		return;
	cnt = basemodel->columnCount(QModelIndex());
	basemodel->colResizeStart();
	for (i=0; i<cnt; i++) {
		if (!basemodel->fixedHeaderSize(i)) {
			resizeColumnToContents(i);
		}
	}
	basemodel->colResizeEnd();
}

void XcaTreeView::sectionMoved(int, int, int)
{
	int cnt = header()->count();
	for (int i=0; i<cnt; i++) {
		basemodel->setVisualIndex(i, header()->visualIndex(i));
	}
}

QModelIndex XcaTreeView::currentIndex()
{
	QModelIndex idx = QTreeView::currentIndex();
	idx = getIndex(idx);
	idx = basemodel->index(idx.row(), 0, idx.parent());
	if (!idx.isValid()) {
		QModelIndexList l = getSelectedIndexes();
		if (l.size() > 0)
			idx = l[0];
	}
	return idx;
}

void XcaTreeView::editIdx()
{
	edit(getProxyIndex(currentIndex()));
}

void XcaTreeView::setFilter(const QString &pattern)
{
	pki_base::limitPattern = QRegExp(pattern,
			Qt::CaseInsensitive, QRegExp::Wildcard);
	// Only to tell the model about the changed filter
	proxy->setFilterFixedString(pattern);
}

void XcaTreeView::deleteItems(void)
{
	QModelIndex index;
	QModelIndexList indexes = getSelectedIndexes();
	QString items, msg;
	int count = 0;
	pki_base *pki = NULL;

	if (indexes.count() == 0 || !basemodel)
		return;

	foreach(index, indexes) {
		pki = static_cast<pki_base*>(index.internalPointer());
		items += "'" + pki->getIntName() + "' ";
		count++;
	}

	if (count == 1)
		msg = pki->getMsg(pki_base::msg_delete).arg(pki->getIntName());
	else
		msg = pki->getMsg(pki_base::msg_delete_multi).arg(count).
				arg(items);

	if (!XCA_OKCANCEL(msg))
		return;

	foreach(index, indexes) {
		basemodel->deletePKI(index);
	}
}

void XcaTreeView::storeItems(void)
{
	QModelIndexList indexes = getSelectedIndexes();
	if (basemodel) {
		try {
			switch (indexes.size()) {
			case 0: return;
			case 1: basemodel->store(indexes[0]); return;
			default: basemodel->store(getSelectedIndexes());
				return;
			}
		} catch (errorEx &err) {
			MainWindow::Error(err);
		}
	}
}

void XcaTreeView::showItems(void)
{
	if (basemodel) {
		QModelIndexList indexes = getSelectedIndexes();
		foreach(QModelIndex index, indexes)
			basemodel->showItem(index);
	}
}

void XcaTreeView::newItem(void)
{
	if (basemodel)
		basemodel->newItem();
}

void XcaTreeView::load(void)
{
	if (basemodel)
		basemodel->load();
}

void XcaTreeView::doubleClick(const QModelIndex &m)
{
	if (basemodel)
		basemodel->showItem(getIndex(m));
}

void XcaTreeView::pem2clipboard(void)
{
	if (basemodel)
		basemodel->pem2clipboard(getSelectedIndexes());
}

void XcaTreeView::headerDetails(void)
{
	if (curr_hd && curr_hd->id > 0 && mainwin)
		mainwin->getResolver()->searchOid(QString::number(curr_hd->id));
}

void XcaTreeView::columnRemove(void)
{
	if (curr_hd->action)
		curr_hd->action->setChecked(false);
}

void XcaTreeView::contextMenu(QContextMenuEvent *e, QMenu *parent, int col)
{
	int shown = 0;
	tipMenu *menu, *dn, *v3ext, *current, *v3ns;
	QAction *a, *sep;
	dbheader *hd;
	dbheaderList allHeaders = basemodel->getAllHeaders();

	menu = new tipMenu(QString(), mainwin);
	dn = new tipMenu(tr("Subject entries"), mainwin);
	v3ext = new tipMenu(tr("X509v3 Extensions"), mainwin);
	v3ns = new tipMenu(tr("Netscape extensions"), mainwin);
	menu->addAction(tr("Reset"), basemodel, SLOT(columnResetDefaults()));
	if (col >= 0 && col < allHeaders.size()) {
		curr_hd = allHeaders[col];
		menu->addAction(tr("Remove Column"), this,SLOT(columnRemove()));
		if (curr_hd->id > 0)
			menu->addAction(tr("Details"), this,
						SLOT(headerDetails()));
	} else {
		curr_hd = NULL;
	}
	sep = menu->addSeparator();
	foreach(hd, allHeaders) {
		switch (hd->type) {
			case dbheader::hd_x509name:
				current = dn;
				break;
			case dbheader::hd_v3ext:
				current = v3ext;
				break;
			case dbheader::hd_v3ext_ns:
				if (pki_x509::disable_netscape)
					continue;
				current = v3ns;
				break;
			default:
				current = menu;
				break;
		}
		a = current->addAction(hd->getName());
		a->setCheckable(true);
		a->setChecked(hd->show);
		a->setToolTip(hd->getTooltip());
		hd->action = a;
	}
	if (!dn->isEmpty() || !v3ext->isEmpty())
		menu->insertSeparator(sep);

	if (!dn->isEmpty())
		menu->insertMenu(sep, dn);
	else
		delete dn;

	if (!v3ext->isEmpty()) {
		if (!v3ns->isEmpty()) {
			v3ext->addSeparator();
			v3ext->addMenu(v3ns);
		} else {
			delete v3ns;
		}
		menu->insertMenu(sep, v3ext);
	} else {
		delete v3ext;
		delete v3ns;
	}
	if (parent) {
		parent->addSeparator();
		parent->addMenu(menu)->setText(tr("Columns"));
		parent->exec(e->globalPos());
	} else {
		menu->exec(e->globalPos());
	}
	foreach(hd, allHeaders) {
		if (hd->action)
			hd->show = hd->action->isChecked();
		shown += hd->show ? 1 : 0;
		hd->action = NULL;
	}
	if (!shown)
		allHeaders[0]->show = true;
        delete menu;
	if (parent)
		delete parent;
	showHideSections();
}

void XcaTreeView::showContextMenu(QContextMenuEvent *e,
		const QModelIndex &idx)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport = NULL;
	QModelIndexList indexes = getSelectedIndexes();
	QModelIndex index;

	index = idx.isValid() ? idx : currentIndex();
	menu->addAction(tr("New"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	menu->addAction(tr("Paste PEM data"), mainwin, SLOT(pastePem()));

	if (indexes.size() == 1)
		menu->addAction(tr("Rename"), this, SLOT(editIdx()));

	if (indexes.size() > 0) {
		menu->addAction(tr("Delete"), this, SLOT(deleteItems()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("Clipboard"), this,
				SLOT(pem2clipboard()));
		subExport->addAction(tr("File"), this, SLOT(storeItems()));
	}

	fillContextMenu(menu, subExport, index, indexes);

	contextMenu(e, menu, -1);
}
