/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_base.h"
#include "func.h"
#include "exception.h"
#include <QtGui/QMessageBox>
#include <QtGui/QListView>
#include <QtCore/QDir>
#include "widgets/MainWindow.h"
#include "widgets/ImportMulti.h"

db_base::db_base(QString db, MainWindow *mw)
	:QAbstractItemModel(NULL)
{
	dbName = db;
	rootItem = newPKI();
	mainwin = mw;
	colResizing = 0;
	currentIdx = QModelIndex();
	view = NULL;
	class_name = "base";
	for (size_t i =0; i<ARRAY_SIZE(pkitype); i++)
		pkitype[i] = none;
	allHeaders << new dbheader(HD_internal_name, true, tr("Internal name"));
}

db_base::~db_base()
{
	saveHeaderState();
	delete rootItem;
}

pki_base *db_base::newPKI(db_header_t *)
{
	return new pki_base("rootItem");
}

void db_base::createSuccess(pki_base *pki)
{
	if (!pki)
		return;

	QMessageBox::information(mainwin, XCA_TITLE,
		pki->getMsg(pki_base::msg_create).
			arg(pki->getIntName()));
}

void db_base::remFromCont(QModelIndex &idx)
{
	if (!idx.isValid())
		return;
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	pki_base *parent_pki = pki->getParent();
	int row = pki->row();

	beginRemoveRows(parent(idx), row, row);
	parent_pki->takeChild(pki);
	endRemoveRows();
	view->columnsResize();
}

void db_base::loadContainer()
{
	db mydb(dbName);
	unsigned char *p = NULL;
	db_header_t head;
	pki_base *pki;

	for (int i=0; pkitype[i] != none; i++) {
		mydb.first();
		while (mydb.find(pkitype[i], QString()) == 0) {
			QString s;
			p = mydb.load(&head);
			if (!p) {
				printf("Load was empty !\n");
				goto next;
			}
			pki = newPKI(&head);
			if (pki->getVersion() < head.version) {
				printf("Item[%s]: Version %d "
					"> known version: %d -> ignored\n",
					head.name, head.version,
					pki->getVersion()
				);
				free(p);
				delete pki;
				goto next;
			}
			pki->setIntName(QString::fromUtf8(head.name));

			try {
				pki->fromData(p, &head);
			}
			catch (errorEx &err) {
				err.appendString(pki->getIntName());
				mainwin->Error(err);
				delete pki;
				pki = NULL;
			}
			free(p);
			if (pki) {
				inToCont(pki);
			}
next:
			if (mydb.next())
				break;
		}
	}

	int max = allHeaders.count();
	mydb.first();
	if (!mydb.find(setting, class_name + "_hdView")) {
		QByteArray ba;
		char *p;
		if ((p = (char *)mydb.load(&head))) {
			ba = QByteArray(p, head.len - sizeof(db_header_t));
			free(p);
		}
		if (head.version != 4)
			return;
		for (int i=0; i<max; i++) {
			if (ba.size() == 0)
				break;
			try {
				allHeaders[i]->fromData(ba);
			}  catch (errorEx()) {
				for (int j=0; j<=i; i++) {
					allHeaders[i]->reset();
				}
				break;
			}
		}
	}
	view->columnsResize();
	return;
}

void db_base::saveHeaderState()
{
	QByteArray ba;
	if (dbName.isEmpty())
		return;
	int max = allHeaders.count();
	for (int i=0; i<max; i++) {
		ba += allHeaders[i]->toData();
	}
	db mydb(dbName);
	mydb.set((const unsigned char *)ba.constData(), ba.size(), 4,
		setting, class_name + "_hdView");
}

void db_base::setVisualIndex(int i, int visualIndex)
{
	if (colResizing)
		return;
	allHeaders[i]->visualIndex = visualIndex;
}

void db_base::sectionResized(int i, int old, int newSize)
{
	if (!allHeaders[i]->show || newSize <= 0 || colResizing)
		return;
	allHeaders[i]->size = newSize;
}

bool db_base::fixedHeaderSize(int sect)
{
	return allHeaders[sect]->size != -1;
}

void db_base::initHeaderView(QHeaderView *hv)
{
	int max = allHeaders.count();
	colResizeStart();
	for (int i=0; i<max; i++) {
		allHeaders[i]->setupHeaderView(i, hv);
	}
	for (int i=0; i<max; i++) {
		if (allHeaders[i]->visualIndex == -1)
			continue;
		if (hv->visualIndex(i) != allHeaders[i]->visualIndex) {
			hv->moveSection(hv->visualIndex(i),
					allHeaders[i]->visualIndex);
		}
	}
	colResizeEnd();
}

void db_base::sortIndicatorChanged(int logicalIndex, Qt::SortOrder order)
{
	int max = allHeaders.count();
	for (int i=0; i<max; i++) {
		allHeaders[i]->sortIndicator = -1;
	}
	allHeaders[logicalIndex]->sortIndicator = order;
}

void db_base::insertPKI(pki_base *pki)
{
	QString name;
	db mydb(dbName);
	QByteArray ba = pki->toData();

	if (ba.count() > 0) {
		name = mydb.uniq_name(pki->getIntName(), pki->getType());
		pki->setIntName(name);
		mydb.add((const unsigned char*)ba.constData(), ba.count(),
			pki->getVersion(), pki->getType(), name);
	}
	inToCont(pki);
	view->columnsResize();
}

void db_base::delete_ask()
{
	if (!currentIdx.isValid())
		return;
	pki_base *pki = static_cast<pki_base*>(currentIdx.internalPointer());

	if (QMessageBox::question(mainwin, XCA_TITLE,
				pki->getMsg(pki_base::msg_delete)
					.arg(pki->getIntName()),
				QMessageBox::Ok | QMessageBox::Cancel) !=
				QMessageBox::Ok)
		 return;

	deletePKI();
}

void db_base::deletePKI()
{
	if (!currentIdx.isValid())
		return;
	pki_base *pki = static_cast<pki_base*>(currentIdx.internalPointer());
	try {
		pki->deleteFromToken();

		remFromCont(currentIdx);

		db mydb(dbName);
		mydb.find(pki->getType(), pki->getIntName());
		mydb.erase();
		delete pki;
	} catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void db_base::updatePKI(pki_base *pki)
{
	db mydb(dbName);

	QByteArray ba = pki->toData();

	if (ba.count() > 0) {
		mydb.set((const unsigned char*)ba.constData(), ba.count(),
			pki->getVersion(), pki->getType(), pki->getIntName());
	}
}

void db_base::deleteSelectedItems(XcaTreeView* view)
{
	QModelIndexList indexes = view->getSelectedIndexes();
	QModelIndex index;
	QString items, msg;
	int count = 0;
	pki_base *pki = NULL;

	if (indexes.count() == 0)
		return;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki = static_cast<pki_base*>(index.internalPointer());
		items += "'" + pki->getIntName() + "' ";
		count++;
	}
	if (count == 1)
		msg = pki->getMsg(pki_base::msg_delete).arg(pki->getIntName());
	else
		msg = pki->getMsg(pki_base::msg_delete_multi).arg(count).
				arg(items);

	if (QMessageBox::question(mainwin, XCA_TITLE, msg,
				QMessageBox::Ok | QMessageBox::Cancel) !=
				QMessageBox::Ok)
		return;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		currentIdx = index;
		deletePKI();
	}
	currentIdx = QModelIndex();
}

void db_base::showSelectedItems(XcaTreeView* view)
{
	QModelIndexList indexes = view->getSelectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		currentIdx = index;
		showItem();
	}
	currentIdx = QModelIndex();
}

void db_base::storeSelectedItems(XcaTreeView* view)
{
	QModelIndexList indexes = view->getSelectedIndexes();
	QModelIndex index;
	QString items;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		try {
			currentIdx = index;
			store();
		} catch (errorEx &err) {
			MainWindow::Error(err);
		}

	}
	currentIdx = QModelIndex();
}

void db_base::showItem(const QModelIndex &index)
{
	showPki(static_cast<pki_key*>(index.internalPointer()));
}

void db_base::showItem(const QString name)
{
	pki_base *pki = getByName(name);
	if (pki)
		showPki(pki);
}

void db_base::insertChild(pki_base *parent, pki_base *child)
{
	QModelIndex idx = QModelIndex();

	if (parent == child || parent == NULL)
		parent = rootItem;

	if (parent != rootItem)
		idx = index(parent);

	beginInsertRows(idx, 0, 0);
	parent->insert(0,child);
	endInsertRows();
}

void db_base::inToCont(pki_base *pki)
{
	insertChild(rootItem, pki);
}

pki_base *db_base::getByName(QString desc)
{
	FOR_ALL_pki(pki, pki_base) {
		if (pki->getIntName() == desc)
			return pki;
	}
	return NULL;
}

pki_base *db_base::getByReference(pki_base *refpki)
{
	if (refpki == NULL)
		return NULL;
	FOR_ALL_pki(pki, pki_base) {
		if (refpki->compare(pki))
			return pki;
	}
	return NULL;
}

QStringList db_base::getDesc()
{
	QStringList x;
	x.clear();
	FOR_ALL_pki(pki, pki_base) {
		x.append(pki->getIntName());
	}
	return x;
}

pki_base *db_base::insert(pki_base *item)
{
	insertPKI(item);
	return item;
}

void db_base::writeAll(void)
{
}

void db_base::dump(QString dirname)
{
	dirname += QDir::separator() + class_name;
	QDir d(dirname);
	if (!d.exists() && !d.mkdir(dirname)) {
		throw errorEx("Could not create directory '" + dirname + "'");
	}

	try {
		FOR_ALL_pki(pki, pki_base) {
			pki->writeDefault(dirname);
		}
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

QModelIndex db_base::index(int row, int column, const QModelIndex &parent)
	                const
{
	pki_base *parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<pki_base*>(parent.internalPointer());

	pki_base *childItem = parentItem->child(row);
	if (childItem)
		return createIndex(row, column, childItem);
	else
		return QModelIndex();
}

QModelIndex db_base::index(pki_base *pki) const
{
	return createIndex(pki->row(), 0, pki);
}

QModelIndex db_base::parent(const QModelIndex &idx) const
{
	if (!idx.isValid())
		return QModelIndex();

	pki_base *childItem = static_cast<pki_base*>(idx.internalPointer());
	pki_base *parentItem = childItem->getParent();
#if 0
	if (parentItem == NULL) {
		printf("Item: (%s) %s: parent == NULL\n",
			childItem->className(), CCHAR(childItem->getIntName()));
	}
	printf("Parent of:%s(%p) %p %p\n",
	CCHAR(childItem->getIntName()), childItem, parentItem, rootItem);
#endif
	if (parentItem == rootItem || parentItem == NULL)
		return QModelIndex();

	return index(parentItem);
}

int db_base::rowCount(const QModelIndex &parent) const
{
	pki_base *parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<pki_base*>(parent.internalPointer());

	//printf("%s rows=%d\n", CCHAR(parentItem->getIntName()), parentItem->childCount());
	return parentItem->childCount();
}

int db_base::columnCount(const QModelIndex &parent) const
{
	return allHeaders.count();
}

QVariant db_base::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();
	dbheader *hd = allHeaders[index.column()];
	pki_base *item = static_cast<pki_base*>(index.internalPointer());
	switch (role) {
		case Qt::EditRole:
		case Qt::DisplayRole:
			return item->column_data(hd->id);
		case Qt::DecorationRole:
			return item->getIcon(hd->id);
		case Qt::TextAlignmentRole:
			return hd->isNumeric() ? Qt::AlignRight : Qt::AlignLeft;
		case Qt::FontRole: {
			if (hd->isNumeric())
				return QVariant(QFont("Monospace"));
			return QVariant(QApplication::font());
		}
	}
	return QVariant();
}
#if 0
static QString getHeaderViewInfo(int sect, dbheader *h)
{
	return QString("H[%1] Show:%2%3 Size:%4 VI:%5 Indi:%6").
		arg(sect).arg(h->show).arg(h->showDefault).arg(h->size).
		arg(h->visualIndex).arg(h->sortIndicator);
}
#endif
QVariant db_base::headerData(int section, Qt::Orientation orientation,
		int role) const
{
	if (orientation == Qt::Horizontal) {
		switch (role) {
		case Qt::DisplayRole:
			return QVariant(allHeaders[section]->name);
		case Qt::ToolTipRole:
#if 0
			return getHeaderViewInfo(section, allHeaders[section]);
#endif
			return QVariant(allHeaders[section]->tooltip);
		}
	}
	return QVariant();
}

Qt::ItemFlags db_base::flags(const QModelIndex &index) const
{
	if (!index.isValid())
		return Qt::ItemIsEnabled;

	if (index.column() == 0)
		return QAbstractItemModel::flags(index) | Qt::ItemIsEditable;
	else
		return QAbstractItemModel::flags(index);
}

bool db_base::setData(const QModelIndex &index, const QVariant &value, int role)
{
	QString on, nn;
	pki_base *item;
	if (index.isValid() && role == Qt::EditRole) {
		nn = value.toString();
		db mydb(dbName);
		item = static_cast<pki_base*>(index.internalPointer());
		on = item->getIntName();
		try {
			mydb.rename(item->getType(), on, nn);
			item->setIntName(nn);
			emit dataChanged(index, index);
			return true;
		} catch (errorEx &err) {
			mainwin->Error(err);
		}
	}
	return false;
}

void db_base::load_default(load_base &load)
{
	QStringList slist = QFileDialog::getOpenFileNames(mainwin, load.caption,
			mainwin->getPath(), load.filter);

	if (!slist.count())
		return;

	QString fn = QDir::convertSeparators(slist[0]);
	mainwin->setPath(fn.mid(0, fn.lastIndexOf(QRegExp("[/\\\\]")) ));

	ImportMulti *dlgi = new ImportMulti(mainwin);
	for (QStringList::Iterator it = slist.begin(); it != slist.end(); ++it) {
		QString s = *it;
		s = QDir::convertSeparators(s);
		pki_base *item = NULL;
		try {
			item = load.loadItem(s);
			dlgi->addItem(item);
		}
		catch (errorEx &err) {
			MainWindow::Error(err);
			delete item;
		}
	}
	dlgi->execute();
	delete dlgi;
}

void db_base::edit()
{
	if (!currentIdx.isValid())
		return;
	view->edit(view->getProxyIndex(currentIdx));
}

void db_base::showItem()
{
	if (!currentIdx.isValid())
		return;
	showItem(currentIdx);
}

bool db_base::columnHidden(int col) const
{
	return !allHeaders[col]->show;
}

void db_base::columnResetDefaults()
{
	dbheader *hd;
	foreach(hd, allHeaders) {
		hd->reset();
	}
	emit resetHeader();
}

bool db_base::isNumericCol(int col) const
{
	return allHeaders[col]->isNumeric();
}

void db_base::showHeaderMenu(QContextMenuEvent *e, int sect)
{
	contextMenu(e, NULL, sect);
}

void db_base::contextMenu(QContextMenuEvent *e, QMenu *parent, int sect)
{
	int shown = 0;
	QMenu *menu = new QMenu(mainwin);
	QMenu *dn = NULL;
	QAction *a;
	dbheader *hd;
	menu->addAction(tr("Reset"), this, SLOT(columnResetDefaults()));
	menu->addSeparator();
	foreach(hd, allHeaders) {
		if (hd->isNid()) {
			if (!dn)
				dn = menu->addMenu(tr("Subject entries"));
			a = dn->addAction(hd->name);
		} else {
			a = menu->addAction(hd->name);
		}
		a->setCheckable(true);
		a->setChecked(hd->show);
		if (!hd->tooltip.isEmpty())
			a->setToolTip(hd->tooltip);
		hd->action = a;
	}

	if (parent) {
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
	emit updateHeader();
}
