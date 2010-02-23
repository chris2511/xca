/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_base.h"
#include "exception.h"
#include <qmessagebox.h>
#include <qdir.h>
#include <qlistview.h>
#include <qdir.h>

#include "widgets/MainWindow.h"
#include "widgets/ImportMulti.h"

db_base::db_base(QString db, MainWindow *mw)
	:QAbstractItemModel(NULL)
{
	dbName = db;
	rootItem = newPKI();
	headertext.clear();
	mainwin = mw;
	currentIdx = QModelIndex();
	view = NULL;
	class_name = "base";
	for (size_t i =0; i<ARRAY_SIZE(pkitype); i++)
		pkitype[i] = none;
}

db_base::~db_base()
{
	delete rootItem;
}

pki_base *db_base::newPKI(db_header_t *head){
	return new pki_base("rootItem");
}

void db_base::createSuccess(pki_base *pki)
{
	if (!pki)
		return;

	QMessageBox::information(mainwin, XCA_TITLE,
		tr("Successfully created the %1 '%2'").
		arg(pki->getFriendlyClassName()).
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
			if (pki)
				inToCont(pki);
next:
			if (mydb.next())
				break;
		}
	}
	view->columnsResize();
}

void db_base::insertPKI(pki_base *pki)
{
	unsigned char *p;
	int size;
	QString name;
	db mydb(dbName);

	p = pki->toData(&size);

	if (p) {
		name = mydb.uniq_name(pki->getIntName(), pki->getType());
		pki->setIntName(name);
		mydb.add(p, size, pki->getVersion(), pki->getType(), name);
		OPENSSL_free(p);
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
				delete_txt.arg(pki->getIntName()),
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
	unsigned char *p;
	int size;
	db mydb(dbName);

	p = pki->toData(&size);

	if (p) {
		mydb.set(p, size, pki->getVersion(), pki->getType(), pki->getIntName());
		OPENSSL_free(p);
	}
}

void db_base::deleteSelectedItems(XcaTreeView* view)
{
	QModelIndexList indexes = view->getSelectedIndexes();
	QModelIndex index;
	QString items, single, msg;
	int count = 0;

	if (indexes.count() == 0)
		return;

	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki_base *pki = static_cast<pki_base*>(index.internalPointer());
		items += "'" + pki->getIntName() + "' ";
		single = pki->getIntName();
		count++;
	}
	if (count == 1)
		msg = delete_txt.arg(single);
	else
		msg = delete_multi_txt.arg(count).arg(items);

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
	pki_base *item;
	if (!parent.isValid()) {
		if (headertext.count())
			return headertext.count();
		item = rootItem;
	} else {
		item = static_cast<pki_base*>(parent.internalPointer());
	}
	return item->columns();
}

QVariant db_base::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();

	pki_base *item = static_cast<pki_base*>(index.internalPointer());
	switch (role) {
		case Qt::EditRole:
		case Qt::DisplayRole:
			return item->column_data(index.column());
		case Qt::DecorationRole:
			return item->getIcon(index.column());
	}
	return QVariant();
}

QVariant db_base::headerData(int section, Qt::Orientation orientation,
		int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
		return headertext[section];

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

