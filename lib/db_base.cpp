/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           


#include "db_base.h"
#include "exception.h"
#include <Qt/qmessagebox.h>
#include <Qt/qdir.h>
#include <Qt/qlistview.h>
#include <Qt/qdir.h>
#ifdef WIN32
#include <direct.h>     // to define mkdir function
#include <windows.h>    // to define mkdir function
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include "widgets/MainWindow.h"
//#include "widgets/ImportMulti.h"


db_base::db_base(QString db, MainWindow *mw) 
	:QAbstractItemModel(NULL)
{
	dbName = db;
	rootItem = newPKI();
	printf("New DB: %s\n", CCHAR(db));
	headertext.clear();
	mainwin = mw;
}

db_base::~db_base()
{
	FOR_ALL_pki(pki, pki_base)
		rootItem->freeChild(pki);
	delete rootItem;
}

pki_base *db_base::newPKI(){
	return new pki_base("rootItem");
}

void db_base::remFromCont(pki_base *ref)
{
}

void db_base::loadContainer()
{
	db mydb(dbName);
	unsigned char *p;
	db_header_t head;
	
	pki_base *pb, *pki;
	pb = newPKI();
	while ( mydb.find(pb->getType(), NULL) == 0 ) {
		QString s;
		p = mydb.load(&head);
		if (!p) {
			printf("Load was empty !\n");
			break;
		}
		//printf("load item: %s\n",head.name);
		if (pb->getVersion() < head.version) {
			free(p);
			printf("Item[%s]: Version %d > known version: %d -> ignored\n",
					head.name, head.version, pb->getVersion() );
			continue;
		}
		pki = newPKI();
		s = head.name;
		pki->setIntName(s);

		pki->fromData(p, &head);
		inToCont(pki);
		if (mydb.next() != 0)
			break;
	}
	delete pb;
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
		mydb.add(p, size, pki->getVersion(), pki->getType(), name.toAscii());
		OPENSSL_free(p);
	}
	inToCont(pki);
}

void db_base::deletePKI(QModelIndex &index)
{
	pki_base *pki = static_cast<pki_base*>(index.internalPointer());
	int row = pki->row();
	
	printf("Deleting item: %s\n", CCHAR(pki->getIntName()));
	
	beginRemoveRows(parent(index), row, row);
	
	db mydb(dbName);
	mydb.find(pki->getType(), CCHAR(pki->getIntName()));
	mydb.erase();
	remFromCont(pki);
	pki->getParent()->freeChild(pki);
	
	endRemoveRows();
}

void db_base::updatePKI(pki_base *pki)
{
	unsigned char *p;
	int size;
	db mydb(dbName);

	printf("Updating item: %s\n", CCHAR(pki->getIntName()));
	p = pki->toData(&size);
	
	if (p) {
		mydb.set(p, size, pki->getVersion(), pki->getType(),
				CCHAR(pki->getIntName()));
		OPENSSL_free(p);
	}
}

void db_base::deleteSelectedItems(QAbstractItemView* view)
{
	printf("Delete selected items\n");
	QItemSelectionModel *selectionModel = view->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;
	
	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		pki_base *pki = static_cast<pki_base*>(index.internalPointer());
		items += "'" + pki->getIntName() + "' ";
	}
	
	if (QMessageBox::information(mainwin, tr(XCA_TITLE),
				delete_txt + ": " + items + " ?\n" ,
				tr("Delete"), tr("Cancel"))
        ) return;
	
	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		deletePKI(index);
	}
}

void db_base::showSelectedItems(QAbstractItemView* view)
{
	QItemSelectionModel *selectionModel = view->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;
	
	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		showItem(index);
	}
}

void db_base::storeSelectedItems(QAbstractItemView* view)
{
	QItemSelectionModel *selectionModel = view->selectionModel();
	QModelIndexList indexes = selectionModel->selectedIndexes();
	QModelIndex index;
	QString items;
	
	foreach(index, indexes) {
		if (index.column() != 0)
			continue;
		try {
			store(index);
		} catch (errorEx &err) {
			MainWindow::Error(err);
		}
		
	}
}

void db_base::inToCont(pki_base *pki)
{
	static int i=0;
	int row = rootItem->childCount()+1;

	beginInsertRows(QModelIndex(), row, row);
	rootItem->append(pki);
	pki->setParent(rootItem);
	endInsertRows();
	printf("insertRow %d\n", ++i);
}

pki_base *db_base::getByName(QString desc)
{
	if (desc == "" ) return NULL;
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
	dirname += QDir::separator() + dbName;	
	QDir d(dirname);
	if ( ! d.exists() && !d.mkdir(dirname)) {
		throw errorEx("Could not create directory '" + dirname + "'");
	}

	FOR_ALL_pki(pki, pki_base) {
		pki->writeDefault(dirname);	
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

QModelIndex db_base::parent(const QModelIndex &index) const
{
	if (!index.isValid())
		return QModelIndex();

	pki_base *childItem = static_cast<pki_base*>(index.internalPointer());
	pki_base *parentItem = childItem->getParent();

	if (parentItem == rootItem)
		return QModelIndex();

	return createIndex(parentItem->row(), 0, parentItem);
}

int db_base::rowCount(const QModelIndex &parent) const
{
	pki_base *parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<pki_base*>(parent.internalPointer());

	return parentItem->childCount();
}

int db_base::columnCount(const QModelIndex &parent) const
{
	pki_base *item;
	if (parent.isValid())
		item = static_cast<pki_base*>(parent.internalPointer());
	else
		item = rootItem;
	
	return item->columns();
}

QVariant db_base::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();

	pki_base *item = static_cast<pki_base*>(index.internalPointer());
	switch (role) {
		case Qt::DisplayRole:
			return item->column_data(index.column());
		case Qt::DecorationRole:
			if (!index.column())
				return item->getIcon();
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
	//const char *n=NULL, *oldn=NULL;
	QString on, nn;
	pki_base *item;
	if (index.isValid() && role == Qt::EditRole) {
		//n = value.toString().toAscii().constData();
		nn = value.toString();
		//printf("New name: '%s', %p, %p\n", n, n, oldn);
		db mydb(dbName);
		item = static_cast<pki_base*>(index.internalPointer());
		on = item->getIntName();
		//printf("New name: '%s', old name: '%s' %p %p\n", n, oldn, n, oldn);
		if (mydb.rename(item->getType(), CCHAR(on), CCHAR(nn)) == 0) {
			printf("Rename Success !\n");
			item->setIntName(nn);
			emit dataChanged(index, index);
			return true;
		}
	}
	return false;
}

void db_base::load_default(load_base &load)
{
	QStringList slist;
	
	QFileDialog *dlg = new QFileDialog(mainwin);
	
	dlg->setWindowTitle(load.caption);
	dlg->setFilters(load.filter);
	dlg->setFileMode( QFileDialog::ExistingFiles );
	dlg->setDirectory(mainwin->getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		mainwin->setPath(dlg->directory().path());
	}
	delete dlg;

	//ImportMulti *dlgi = NULL;
	//dlgi = new ImportMulti(mainwin);
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		QString s = *it;
		s = QDir::convertSeparators(s);
		pki_base *item = NULL;
		try {
			item = load.loadItem(s);
			//dlgi->addItem(item);
		}
		catch (errorEx &err) {
			MainWindow::Error(err);
			delete item;
			return;
		}
		insert(item);
	}
	//dlgi->execute();
	//delete dlgi;
}

