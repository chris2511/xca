/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_base.h"
#include "func.h"
#include "exception.h"
#include <QMessageBox>
#include <QListView>
#include <QClipboard>
#include <QDir>
#include <QDebug>
#include <QMimeData>
#include "widgets/MainWindow.h"
#include "widgets/ImportMulti.h"
#include "widgets/XcaDialog.h"
#include "ui_ItemProperties.h"


QHash<quint64, pki_base*> db_base::lookup;

void db_base::restart_timer()
{
	killTimer(secondsTimer);
	killTimer(minutesTimer);
	killTimer(hoursTimer);

	secondsTimer = startTimer(1000);
	minutesTimer = startTimer(MSECS_PER_MINUTE);
	hoursTimer = startTimer(MSECS_PER_HOUR);
}

db_base::db_base(MainWindow *mw)
	:QAbstractItemModel(NULL)
{
	rootItem = newPKI();
	rootItem->setIntName(rootItem->getClassName());
	mainwin = mw;
	colResizing = 0;
	currentIdx = QModelIndex();
	class_name = "base";
	secondsTimer = minutesTimer = hoursTimer = 0;
	restart_timer();
}

db_base::~db_base()
{
	saveHeaderState();
	delete rootItem;
}

pki_base *db_base::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_base("rootItem");
}

void db_base::createSuccess(pki_base *pki)
{
	if (!pki)
		return;

	if (Settings["suppress_messages"])
		return;

	XCA_INFO(pki->getMsg(pki_base::msg_create).arg(pki->getIntName()));
}

void db_base::remFromCont(const QModelIndex &idx)
{
	if (!idx.isValid())
		return;
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	pki_base *parent_pki = pki->getParent();
	int row = pki->row();

	beginRemoveRows(parent(idx), row, row);
	parent_pki->takeChild(pki);
	endRemoveRows();
	emit columnsContentChanged();
}

QString db_base::sqlItemSelector()
{
	QStringList sl;
	QString selector;

	foreach(enum pki_type pt, pkitype)
		sl << QString("type=%1").arg(pt);

	return sl.join(" OR ");
}

XSqlQuery db_base::sqlSELECTpki(QString query, QList<QVariant> values)
{
	XSqlQuery q;
	int i, num_values = values.size();

	SQL_PREPARE(q, query);
	for (i=0; i < num_values; i++) {
		q.bindValue(i, values[i]);
	}
	q.exec();
	MainWindow::dbSqlError(q.lastError());
	return q;
}

void db_base::loadContainer()
{
	XSqlQuery q;
	QSqlError e;
	QString stmt;

	SQL_PREPARE(q, QString("SELECT * FROM view_") + sqlHashTable);
	q.exec();
	e = q.lastError();
	mainwin->dbSqlError(e);

	while (q.next()) {
		enum pki_type t;
		QSqlRecord rec = q.record();
		t = (enum pki_type)q.value(VIEW_item_type).toInt();
		pki_base *pki = newPKI(t);
		pki->restoreSql(rec);
		insertChild(rootItem, pki);
		lookup[q.value(VIEW_item_id).toULongLong()] = pki;
	}

	QString view = Settings[class_name + "_hdView"];
	if (view.isEmpty()) {
		for (int i=0; i< allHeaders.count(); i++) {
			allHeaders[i]->reset();
		}
	} else {
		allHeaders.fromData(view);
	}
	restart_timer();
	emit columnsContentChanged();
}

void db_base::updateHeaders()
{
	QString s = allHeaders.toData();
	foreach(dbheader *h, allHeaders)
		delete h;
	allHeaders = getHeaders();
	allHeaders.fromData(s);
}

dbheaderList db_base::getHeaders()
{
	dbheaderList h;
	/* "No." handled in XcaProxyModel */
	h << new dbheader(HD_internal_name, true, tr("Internal name"))
	  << new num_dbheader(HD_counter, false, tr("No."))
	  << new num_dbheader(HD_primary_key, false, tr("Primary key"),
			tr("Database unique number"))
	  << new date_dbheader(HD_creation, false, tr("Date"),
			tr("Date of creation or insertion"))
	  << new dbheader(HD_source, false, tr("Source"),
			tr("Generated, Imported, Transformed"))
	  << new dbheader(HD_comment, false, tr("Comment"),
			tr("First line of the comment field"));
	return h;
}

void db_base::saveHeaderState()
{
	if (QSqlDatabase::database().isOpen())
		Settings[class_name + "_hdView"] = allHeaders.toData();
}

void db_base::setVisualIndex(int i, int visualIndex)
{
	if (colResizing)
		return;
	allHeaders[i]->visualIndex = visualIndex;
}

void db_base::sectionResized(int i, int,  int newSize)
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
	if (!isValidCol(logicalIndex))
		return;
	for (int i=0; i<max; i++) {
		allHeaders[i]->sortIndicator = -1;
	}
	allHeaders[logicalIndex]->sortIndicator = order;
}

void db_base::insertPKI(pki_base *pki)
{
	Transaction;
	if (!TransBegin())
		return;
	QSqlError e = pki->insertSql();
	if (e.isValid()) {
		mainwin->dbSqlError(e);
		TransRollback();
		return;
	}
	lookup[pki->getSqlItemId().toULongLong()] = pki;
	inToCont(pki);
	TransCommit();
	restart_timer();
	emit columnsContentChanged();
}

QString db_base::pem2QString(QModelIndexList indexes) const
{
	exportType::etype format;
	QString msg;

	format = clipboardFormat(indexes);
	foreach(QModelIndex idx, indexes) {
		long l;
		const char *p;
		if (idx.column() != 0)
			continue;
		BIO *bio = BIO_new(BIO_s_mem());
		pki_base *pki = static_cast<pki_base*>
				(idx.internalPointer());
		pki->pem(bio, format);
		openssl_error();
		l = BIO_get_mem_data(bio, &p);
		msg += QString::fromUtf8(p, l);
		BIO_free(bio);
	}
	return msg;
}

void db_base::pem2clipboard(QModelIndexList indexes) const
{
	QString msg = pem2QString(indexes);
	QClipboard *cb = QApplication::clipboard();

	if (cb->supportsSelection())
		cb->setText(msg, QClipboard::Selection);
	cb->setText(msg);
}

void db_base::deletePKI(QModelIndex idx)
{
	pki_base *pki = static_cast<pki_base*>(idx.internalPointer());
	QSqlDatabase db = QSqlDatabase::database();
	try {
		try {
			pki->deleteFromToken();
		} catch (errorEx &err) {
			MainWindow::Error(err);
		}
		Transaction;
		if (TransBegin()) {
			QSqlError e = pki->deleteSql();
			TransDone(e);
			if (!e.isValid())
				remFromCont(idx);
			mainwin->dbSqlError(e);
		}
	} catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void db_base::showItem(const QModelIndex &index)
{
	pki_base *pki = static_cast<pki_base*>(index.internalPointer());
	if (pki->isVisible() == 1)
		showPki(pki);
}

void db_base::showItem(const QString name)
{
	pki_base *pki = lookupPki<pki_base>(name.toULongLong());
	if (pki && pki->isVisible() == 1)
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

/* Does all the linking from existing keys, crls, certs
 * to the new imported or generated item
 * called before the new item will be inserted into the database
 */
void db_base::inToCont(pki_base *pki)
{
	insertChild(rootItem, pki);
}

pki_base *db_base::getByName(QString desc)
{
	QList<pki_base*> list = sqlSELECTpki<pki_base>(
		QString("SELECT id FROM items WHERE name=? AND ") +
			sqlItemSelector(),
		QList<QVariant>() << QVariant(desc));
	return list.isEmpty() ? NULL : list[0];
}

pki_base *db_base::getByReference(pki_base *refpki)
{
	if (refpki == NULL)
		return NULL;
	QList<pki_base*> list = sqlSELECTpki<pki_base>(
		QString("SELECT item FROM %1 WHERE hash=?").arg(sqlHashTable),
		QList<QVariant>() << QVariant(refpki->hash()));
	foreach(pki_base *pki, list) {
		if (refpki->compare(pki))
			return pki;
	}
	return NULL;
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

	if(column <0)
		abort();
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
	if (!pki)
		return QModelIndex();
	return createIndex(pki->row(), 0, pki);
}

QModelIndex db_base::parent(const QModelIndex &idx) const
{
	if (!idx.isValid())
		return QModelIndex();

	pki_base *childItem = static_cast<pki_base*>(idx.internalPointer());
	pki_base *parentItem = childItem->getParent();

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

	return parentItem->childCount();
}

int db_base::columnCount(const QModelIndex &) const
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
			if (hd->id==HD_internal_name || item->isVisible()==1)
				return item->column_data(hd);
			break;
		case Qt::DecorationRole:
			return item->getIcon(hd);
		case Qt::TextAlignmentRole:
			return hd->isNumeric() ? Qt::AlignRight : Qt::AlignLeft;
		case Qt::FontRole:
			return QVariant(XCA_application::tableFont);
		case Qt::BackgroundRole:
			return item->bg_color(hd);
		case Qt::UserRole:
			return item->isVisible();
		case Qt::ToolTipRole:
			if (hd->id==HD_internal_name || item->isVisible()==1)
				return item->column_tooltip(hd);
			break;
	}
	return QVariant();
}
static QVariant getHeaderViewInfo(dbheader *h)
{
	return QVariant(
#if 0
	QString("H[%1] Show:%2%3 Size:%4 VI:%5 Indi:%6").
		arg(sect).arg(h->show).arg(h->showDefault).arg(h->size).
		arg(h->visualIndex).arg(h->sortIndicator)
#else
	h->getTooltip()
#endif
	);
}

QVariant db_base::headerData(int section, Qt::Orientation orientation,
		int role) const
{
	if (!isValidCol(section))
		return QVariant();
	if (orientation == Qt::Horizontal) {
		switch (role) {
		case Qt::DisplayRole:
			return QVariant(allHeaders[section]->getName());
		case Qt::ToolTipRole:
			return getHeaderViewInfo(allHeaders[section]);
		}
	}
	return QVariant();
}

Qt::ItemFlags db_base::flags(const QModelIndex &index) const
{
	if (!index.isValid())
		return Qt::NoItemFlags;

	Qt::ItemFlags flags = QAbstractItemModel::flags(index) |
				Qt::ItemIsDragEnabled;
	pki_base *item = static_cast<pki_base*>(index.internalPointer());
	if (item->isVisible() == 2)
		flags &= ~Qt::ItemIsEnabled;
	else if (index.column() == 0)
		flags |= Qt::ItemIsEditable;
	return flags;
}

bool db_base::setData(const QModelIndex &index, const QVariant &value, int role)
{
	QString on, nn;
	pki_base *item;
	if (index.isValid() && role == Qt::EditRole) {
		nn = value.toString();
		item = static_cast<pki_base*>(index.internalPointer());
		on = item->getIntName();
		if (nn == on)
			return true;
		updateItem(item, nn, item->getComment());
		return true;
	}
	return false;
}

void db_base::updateItem(pki_base *pki, QString name, QString comment)
{
	XSqlQuery q;
	QSqlError e;

	Transaction;
	TransThrow();

	SQL_PREPARE(q, "UPDATE items SET name=?, comment=? WHERE id=?");
	q.bindValue(0, name);
	q.bindValue(1, comment);
	q.bindValue(2, pki->getSqlItemId());
	q.exec();
	e = q.lastError();
	AffectedItems(pki->getSqlItemId());
	mainwin->dbSqlError(e);
	if (e.isValid())
		return;
	TransDone(e);
	pki->setIntName(name);
	pki->setComment(comment);

	QModelIndex i, j;
	i = index(pki);
	j = index(i.row(), allHeaders.size(), i.parent());
	emit dataChanged(i, j);
	emit pkiChanged(pki);
	restart_timer();
}

void db_base::timerEvent(QTimerEvent *event)
{
	int youngest = SECS_PER_DAY;
	int id = event->timerId();

	FOR_ALL_pki(pki, pki_base) {
		for (int idx=0; idx < allHeaders.count(); idx++) {
			dbheader *hd = allHeaders[idx];
			if (hd->type != dbheader::hd_asn1time)
				continue;
			a1time t = pki->column_a1time(hd);
			if (t.isUndefined())
				continue;
			int age = t.age();
			if (age < 0)
				age *= -1;
			bool do_emit = false;
			if (age < youngest)
				youngest = age;
			if (!hd->show)
				continue;
			if (id == secondsTimer && (age < SECS_PER_MINUTE *2 ||
						   age % SECS_PER_MINUTE < 2))
				do_emit = true;
			if (id == minutesTimer && (age % SECS_PER_HOUR < 60))
				do_emit = true;
			if (id == hoursTimer &&
					 (age % SECS_PER_DAY < SECS_PER_HOUR))
				do_emit = true;
			if (do_emit) {
				qDebug() << "Date changed for" << pki->getIntName() << ":" << hd->getName() << "Col:" << idx << t.toSortable();
				QModelIndex i;
				i = createIndex(pki->row(), idx, pki);
				emit dataChanged(i, i);
			}
		}
	}
	if (secondsTimer && youngest > SECS_PER_HOUR *2) {
		killTimer(secondsTimer);
		secondsTimer = 0;
	}
	if (minutesTimer && youngest > SECS_PER_DAY *2) {
		killTimer(minutesTimer);
		minutesTimer = 0;
	}
}

void db_base::editComment(const QModelIndex &index)
{
	pki_base *item = static_cast<pki_base*>(index.internalPointer());
	if (!index.isValid() || !item)
		return;

	QWidget *w = new QWidget(NULL);
	Ui::ItemProperties *prop = new Ui::ItemProperties();
	prop->setupUi(w);
	prop->comment->setPlainText(item->getComment());
	prop->name->setText(item->getIntName());
	prop->source->setText(item->pki_source_name());
	prop->insertionDate->setText(item->getInsertionDate().toPretty());
	XcaDialog *d = new XcaDialog(mainwin, item->getType(), w,
		tr("Item properties"), QString());
	if (d->exec())
		updateItem(item, prop->name->text(), prop->comment->toPlainText());
	delete d;
}

void db_base::load_default(load_base &load)
{
	QString s;
	QStringList slist = QFileDialog::getOpenFileNames(mainwin, load.caption,
				Settings["workingdir"], load.filter);

	if (!slist.count())
		return;

	QString fn = slist[0];
	Settings["workingdir"] = fn.mid(0, fn.lastIndexOf("/"));

	ImportMulti *dlgi = new ImportMulti(mainwin);
	foreach(s, slist) {
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

void db_base::store(QModelIndexList indexes)
{
	int ret;

	xcaWarning msg(mainwin, tr("How to export the %1 selected items").
				arg(indexes.size()));
	msg.addButton(QMessageBox::Ok)->setText(tr("All in one PEM file"));
	msg.addButton(QMessageBox::Apply)->setText(tr("Each item in one file"));
	msg.addButton(QMessageBox::Cancel);
	ret = msg.exec();
	if (ret == QMessageBox::Apply) {
		foreach(QModelIndex i, indexes)
			store(i);
		return;
	} else if (ret != QMessageBox::Ok) {
		return;
	}

	QString fn = Settings["workingdir"] + QDir::separator() + "export.pem";
	QString s = QFileDialog::getSaveFileName(mainwin,
		tr("Save %1 items in one file as").arg(indexes.size()), fn,
		tr("PEM files ( *.pem );; All files ( * )"));
	if (s.isEmpty())
		return;
	s = nativeSeparator(s);
	Settings["workingdir"] = s.mid(0, s.lastIndexOf(QRegExp("[/\\\\]")));
	try {
		QString pem = pem2QString(indexes);
		FILE *fp = fopen_write(s);
		if (!fp) {
			throw errorEx(tr("Error opening file: '%1': %2").
				arg(s).arg(strerror(errno)), class_name);
		}
		if (fwrite(pem.toLatin1(), pem.size(), 1, fp)) {
			/* IGNORE_RESULT */
		}
		fclose(fp);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

bool db_base::columnHidden(int col) const
{
	if (!isValidCol(col))
		return true;
	if (Settings["disable_netscape"] &&
	    allHeaders[col]->type == dbheader::hd_v3ext_ns)
		return true;
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

bool db_base::isValidCol(int col) const
{
	return col >= allHeaders.size() || col < 0 ? false : true;
}

QMimeData *db_base::mimeData(const QModelIndexList &indexes) const
{
	QString data = pem2QString(indexes);

	if (data.isEmpty())
		return NULL;

	QMimeData *mimeData = new QMimeData();
	mimeData->setText(data.toLatin1());
	mimeData->setData(X_XCA_DRAG_DATA, QByteArray());
	return mimeData;
}

void db_base::writeVcalendar(const QString &fname, QStringList vcal)
{
	QFile file(fname);
	file.open(QFile::ReadWrite | QFile::Truncate);
	if (file.error()) {
		throw errorEx(tr("Error opening file: '%1': %2")
			.arg(fname).arg(strerror(errno)));
		return;
	}

	QStringList ics; ics <<
	"BEGIN:VCALENDAR" <<
	"VERSION:2.0" <<
	"PRODID:-//" XCA_TITLE "//" PACKAGE_VERSION "//" <<
	vcal <<
	"END:VCALENDAR";
	file.write(ics.join("\r\n").toUtf8());
}
