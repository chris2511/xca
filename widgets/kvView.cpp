/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "widgets/kvView.h"
#include <QHeaderView>
#include <QLineEdit>

QWidget *comboDelegate::createEditor(QWidget *parent,
	const QStyleOptionViewItem &,
	const QModelIndex &) const
{
	QComboBox *editor = new QComboBox(parent);
	editor->addItems(keys);
	return editor;
}

void comboDelegate::setEditorData(QWidget *editor,
			const QModelIndex &index) const
{
	QString v = index.model()->data(index, Qt::EditRole).toString();
	QComboBox *c = static_cast<QComboBox*>(editor);
	c->setCurrentIndex(c->findText(v));
}

void comboDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
		const QModelIndex &index) const
{
	QComboBox *c = static_cast<QComboBox*>(editor);
	model->setData(index, c->currentText(), Qt::EditRole);
}

QWidget *lineDelegate::createEditor(QWidget *parent,
	const QStyleOptionViewItem &,
	const QModelIndex &) const
{
	return new QLineEdit(parent);
}

void lineDelegate::setEditorData(QWidget *editor,
			const QModelIndex &index) const
{
	QString v, k;

	v = index.model()->data(index, Qt::EditRole).toString();
	QModelIndex key = index.sibling(index.row(), 0);
	QLineEdit *l = static_cast<QLineEdit*>(editor);

	l->setText(v);

	if (key.isValid()) {
		k = key.model()->data(key, Qt::DisplayRole).toString();
		emit setupLineEdit(k, l);
	}
	if (infoLabel)
		infoLabel->setText(k + ": " + l->toolTip());
}

void lineDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
		const QModelIndex &index) const
{
	QLineEdit *l = static_cast<QLineEdit*>(editor);
	model->setData(index, l->text(), Qt::EditRole);
}

kvmodel::kvmodel(QStringList &heads)
{
	header = heads;
	myCols = heads.size();
}

QStringList kvmodel::getRow(int i)
{
	QStringList sl;
	sl << items[i*myCols] << items[i *myCols +1];
	return sl;
}

void kvmodel::addRow(const QStringList &newrow)
{
	int row = rowCount(QModelIndex());
	beginInsertRows(QModelIndex(), row, row);
	for (int i = 0; i<myCols; i++) {
		if (i >= newrow.size())
			items << QString();
		else
			items << newrow[i].trimmed();
	}
	endInsertRows();
}

QVariant kvmodel::data(const QModelIndex &index, int role) const
{
	int id = index.internalId();
	QString s = items[id];

	switch (role) {
		case Qt::EditRole:
		case Qt::DisplayRole:
			return QVariant(s);
	}
	return QVariant();
}

QVariant kvmodel::headerData(int section, Qt::Orientation orientation,
	int role) const
{
	if (role == Qt::DisplayRole) {
		if (orientation == Qt::Horizontal)
			return QVariant(header[section]);
		if (orientation == Qt::Vertical)
			return QVariant(section);
	}
	return QVariant();
}

bool kvmodel::insertRows(int row, int count, const QModelIndex &)
{
	beginInsertRows(QModelIndex(), row, row+count-1);
	for (int i=0; i< count *myCols; i++) {
		items.insert(row*myCols, QString());
	}
	endInsertRows();
	return true;
}

bool kvmodel::removeRows(int row, int count, const QModelIndex &)
{
	beginRemoveRows(QModelIndex(), row, row+count-1);
	for (int i=0; i< count*myCols; i++) {
		items.removeAt(row*myCols);
	}
	endRemoveRows();
	return true;
}

bool kvmodel::setData(const QModelIndex &index, const QVariant &value, int role)
{
	if (index.isValid() && role == Qt::EditRole) {
		items[index.internalId()] = value.toString().trimmed();
		emit dataChanged(index, index);
		return true;
	}
	return false;
}

void kvmodel::moveRow(int oldi, int newi)
{
	QStringList line = items.mid(oldi*myCols, myCols);
	removeRows(oldi, 1);
	insertRows(newi, 1);
	for (int i=0; i<myCols; i++)
		items[newi*myCols +i] = line[i];
}

kvView::kvView(QWidget *parent)
	:QTableView(parent)
{
	QStringList sl;
	sl << tr("Type") << tr("Content");
	initCols(sl);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setAlternatingRowColors(true);
	horizontalHeader()->setDefaultSectionSize(200);
	horizontalHeader()->setStretchLastSection(true);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
	verticalHeader()->setSectionsMovable(true);
#else
	verticalHeader()->setMovable(true);
#endif
	verticalHeader()->setDefaultSectionSize(24);
	setEditTriggers(QAbstractItemView::AllEditTriggers);

	connect(verticalHeader(), SIGNAL(sectionMoved(int,int,int)),
		this, SLOT(moveRow(int,int,int)));
	infoLabel = NULL;
	initLineDelegate();
}

void kvView::initCols(QStringList &heads)
{
	QAbstractItemModel *m = model();
	setModel(new kvmodel(heads));
	delete m;
}

kvView::~kvView()
{
	delete model();
}

void kvView::initLineDelegate(int col)
{
	lineDelegate *d = new lineDelegate(infoLabel, this);
	setItemDelegateForColumn(col, d);
	connect(static_cast<QItemDelegate*>(d),
	   SIGNAL(closeEditor(QWidget *, QAbstractItemDelegate::EndEditHint)),
	   this, SLOT(editorExited()));
}

void kvView::setKeys(const QStringList &k, int col)
{
	if (!col)
		keys0 = k;
	comboDelegate *d = new comboDelegate(k, this);
	setItemDelegateForColumn(col, d);
}

void kvView::moveRow(int, int oldi, int newi)
{
	static int moving = 0;

	if (moving)
		return;
	moving = 1;
	verticalHeader()->moveSection(newi, oldi);
	static_cast<kvmodel*>(model())->moveRow(oldi, newi);
	repaint();
	moving = 0;
}

void kvView::addRow(const QStringList &newrow)
{
	int max = MIN(model()->columnCount(QModelIndex()), newrow.size());
	for (int i = 0; i<max; i++) {
		QString key = newrow[i].trimmed();
		static_cast<kvDelegate*>(itemDelegateForColumn(i))->addKey(key);
	}
	static_cast<kvmodel*>(model())->addRow(newrow);
}

void kvView::addKvRow()
{
	QString k;
	if (keys0.count() > 0)
		k = keys0[rowCount() % keys0.count()];
	addRow(QStringList(k));
}

void kvView::deleteCurrentRow()
{
	model()->removeRows(currentIndex().row(), 1, QModelIndex());
}

void kvView::editorExited()
{
	if (infoLabel)
		infoLabel->clear();
}

