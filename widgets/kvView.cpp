
#include "widgets/kvView.h"
#include <qheaderview.h>
#include <qlineedit.h>

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

kvmodel::kvmodel(QStringList heads)
{
	header = heads;
}

QStringList kvmodel::getRow(int i)
{
	QStringList sl;
	sl << items[i*2] << items[i*2+1];
	return sl;
}

void kvmodel::addRow(QString &type, QString &value)
{
	int row = rowCount(QModelIndex());
	beginInsertRows(QModelIndex(), row, row);
	items << type.trimmed() << value.trimmed();
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
	for (int i=0; i< count; i++) {
		items.insert(row*2, QString());
		items.insert(row*2, QString());
	}
	endInsertRows();
	return true;
}

bool kvmodel::removeRows(int row, int count, const QModelIndex &)
{
	beginRemoveRows(QModelIndex(), row, row+count-1);
	for (int i=0; i< count; i++) {
		items.removeAt(row*2);
		items.removeAt(row*2);
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
	QString k = items[oldi*2];
	QString v = items[oldi*2 +1];
	removeRows(oldi, 1);
	insertRows(newi, 1);
	items[newi*2] = k;
	items[newi*2+1] = v;
}

kvView::kvView(QWidget *parent)
	:QTableView(parent)
{
	QStringList sl;
	sl << tr("Type") << tr("Content");
	mymodel = new kvmodel(sl);
	setModel(mymodel);
	setSelectionMode(QAbstractItemView::ExtendedSelection);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setAlternatingRowColors(true);
	horizontalHeader()->setDefaultSectionSize(200);
	horizontalHeader()->setStretchLastSection(true);
	verticalHeader()->setMovable(true);
	verticalHeader()->setDefaultSectionSize(24);
	setEditTriggers(QAbstractItemView::AllEditTriggers);

	connect(verticalHeader(), SIGNAL(sectionMoved(int,int,int)),
		this, SLOT(moveRow(int,int,int)));
	infoLabel = NULL;
	initLineDelegate();
}

kvView::~kvView()
{
	delete mymodel;
}

void kvView::initLineDelegate()
{
	lineDelegate *d = new lineDelegate(infoLabel, this);
	setItemDelegateForColumn(1, d);
	connect(static_cast<QItemDelegate*>(d),
	   SIGNAL(closeEditor(QWidget *, QAbstractItemDelegate::EndEditHint)),
	   this, SLOT(editorExited()));
}

void kvView::setKeys(const QStringList &k)
{
	keys = k;
	comboDelegate *d = new comboDelegate(keys, this);
	setItemDelegateForColumn(0, d);
}

void kvView::moveRow(int, int oldi, int newi)
{
	static int moving = 0;

	if (moving)
		return;
	moving = 1;
	verticalHeader()->moveSection(newi, oldi);
	mymodel->moveRow(oldi, newi);
	repaint();
	moving = 0;
}

void kvView::addKvRow()
{
	QString k, v;
	if (keys.count() > 0)
		k = keys[rowCount() % keys.count()];
	addRow(k, v);
}

void kvView::deleteCurrentRow()
{
	mymodel->removeRows(currentIndex().row(), 1, QModelIndex());
}

void kvView::editorExited()
{
	if (infoLabel)
		infoLabel->clear();
}

