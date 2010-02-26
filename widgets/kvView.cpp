
#include "widgets/kvView.h"
#include <qheaderview.h>

QWidget *comboDelegate::createEditor(QWidget *parent,
	const QStyleOptionViewItem &option,
	const QModelIndex &index) const
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

bool kvmodel::insertRows(int row, int count, const QModelIndex &parent)
{
	beginInsertRows(QModelIndex(), row, row+count-1);
	for (int i=0; i< count; i++) {
		items.insert(row*2, QString());
		items.insert(row*2, QString());
	}
	endInsertRows();
	return true;
}

bool kvmodel::removeRows(int row, int count, const QModelIndex &parent)
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
	verticalHeader()->setMovable(true);

	connect(verticalHeader(), SIGNAL(sectionMoved(int,int,int)),
		this, SLOT(moveRow(int,int,int)));
}

kvView::~kvView()
{
	delete mymodel;
}

void kvView::setKeys(const QStringList &k)
{
	keys = k;
	comboDelegate *d = new comboDelegate(keys, this);
	setItemDelegateForColumn(0, d);
}

void kvView::moveRow(int logical, int oldi, int newi)
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

