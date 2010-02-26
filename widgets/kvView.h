
#ifndef _KVVIEW_H
#define _KVVIEW_H

#include <qabstractitemmodel.h>
#include <qtableview.h>
#include <qcombobox.h>
#include <qitemdelegate.h>
#include "lib/base.h"

class comboDelegate : public QItemDelegate
{
	QStringList keys;

public:
	comboDelegate(QStringList k, QObject *parent = 0)
			:QItemDelegate(parent)
	{
		keys = k;
	}
	QWidget *createEditor(QWidget *parent,
		const QStyleOptionViewItem &option,
		const QModelIndex &index) const;
	void setEditorData(QWidget *editor, const QModelIndex &index) const;
	void setModelData(QWidget *editor, QAbstractItemModel *model,
			const QModelIndex &index) const;
	void updateEditorGeometry(QWidget *editor,
		const QStyleOptionViewItem &option,
		const QModelIndex &index) const
	{
		editor->setGeometry(option.rect);
	}
};

class kvmodel: public QAbstractTableModel
{
	QStringList items;
	QStringList header;

public:
	kvmodel(QStringList heads);
	QStringList getRow(int i);
	void addRow(QString &type, QString &value);
	Qt::ItemFlags flags(const QModelIndex &index) const
	{
		return QAbstractTableModel::flags(index) | Qt::ItemIsEditable;
	}
	QModelIndex index(int row, int column,
			const QModelIndex &parent = QModelIndex()) const
	{
		return createIndex(row, column, row*2 +column);
	}
	QVariant data(const QModelIndex &index, int role) const;
	QVariant headerData(int section, Qt::Orientation orientation,
                int role) const;
	bool insertRows(int row, int count,
				const QModelIndex &parent = QModelIndex());
	bool removeRows(int row, int count,
				const QModelIndex & parent = QModelIndex());
	int rowCount(const QModelIndex &parent) const
	{
		return items.count()/2;
	}
	int columnCount(const QModelIndex &parent) const
	{
		return 2;
	}
	bool setData(const QModelIndex &index, const QVariant &value, int role);
	void moveRow(int oldi, int newi);
};

class kvView: public QTableView
{
	Q_OBJECT

	kvmodel *mymodel;
	QStringList keys;
public:
	kvView(QWidget *parent = 0);
	~kvView();
	void setKeys(const QStringList &k);
	int rowCount()
	{
		return mymodel->rowCount(QModelIndex());
	}
	QStringList getRow(int i)
	{
		return mymodel->getRow(i);
	}
	void addRow(QString &k, QString &v)
	{
		mymodel->addRow(k, v);
	}
	void deleteAllRows()
	{
		mymodel->removeRows(0, rowCount(), QModelIndex());
	}
private slots:
	void moveRow(int logical, int oldi, int newi);
public slots:
	void addKvRow();
	void deleteCurrentRow();

};

#endif
