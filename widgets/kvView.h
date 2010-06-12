/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __KVVIEW_H
#define __KVVIEW_H

#include <QtCore/QAbstractItemModel>
#include <QtGui/QTableView>
#include <QtGui/QComboBox>
#include <QtGui/QItemDelegate>
#include <QtGui/QLabel>

#include "lib/base.h"

class kvView;
class comboDelegate : public QItemDelegate
{
	QStringList keys;

public:
	comboDelegate(QStringList k, QObject *parent = 0)
			:QItemDelegate(parent)
	{
		keys = k;
	}
	void addKey(QString &key)
	{
		if (!key.isEmpty() && (keys.count() == 0 || !keys.contains(key)))
			keys << key;
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
		(void)index;
		editor->setGeometry(option.rect);
	}
};

class lineDelegate : public QItemDelegate
{
	Q_OBJECT

	QLabel *infoLabel;
public:
	lineDelegate(QLabel *lbl = 0, QObject *parent = 0)
			:QItemDelegate(parent)
	{
		infoLabel = lbl;
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
		(void)index;
		editor->setGeometry(option.rect);
	}
signals:
	void setupLineEdit(const QString &s, QLineEdit *l) const;
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
		(void)parent;
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
		(void)parent;
		return items.count()/2;
	}
	int columnCount(const QModelIndex &parent) const
	{
		(void)parent;
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
	QLabel *infoLabel;

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
	void addRow(QString &k, QString &v);
	void deleteAllRows()
	{
		mymodel->removeRows(0, rowCount(), QModelIndex());
	}
	void setInfoLabel(QLabel *lbl)
	{
		infoLabel = lbl;
		initLineDelegate();
	}
	void initLineDelegate();
private slots:
	void moveRow(int logical, int oldi, int newi);
	void editorExited();
public slots:
	void addKvRow();
	void deleteCurrentRow();
};

#endif
