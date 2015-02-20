/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __KVVIEW_H
#define __KVVIEW_H

#include <QAbstractItemModel>
#include <QTableView>
#include <QComboBox>
#include <QItemDelegate>
#include <QLabel>

#include "lib/base.h"

class kvView;

class kvDelegate : public QItemDelegate
{
public:
	kvDelegate(QObject *parent)
		:QItemDelegate(parent)
	{
	}
	virtual void addKey(QString &) {};
};

class comboDelegate : public kvDelegate
{
	QStringList keys;

public:
	comboDelegate(QStringList k, QObject *parent = 0)
			:kvDelegate(parent)
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

class lineDelegate : public kvDelegate
{
	Q_OBJECT

	QLabel *infoLabel;
public:
	lineDelegate(QLabel *lbl = 0, QObject *parent = 0)
			:kvDelegate(parent)
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
	int myCols;

public:
	kvmodel(QStringList &heads);
	QStringList getRow(int i);
	void addRow(const QStringList &newrow);
	Qt::ItemFlags flags(const QModelIndex &index) const
	{
		return QAbstractTableModel::flags(index) | Qt::ItemIsEditable;
	}
	QModelIndex index(int row, int column,
			const QModelIndex &parent = QModelIndex()) const
	{
		(void)parent;
		return createIndex(row, column, row*myCols +column);
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
		return items.count()/myCols;
	}
	int columnCount(const QModelIndex &parent) const
	{
		(void)parent;
		return myCols;
	}
	bool setData(const QModelIndex &index, const QVariant &value, int role);
	void moveRow(int oldi, int newi);
};

class kvView: public QTableView
{
	Q_OBJECT

	QStringList keys0;
	QLabel *infoLabel;

public:
	kvView(QWidget *parent = 0);
	~kvView();
	int rowCount()
	{
		return model()->rowCount(QModelIndex());
	}
	QStringList getRow(int i)
	{
		return static_cast<kvmodel*>(model())->getRow(i);
	}
	void addRow(const QStringList &newrow);
	void deleteAllRows()
	{
		model()->removeRows(0, rowCount(), QModelIndex());
	}
	void setInfoLabel(QLabel *lbl, int col = 1)
	{
		infoLabel = lbl;
		initLineDelegate(col);
	}
	void initLineDelegate(int col = 1);
	void setKeys(const QStringList &k, int col = 0);
	void initCols(QStringList &heads);
private slots:
	void moveRow(int logical, int oldi, int newi);
	void editorExited();
public slots:
	void addKvRow();
	void deleteCurrentRow();
};

#endif
