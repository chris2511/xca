/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCA_PKCS11_LIB_H
#define __XCA_PKCS11_LIB_H

#include "lib/exception.h"
#include "opensc-pkcs11.h"
#include <QAbstractListModel>
#include <QString>
#include <QObject>
#include <QList>
#include <QLibrary>

class pkcs11_lib : public QLibrary
{
	Q_OBJECT

  private:
	CK_FUNCTION_LIST *p11{};
	QString file, load_error{};
	bool enabled{};

  public:
	static QString name2File(const QString &name, bool *enabled = nullptr);
	pkcs11_lib(const QString &file);
	pkcs11_lib() = delete;
	~pkcs11_lib();

	QList<CK_SLOT_ID> getSlotList();
	QString driverInfo() const;
	QString filename() const
	{
		return file;
	}
	CK_FUNCTION_LIST *ptr() const
	{
		return p11;
	}
	bool isLoaded() const
	{
		return p11 != NULL;
	}
	enum Qt::CheckState checked() const
	{
		return enabled ? Qt::Checked : Qt::Unchecked;
	}
	bool isLib(const QString &name) const
	{
		return name2File(name) == file;
	}
	QString toData(int enabled) const
	{
		return QString("%1:%2").arg(enabled).arg(file);
	}
	QString toData() const
	{
		return toData(enabled);
	}
	QString pixmap() const
	{
		if (!enabled)
			return QString();
                return isLoaded() ? ":doneIco" : ":warnIco";
	}
};

class slotid
{
  public:
	pkcs11_lib *lib;
	CK_SLOT_ID id;
	slotid() = default;
	slotid(pkcs11_lib *l, CK_SLOT_ID i) : lib(l), id(i) { }
	void isValid() const
	{
		if (!lib)
			throw errorEx("InternalError: slotid is invalid");
	}
	CK_FUNCTION_LIST *p11() const
	{
		return lib->ptr();
	}
};

typedef QList<slotid> slotidList;

class pkcs11_lib_list: public QAbstractListModel
{
	QList<pkcs11_lib*> libs;
	QList<int> model_data;

    public:
	~pkcs11_lib_list();
	pkcs11_lib *add_lib(const QString &fname);
	void load(const QString &list);
	slotidList getSlotList() const;
	QString getPkcs11Provider() const;
	void remove_libs();
	bool loaded() const;

	/* Helper for QAbstractListModel */
	pkcs11_lib *libByModelIndex(const QModelIndex &index) const;

	/* Reimplementation from QAbstractListModel */
	int rowCount(const QModelIndex &parent = QModelIndex()) const;
	QVariant data(const QModelIndex &index,
			int role = Qt::DisplayRole) const;
	bool setData(const QModelIndex &index, const QVariant &value, int role);

	QMap<int, QVariant> itemData(const QModelIndex &index) const;
	bool setItemData(const QModelIndex &index, const QMap<int, QVariant> &roles);

	Qt::ItemFlags flags(const QModelIndex& index) const;
	Qt::DropActions supportedDropActions() const;

	bool removeRows(int row, int count, const QModelIndex &p = QModelIndex());
	bool insertRows(int row, int count, const QModelIndex &p = QModelIndex());
};

void pk11error(const QString &fmt, int r);
void pk11error(const slotid &slot, const QString &func, int rv);
const char *pk11errorString(unsigned long rv);
#endif
