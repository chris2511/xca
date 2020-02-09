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
#include <QString>
#include <QList>

#include <ltdl.h>

class pkcs11_lib
{
    private:
	lt_dlhandle dl_handle;
	CK_FUNCTION_LIST *p11;
	QString file;
	bool enabled;
	QString load_error;

    public:
	static QString name2File(const QString &name, bool *enabled = NULL);
	pkcs11_lib(const QString &file);
	~pkcs11_lib();

	QList<unsigned long> getSlotList();
	QString driverInfo();
	QString filename()
	{
		return file;
	}
	CK_FUNCTION_LIST *ptr()
	{
		return p11;
	}
	bool isLoaded() const
	{
		return p11 != NULL;
	}
	bool isEnabled() const
	{
		return enabled;
	}
	bool isLib(const QString &name)
	{
		return name2File(name) == file;
	}
};

class slotid
{
    public:
	CK_ULONG id;
	pkcs11_lib *lib;
	slotid()
	{
		lib = NULL;
		id = 0;
	}
	slotid(pkcs11_lib *l, CK_ULONG i)
	{
		lib = l;
		id = i;
	}
	slotid(const slotid &other)
	{
		lib = other.lib;
		id = other.id;
	}
	slotid &operator = (const slotid &other)
	{
		lib = other.lib;
		id = other.id;
		return *this;
	}
	void isValid()
	{
		if (!lib)
			throw errorEx("InternalError: slotid is invalid");
	}
	CK_FUNCTION_LIST *p11()
	{
		return lib->ptr();
	}
};

typedef QList<slotid> slotidList;

class pkcs11_lib_list: public QList<pkcs11_lib*>
{
    public:
	pkcs11_lib *add_lib(const QString &fname);
	pkcs11_lib *get_lib(const QString &fname);
	bool remove_lib(const QString &fname);
	slotidList getSlotList();
};

void pk11error(const QString &fmt, int r);
void pk11error(slotid slot, const QString &func, int rv);
const char *pk11errorString(unsigned long rv);
#endif
