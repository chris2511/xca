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

    public:
	pkcs11_lib(QString file);
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
	pkcs11_lib *add_lib(QString fname);
	pkcs11_lib *get_lib(QString fname);
	bool remove_lib(QString fname);
	slotidList getSlotList();
};

void pk11error(QString fmt, int r);
void pk11error(slotid slot, QString func, int rv);
const char *pk11errorString(unsigned long rv);
#endif
