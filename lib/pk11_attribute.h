/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_PKCS11_ATTRIBUTE_H
#define PKI_PKCS11_ATTRIBUTE_H

#include <qstring.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include "opensc-pkcs11.h"

#define UTF8QSTRING(x,s) QString::fromUtf8((const char*)(x), s).trimmed();

class pk11_attribute
{
protected:
	CK_ATTRIBUTE attr;

public:
	pk11_attribute(unsigned long type)
	{
		memset(&attr, 0, sizeof(attr));
		attr.type = type;
	}
	virtual void load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj) { }
	virtual ~pk11_attribute() { }
	const CK_ATTRIBUTE *getAttribute() const
	{
		return &attr;
	}
	void store(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
};

class pk11_attr_ulong: public pk11_attribute
{
protected:
	unsigned long value;

public:
	pk11_attr_ulong(unsigned long type) : pk11_attribute(type)
	{
		attr.pValue = &value;
		attr.ulValueLen = sizeof(value);
	}
	unsigned long getValue() const
	{
		return value;
	}
	void setValue(unsigned long v)
	{
		value = v;
	}
	void load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
};

class pk11_attr_data: public pk11_attribute
{

public:
	pk11_attr_data(unsigned long type) : pk11_attribute(type)
	{
		attr.pValue = NULL;
		attr.ulValueLen = 0;
	}
	unsigned long getValue(const unsigned char **ptr)
	{
		*ptr = (unsigned char*)attr.pValue;
		return attr.ulValueLen;
	}
	~pk11_attr_data()
	{
		if (attr.pValue)
			free(attr.pValue);
	}
	QString getText() const
	{
		return UTF8QSTRING(attr.pValue, attr.ulValueLen);
	}
	BIGNUM *getBignum() const
	{
		return BN_bin2bn((unsigned char*)attr.pValue,
				attr.ulValueLen, NULL);
	}
	void load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
	void setValue(const void *ptr, unsigned long len);
};

#endif
