/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS11_ATTRIBUTE_H
#define __PKI_PKCS11_ATTRIBUTE_H

#include <QString>
#include <stdlib.h>
#include <openssl/bn.h>
#include "opensc-pkcs11.h"
#include "exception.h"

#define UTF8QSTRING(x,s) QString::fromUtf8((const char*)(x), s).trimmed()
#define ASCIIQSTRING(x,s) QString::fromLatin1((const char*)(x), s).trimmed()

class pk11_attlist;

class pk11_attribute
{
	friend class pk11_attlist;
protected:
	CK_ATTRIBUTE attr;

public:
	pk11_attribute(unsigned long type)
	{
		memset(&attr, 0, sizeof(attr));
		attr.type = type;
	}
	virtual ~pk11_attribute() { }
	const CK_ATTRIBUTE *getAttribute() const
	{
		return &attr;
	}
	unsigned long type() const
	{
		return attr.type;
	}
	QByteArray getData() const
	{
		return QByteArray((char*)attr.pValue, attr.ulValueLen);
	}
	virtual void store(slotid slot,
			CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
	virtual void load(slotid slot,
			CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
	bool cmp(const pk11_attribute &other) const
	{
		return (attr.type == other.attr.type) &&
			(attr.ulValueLen == other.attr.ulValueLen) &&
			!memcmp(attr.pValue, other.attr.pValue,
					attr.ulValueLen);
	}
	bool operator == (const pk11_attribute &other) const
	{
		return cmp(other);
	}
};

class pk11_attr_bool: public pk11_attribute
{
protected:
	unsigned char value;

public:
	pk11_attr_bool(unsigned long type, bool v = false)
			:pk11_attribute(type)
	{
		attr.pValue = &value;
		attr.ulValueLen = sizeof(value);
		setValue(v);
	}
	pk11_attr_bool(const pk11_attr_bool &p)
			:pk11_attribute(p.type())
	{
		attr.pValue = &value;
		attr.ulValueLen = sizeof(value);
		setValue(p.value);
	}
	bool getValue() const
	{
		return value ? true : false;
	}
	void setValue(unsigned long v)
	{
		value = v ? 1 : 0;
	}
};

class pk11_attr_ulong: public pk11_attribute
{
protected:
	unsigned long value;

public:
	pk11_attr_ulong(unsigned long type, unsigned long v = 0)
			:pk11_attribute(type)
	{
		attr.pValue = &value;
		attr.ulValueLen = sizeof(value);
		setValue(v);
	}
	pk11_attr_ulong(const pk11_attr_ulong &p)
			:pk11_attribute(p.type())
	{
		attr.pValue = &value;
		attr.ulValueLen = sizeof(value);
		setValue(p.value);
	}
	unsigned long getValue() const
	{
		return value;
	}
	void setValue(unsigned long v)
	{
		value = v;
	}
};

class pk11_attr_data: public pk11_attribute
{

public:
	pk11_attr_data() :pk11_attribute(0) { }
	pk11_attr_data(unsigned long type, const unsigned char *v = NULL,
			unsigned long len = 0) :pk11_attribute(type)
	{
		setValue(v, len);
	}
	pk11_attr_data(const pk11_attr_data &p)
		:pk11_attribute(p.type())
	{
		const unsigned char *ptr;
		unsigned long size = p.getValue(&ptr);
		setValue(ptr, size);
	}
	pk11_attr_data(unsigned long type, QByteArray ba)
		:pk11_attribute(type)
	{
		setValue((const unsigned char *)ba.constData(), ba.size());
	}
	pk11_attr_data(unsigned long type, BIGNUM *bn, bool consume=true)
		:pk11_attribute(type)
	{
		setBignum(bn, consume);
	}
	pk11_attr_data(unsigned long type, const BIGNUM *bn)
		:pk11_attribute(type)
	{
		setConstBignum(bn);
	}
	pk11_attr_data(unsigned long type, unsigned long value)
		:pk11_attribute(type)
	{
		setULong(value);
	}
	void setULong(unsigned long value)
	{
		BIGNUM *bn = BN_new();
		check_oom(bn);
		check_oom(BN_set_word(bn, value));
		setBignum(bn, true);
	}
	unsigned long getValue(const unsigned char **ptr) const
	{
		*ptr = (const unsigned char*)attr.pValue;
		return attr.ulValueLen;
	}
	~pk11_attr_data()
	{
		if (attr.pValue) {
			memset(attr.pValue, 0, attr.ulValueLen);
			free(attr.pValue);
		}
	}
	QString getText() const
	{
		unsigned long len = attr.ulValueLen;
		char *p = (char*)attr.pValue;

		/* Fixup 0 padded attributes, returned by some broken
		   libs like OpenLimit */
		while (p[len-1] == 0 && len > 0)
			len--;
		return UTF8QSTRING(attr.pValue, len);
	}
	BIGNUM *getBignum() const
	{
		return BN_bin2bn((unsigned char*)attr.pValue,
				attr.ulValueLen, NULL);
	}
	void setBignum(BIGNUM *bn, bool consume=true);
	void setConstBignum(const BIGNUM *bn);
	void load(slotid slot,
		CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
	void setValue(const unsigned char *ptr, unsigned long len);
	pk11_attr_data &operator = (const pk11_attr_data &p)
	{
		const unsigned char *ptr;
		unsigned long size = p.getValue(&ptr);
		attr.type = p.attr.type;
		setValue(ptr, size);
		return *this;
	}
};

class pk11_attlist {

	private:
		CK_ATTRIBUTE *attributes;
		unsigned long attlen;
		unsigned long alloc_len;
		void init()
		{
			attlen = 0;
			alloc_len = 0;
			attributes = NULL;
		}

	public:
		pk11_attlist()
		{
			init();
		}
		pk11_attlist(const pk11_attlist &a);
		pk11_attlist(const pk11_attribute &a)
		{
			init();
			addAttribute(a);
		}
		~pk11_attlist();
		unsigned long get(CK_ATTRIBUTE **attp)
		{
			*attp = attributes;
			return attlen;
		}
		void addAttribute(const pk11_attribute &a);
		pk11_attlist &operator << (const pk11_attribute &a)
		{
			addAttribute(a);
			return *this;
		}
		CK_ATTRIBUTE *getAttributes() {
			return attributes;
		}
		unsigned long length() {
			return attlen;
		}
		pk11_attlist &operator = (const pk11_attlist &a)
		{
			copy(a);
			return *this;
		}
		void copy(const pk11_attlist &a);
		void reset();
};
#endif
