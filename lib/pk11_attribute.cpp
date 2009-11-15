/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include <qobject.h>

void pk11_attribute::load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	rv = pkcs11::p11->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		pkcs11::pk11error("C_GetAttribute()", rv);
}

void pk11_attr_data::load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	if (attr.pValue) {
		free(attr.pValue);
		attr.pValue = NULL;
	}
	attr.ulValueLen = 0;
	rv = pkcs11::p11->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv == CKR_OK) {
		attr.pValue = malloc(attr.ulValueLen +1);
		check_oom(attr.pValue);
		rv = pkcs11::p11->C_GetAttributeValue(sess, obj, &attr, 1); \
		if (rv == CKR_OK)
			return;
	}
	pkcs11::pk11error("C_GetAttributeValue(data)", rv); \
}

void pk11_attr_data::setValue(const unsigned char *ptr, unsigned long len)
{
	if (attr.pValue)
		free(attr.pValue);
	attr.pValue = malloc(len);
	check_oom(attr.pValue);
	memcpy(attr.pValue, ptr, len);
	attr.ulValueLen = len;
}

void pk11_attribute::store(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	rv = pkcs11::p11->C_SetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		pkcs11::pk11error("C_SetAttributeValue", rv);
}

pk11_attlist::pk11_attlist(const pk11_attlist &a)
{
	attlen = a.attlen;
	alloc_len = a.alloc_len;
	if (alloc_len) {
		attributes =
			(CK_ATTRIBUTE *)malloc(alloc_len *sizeof(*attributes));
		check_oom(attributes);
		memcpy(attributes, a.attributes, attlen *sizeof(*attributes));
	}
	for (unsigned long i=0; i<attlen; i++) {
		void *p = malloc(attributes[i].ulValueLen);
		check_oom(p);
		memcpy(p, attributes[i].pValue, attributes[i].ulValueLen);
	}
}

pk11_attlist::~pk11_attlist()
{
	for (unsigned long i=0; i<attlen; i++)
		free(attributes[i].pValue);
	if (attributes)
		free(attributes);
}

void pk11_attlist::addAttribute(const pk11_attribute &a)
{
	CK_ATTRIBUTE *attr;
	if (attlen == alloc_len) {
		alloc_len = alloc_len ? alloc_len *2 : 16;
		attributes = (CK_ATTRIBUTE *)realloc(attributes,
			alloc_len * sizeof(*attributes));
		check_oom(attributes);
	}
	attr = attributes + attlen++;
	attr->type = a.attr.type;
	attr->ulValueLen = a.attr.ulValueLen;
	attr->pValue = malloc(attr->ulValueLen);
	memcpy(attr->pValue, a.attr.pValue, attr->ulValueLen);
}

void pk11_attlist::reset()
{
	for (unsigned long i=0; i<attlen; i++)
		free(attributes[i].pValue);

	attlen = 0;
}

