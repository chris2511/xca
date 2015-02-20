/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include <QObject>

void pk11_attribute::load(slotid slot,
			CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	rv = slot.p11()->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		pk11error("C_GetAttribute()", rv);
}

void pk11_attr_data::load(slotid slot,
			CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	if (attr.pValue) {
		free(attr.pValue);
		attr.pValue = NULL;
	}
	attr.ulValueLen = 0;
	rv = slot.p11()->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv == CKR_OK) {
		attr.pValue = malloc(attr.ulValueLen +1);
		check_oom(attr.pValue);
		rv = slot.p11()->C_GetAttributeValue(sess, obj, &attr, 1); \
		if (rv == CKR_OK)
			return;
	}
	pk11error("C_GetAttributeValue(data)", rv); \
}

void pk11_attr_data::setValue(const unsigned char *ptr, unsigned long len)
{
	if (attr.pValue)
		free(attr.pValue);
	if (!ptr || len == 0) {
		attr.ulValueLen = 0;
		attr.pValue = NULL;
		return;
	}
	attr.pValue = malloc(len+1);
	check_oom(attr.pValue);
	memcpy(attr.pValue, ptr, len);
	attr.ulValueLen = len;
	((char*)attr.pValue)[len] = 0;
}

void pk11_attr_data::setConstBignum(const BIGNUM *bn)
{
	attr.ulValueLen = BN_num_bytes(bn);
	if (attr.pValue)
		free(attr.pValue);
	attr.pValue = malloc(attr.ulValueLen);
	check_oom(attr.pValue);
	attr.ulValueLen = BN_bn2bin(bn, (unsigned char *)attr.pValue);
}

void pk11_attr_data::setBignum(BIGNUM *bn, bool consume)
{
	setConstBignum(bn);
	if (consume)
		BN_free(bn);
}

void pk11_attribute::store(slotid slot,
			CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	rv = slot.p11()->C_SetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		pk11error("C_SetAttributeValue", rv);
}

void pk11_attlist::copy(const pk11_attlist &a)
{
	reset();
	attlen = a.attlen;
	alloc_len = a.alloc_len;
	if (alloc_len) {
		attributes =
			(CK_ATTRIBUTE *)malloc(alloc_len *sizeof(*attributes));
		check_oom(attributes);
		memcpy(attributes, a.attributes, attlen *sizeof(*attributes));
	}
	for (unsigned long i=0; i<attlen; i++) {
		char *p = (char*)malloc(attributes[i].ulValueLen +1);
		check_oom(p);
		memcpy(p, a.attributes[i].pValue, attributes[i].ulValueLen);
		p[attributes[i].ulValueLen] = '\0';
		attributes[i].pValue = p;
	}
}

pk11_attlist::pk11_attlist(const pk11_attlist &a)
{
	copy(a);
}

pk11_attlist::~pk11_attlist()
{
	for (unsigned long i=0; i<attlen; i++) {
		memset(attributes[i].pValue, 0, attributes[i].ulValueLen);
		free(attributes[i].pValue);
	}
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
	attr->pValue = malloc(attr->ulValueLen +1);
	check_oom(attr->pValue);
	memcpy(attr->pValue, a.attr.pValue, attr->ulValueLen);
	((char*)attr->pValue)[attr->ulValueLen] = 0;
}

void pk11_attlist::reset()
{
	for (unsigned long i=0; i<attlen; i++)
		free(attributes[i].pValue);

	attlen = 0;
}

