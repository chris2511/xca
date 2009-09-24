/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"

void pk11_attr_ulong::load(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_RV rv;
	rv = pkcs11::p11->C_GetAttributeValue(sess, obj, &attr, 1);
	if (rv != CKR_OK)
		pkcs11::pk11error("C_GetAttributeValue(ulong)", rv);
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
		if (!attr.pValue)
			throw errorEx("Out of memory");
		rv = pkcs11::p11->C_GetAttributeValue(sess, obj, &attr, 1); \
		if (rv == CKR_OK)
			return;
	}
	pkcs11::pk11error("C_GetAttributeValue(data)", rv); \
}

