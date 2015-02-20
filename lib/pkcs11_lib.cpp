/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "func.h"
#include "pass_info.h"

#include <openssl/rand.h>
#include <QMessageBox>
#include <ltdl.h>
#include "ui_SelectToken.h"

pkcs11_lib::pkcs11_lib(QString f)
{
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	CK_RV rv;

	file = f;
	lt_dlinit();
	p11 = NULL;

	dl_handle = lt_dlopen(QString2filename(file));
	if (dl_handle == NULL)
		goto how_bad;

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				lt_dlsym(dl_handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto how_bad;

	qDebug("Trying to load PKCS#11 provider %s", QString2filename(file));
	if (c_get_function_list(&p11) != CKR_OK)
		goto how_bad;

	CALL_P11_C(this, C_Initialize, NULL);
	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		pk11error("C_Initialize", rv);

	qDebug("Successfully loaded PKCS#11 provider %s",
		QString2filename(file));
	return;

how_bad:
	WAITCURSOR_END;
	if (dl_handle)
		lt_dlclose(dl_handle);
	lt_dlexit();
	qDebug("Failed to load PKCS#11 provider %s", QString2filename(file));
	throw errorEx(QObject::tr("Failed to open PKCS11 library: %1").
			arg(file));
}

pkcs11_lib::~pkcs11_lib()
{
	CK_RV rv;
	qDebug("Unloading PKCS#11 provider %s", QString2filename(file));
	CALL_P11_C(this, C_Finalize, NULL);
	(void)rv;
	lt_dlclose(dl_handle);
	lt_dlexit();
	qDebug("Unloaded PKCS#11 provider %s", QString2filename(file));
}

QList<unsigned long> pkcs11_lib::getSlotList()
{
	CK_RV rv;
	CK_SLOT_ID *p11_slots = NULL;
	QList<unsigned long> sl;
	unsigned long i, num_slots = 0;

	/* This one helps to avoid errors.
	 * Fist time it fails, 2nd time it works */
	CALL_P11_C(this, C_GetSlotList, CK_TRUE, p11_slots, &num_slots);
	while (1) {
		CALL_P11_C(this, C_GetSlotList, CK_TRUE, p11_slots, &num_slots);
		if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL)
			pk11error("C_GetSlotList", rv);

		if (num_slots == 0)
			break;
		if ((rv == CKR_OK) && p11_slots)
			break;

		p11_slots = (CK_SLOT_ID *)realloc(p11_slots,
					num_slots *sizeof(CK_SLOT_ID));
		check_oom(p11_slots);
	}

	for (i=0; i<num_slots; i++) {
		sl << p11_slots[i];
	}
	if (p11_slots)
		free(p11_slots);
	return sl;
}

QString pkcs11_lib::driverInfo()
{
	CK_INFO info;
	CK_RV rv;

	CALL_P11_C(this, C_GetInfo, &info);
	if (rv != CKR_OK) {
		pk11error("C_GetInfo", rv);
	}

	return QString(
	"Cryptoki version: %1.%2\n"
	"Manufacturer: %3\n"
	"Library: %4 (%5.%6)\n").
	arg(info.cryptokiVersion.major).arg(info.cryptokiVersion.minor).
	arg(UTF8QSTRING(info.manufacturerID, 32)).
	arg(UTF8QSTRING(info.libraryDescription, 32)).
	arg(info.libraryVersion.major).arg(info.libraryVersion.minor);
}

pkcs11_lib *pkcs11_lib_list::add_lib(QString fname)
{
	foreach(pkcs11_lib *l, *this) {
		if (l->filename() == fname)
			return l;
	}
	pkcs11_lib *l = new pkcs11_lib(fname);
	append(l);
	return l;
}

pkcs11_lib *pkcs11_lib_list::get_lib(QString fname)
{
	foreach(pkcs11_lib *l, *this) {
		if (l->filename() == fname)
			return l;
	}
	return NULL;
}

bool pkcs11_lib_list::remove_lib(QString fname)
{
	for(int i=0; i<count(); i++) {
		if (at(i)->filename() == fname) {
			delete takeAt(i);
			return true;
		}
	}
	return false;
}

slotidList pkcs11_lib_list::getSlotList()
{
	slotidList list;
	QString ex;
	bool success = false;

	for (int i=0; i<count(); i++) {
		pkcs11_lib *l = at(i);
		try {
			QList<unsigned long> realids;
			realids = l->getSlotList();
			foreach(int id, realids)
				list << slotid(l, id);
			success = true;
		} catch (errorEx &e) {
			ex = e.getString();
		}
	}
	if (success || ex.isEmpty())
		return list;
	throw errorEx(ex);
}

const char *pk11errorString(unsigned long rv)
{
#define PK11_ERR(x) case x : return #x;

	switch (rv) {
		PK11_ERR(CKR_OK)
		PK11_ERR(CKR_CANCEL)
		PK11_ERR(CKR_HOST_MEMORY)
		PK11_ERR(CKR_SLOT_ID_INVALID)
		PK11_ERR(CKR_GENERAL_ERROR)
		PK11_ERR(CKR_FUNCTION_FAILED)
		PK11_ERR(CKR_ARGUMENTS_BAD)
		PK11_ERR(CKR_NO_EVENT)
		PK11_ERR(CKR_NEED_TO_CREATE_THREADS)
		PK11_ERR(CKR_CANT_LOCK)
		PK11_ERR(CKR_ATTRIBUTE_READ_ONLY)
		PK11_ERR(CKR_ATTRIBUTE_SENSITIVE)
		PK11_ERR(CKR_ATTRIBUTE_TYPE_INVALID)
		PK11_ERR(CKR_ATTRIBUTE_VALUE_INVALID)
		PK11_ERR(CKR_DATA_INVALID)
		PK11_ERR(CKR_DATA_LEN_RANGE)
		PK11_ERR(CKR_DEVICE_ERROR)
		PK11_ERR(CKR_DEVICE_MEMORY)
		PK11_ERR(CKR_DEVICE_REMOVED)
		PK11_ERR(CKR_ENCRYPTED_DATA_INVALID)
		PK11_ERR(CKR_ENCRYPTED_DATA_LEN_RANGE)
		PK11_ERR(CKR_FUNCTION_CANCELED)
		PK11_ERR(CKR_FUNCTION_NOT_PARALLEL)
		PK11_ERR(CKR_FUNCTION_NOT_SUPPORTED)
		PK11_ERR(CKR_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_KEY_SIZE_RANGE)
		PK11_ERR(CKR_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_KEY_NOT_NEEDED)
		PK11_ERR(CKR_KEY_CHANGED)
		PK11_ERR(CKR_KEY_NEEDED)
		PK11_ERR(CKR_KEY_INDIGESTIBLE)
		PK11_ERR(CKR_KEY_FUNCTION_NOT_PERMITTED)
		PK11_ERR(CKR_KEY_NOT_WRAPPABLE)
		PK11_ERR(CKR_KEY_UNEXTRACTABLE)
		PK11_ERR(CKR_MECHANISM_INVALID)
		PK11_ERR(CKR_MECHANISM_PARAM_INVALID)
		PK11_ERR(CKR_OBJECT_HANDLE_INVALID)
		PK11_ERR(CKR_OPERATION_ACTIVE)
		PK11_ERR(CKR_OPERATION_NOT_INITIALIZED)
		PK11_ERR(CKR_PIN_INCORRECT)
		PK11_ERR(CKR_PIN_INVALID)
		PK11_ERR(CKR_PIN_LEN_RANGE)
		PK11_ERR(CKR_PIN_EXPIRED)
		PK11_ERR(CKR_PIN_LOCKED)
		PK11_ERR(CKR_SESSION_CLOSED)
		PK11_ERR(CKR_SESSION_COUNT)
		PK11_ERR(CKR_SESSION_HANDLE_INVALID)
		PK11_ERR(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
		PK11_ERR(CKR_SESSION_READ_ONLY)
		PK11_ERR(CKR_SESSION_EXISTS)
		PK11_ERR(CKR_SESSION_READ_ONLY_EXISTS)
		PK11_ERR(CKR_SESSION_READ_WRITE_SO_EXISTS)
		PK11_ERR(CKR_SIGNATURE_INVALID)
		PK11_ERR(CKR_SIGNATURE_LEN_RANGE)
		PK11_ERR(CKR_TEMPLATE_INCOMPLETE)
		PK11_ERR(CKR_TEMPLATE_INCONSISTENT)
		PK11_ERR(CKR_TOKEN_NOT_PRESENT)
		PK11_ERR(CKR_TOKEN_NOT_RECOGNIZED)
		PK11_ERR(CKR_TOKEN_WRITE_PROTECTED)
		PK11_ERR(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_UNWRAPPING_KEY_SIZE_RANGE)
		PK11_ERR(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_USER_ALREADY_LOGGED_IN)
		PK11_ERR(CKR_USER_NOT_LOGGED_IN)
		PK11_ERR(CKR_USER_PIN_NOT_INITIALIZED)
		PK11_ERR(CKR_USER_TYPE_INVALID)
		PK11_ERR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
		PK11_ERR(CKR_USER_TOO_MANY_TYPES)
		PK11_ERR(CKR_WRAPPED_KEY_INVALID)
		PK11_ERR(CKR_WRAPPED_KEY_LEN_RANGE)
		PK11_ERR(CKR_WRAPPING_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_WRAPPING_KEY_SIZE_RANGE)
		PK11_ERR(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_RANDOM_SEED_NOT_SUPPORTED)
		PK11_ERR(CKR_RANDOM_NO_RNG)
		PK11_ERR(CKR_DOMAIN_PARAMS_INVALID)
		PK11_ERR(CKR_BUFFER_TOO_SMALL)
		PK11_ERR(CKR_SAVED_STATE_INVALID)
		PK11_ERR(CKR_INFORMATION_SENSITIVE)
		PK11_ERR(CKR_STATE_UNSAVEABLE)
		PK11_ERR(CKR_CRYPTOKI_NOT_INITIALIZED)
		PK11_ERR(CKR_CRYPTOKI_ALREADY_INITIALIZED)
		PK11_ERR(CKR_MUTEX_BAD)
		PK11_ERR(CKR_MUTEX_NOT_LOCKED)
		PK11_ERR(CKR_VENDOR_DEFINED)
	}
	return "unknown PKCS11 error";
}

void pk11error(QString func, int rv)
{
	WAITCURSOR_END
	errorEx err(QObject::tr("PKCS#11 function '%1' failed: %2").arg(func).
		arg(pk11errorString(rv)));
	throw err;
}

void pk11error(slotid slot, QString func, int rv)
{
	WAITCURSOR_END
	errorEx err(QObject::tr("PKCS#11 function '%1' failed: %2\nIn library %3\n%4").
		arg(func).arg(pk11errorString(rv)).arg(slot.lib->filename()).
		arg(slot.lib->driverInfo()));
	throw err;
}
