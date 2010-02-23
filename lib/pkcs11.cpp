#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "func.h"
#include "pass_info.h"

#include <openssl/rand.h>
#include <qmessagebox.h>
#include <ltdl.h>

CK_FUNCTION_LIST *pkcs11::p11 = NULL;
lt_dlhandle pkcs11::dl_handle = NULL;

pkcs11::pkcs11()
{
	session = CK_INVALID_HANDLE;
	object = CK_INVALID_HANDLE;
	slot_id = 0;
}

pkcs11::~pkcs11()
{
	if (session != CK_INVALID_HANDLE && p11)
		p11->C_CloseSession(session);
}

void pkcs11::startSession(unsigned long slot, bool rw)
{
	CK_RV rv;
	unsigned long flags = CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0);

	if (session != CK_INVALID_HANDLE) {
		rv = p11->C_CloseSession(session);
		if (rv != CKR_OK)
			pk11error("C_OpenSession", rv);
	}
	rv = p11->C_OpenSession(slot, flags, NULL, NULL, &session);
        if (rv != CKR_OK)
                pk11error("C_OpenSession", rv);
	slot_id = slot;
}

QList<unsigned long> pkcs11::getSlotList()
{
	CK_RV rv;
	CK_SLOT_ID *p11_slots = NULL;
	QList<unsigned long> sl;
	unsigned long i, num_slots = 0;

	/* This one helps to avoid errors.
	 * Fist time it fails, 2nd time it works */
	p11->C_GetSlotList(CK_TRUE, p11_slots, &num_slots);
	while (1) {
		rv = p11->C_GetSlotList(CK_TRUE, p11_slots, &num_slots);
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

QList<CK_MECHANISM_TYPE> pkcs11::mechanismList(unsigned long slot)
{
	CK_RV rv;
	CK_MECHANISM_TYPE *m;
	QList<CK_MECHANISM_TYPE> ml;
	unsigned long count;

	rv = p11->C_GetMechanismList(slot, NULL, &count);
	if (count != 0) {
		m = (CK_MECHANISM_TYPE *)malloc(count *sizeof(*m));
		check_oom(m);

		rv = p11->C_GetMechanismList(slot, m, &count);
		if (rv != CKR_OK) {
			free(m);
			pk11error("C_GetMechanismList", rv);
		}
		for (unsigned i=0; i<count; i++) {
			ml << m[i];
		}
		free(m);
	}
	return ml;
}

void pkcs11::mechanismInfo(unsigned long slot, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO *info)
{
	CK_RV rv;
	rv = p11->C_GetMechanismInfo(slot, m, info);
	if (rv != CKR_OK) {
		pk11error("C_GetMechanismInfo", rv);
	}
}

void pkcs11::logout() const
{
	CK_RV rv;

	rv = p11->C_Logout(session);
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
		pk11error("C_Logout", rv);
}

bool pkcs11::needsLogin(bool so)
{
	CK_SESSION_INFO sinfo;
	CK_RV rv;

	rv = p11->C_GetSessionInfo(session, &sinfo);
	if (rv != CKR_OK)
                pk11error("C_GetSessionInfo", rv);

	switch (sinfo.state) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RW_PUBLIC_SESSION:
		return true;
	case CKS_RW_SO_FUNCTIONS:
		if (so) {
			return false;
		} else {
			logout();
			return true;
		}
	case CKS_RO_USER_FUNCTIONS:
	case CKS_RW_USER_FUNCTIONS:
		if (!so) {
			return false;
		} else {
			logout();
			return true;
		}
	}
	return true;
}

void pkcs11::login(unsigned char *pin, unsigned long pinlen, bool so)
{
	unsigned long user = so ? CKU_SO : CKU_USER;
	CK_RV rv;

	rv = p11->C_Login(session, user, pin, pinlen);
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		pk11error("C_Login", rv);
}

QString pkcs11::tokenLogin(QString name, bool so, bool force)
{
	char _pin[256], *pin = _pin;
	int pinlen;
	bool need_login;

	QString text = so ?
		QObject::tr("Please enter the SO PIN (PUK) of the token %1"):
		QObject::tr("Please enter the PIN of the token %1");

	pass_info p(XCA_TITLE, text.arg(name));
	p.setPin();
	need_login = needsLogin(so);
	if (force || need_login) {
		if (!need_login)
			 logout();
		if (protAuthPath()) {
			pin = NULL;
			pinlen = 0;
		} else {
			pinlen = MainWindow::passRead(pin, 256, 0, &p);
			if (pinlen == -1)
				return QString();
		}
		login((unsigned char*)pin, pinlen, so);
	} else {
		return QString("");
	}
	return QString::fromLocal8Bit(pin, pinlen);
}

void pkcs11::setPin(unsigned char *oldPin, unsigned long oldPinLen,
	    unsigned char *pin, unsigned long pinLen)
{
	CK_RV rv = p11->C_SetPIN(session, oldPin, oldPinLen, pin, pinLen);
	if (rv != CKR_OK)
		pk11error("C_SetPIN", rv);
}

void pkcs11::initPin(unsigned char *pin, unsigned long pinLen)
{
	CK_RV rv = p11->C_InitPIN(session, pin, pinLen);
	if (rv != CKR_OK)
		pk11error("C_InitPIN", rv);
}

void pkcs11::initToken(unsigned long slot, unsigned char *pin, int pinlen,
		QString label)
{
	unsigned char clabel[32] = {' ', };
	QByteArray ba = label.toUtf8().left(32);
	memcpy(clabel, ba.constData(), ba.size());
	CK_RV rv = p11->C_InitToken(slot, pin, pinlen, clabel);
	if (rv != CKR_OK)
		pk11error("C_InitToken", rv);
}

QStringList pkcs11::tokenInfo(CK_SLOT_ID slot)
{
	QStringList l;
	CK_TOKEN_INFO token_info;
	CK_RV rv;

	rv = p11->C_GetTokenInfo(slot, &token_info);
	if (rv != CKR_OK) {
		pk11error("C_GetTokenInfo", rv);
	}
	l << UTF8QSTRING(token_info.label, 32);
	l << UTF8QSTRING(token_info.manufacturerID, 32);
	l << UTF8QSTRING(token_info.serialNumber, 16);
	return l;
}

QStringList pkcs11::tokenInfo()
{
	return tokenInfo(slot_id);
}

bool pkcs11::protAuthPath(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO token_info;
	CK_RV rv;

	rv = p11->C_GetTokenInfo(slot, &token_info);
	if (rv != CKR_OK) {
		pk11error("C_GetTokenInfo", rv);
	}
	return !!(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
}

bool pkcs11::protAuthPath()
{
	return protAuthPath(slot_id);
}

void pkcs11::loadAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	attribute.load(session, object);
}

void pkcs11::storeAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	attribute.store(session, object);
}

CK_OBJECT_HANDLE pkcs11::createObject(pk11_attlist &attrs)
{
	CK_RV rv;
	CK_OBJECT_HANDLE obj;

	rv = p11->C_CreateObject(session, attrs.getAttributes(), attrs.length(), &obj);
	if (rv != CKR_OK) {
		pk11error("C_CreateObject", rv);
	}
	return obj;
}

int pkcs11::deleteObjects(pk11_attlist &atts)
{
	CK_RV rv;
	QList<CK_OBJECT_HANDLE> objects;

	objects = objectList(atts);
	for (int i=0; i< objects.count(); i++) {
		rv = p11->C_DestroyObject(session, objects[i]);
		if (rv != CKR_OK) {
			pk11error("C_DestroyObject", rv);
		}
	}
	return objects.count();
}

#define ID_LEN 8
pk11_attr_data pkcs11::findUniqueID(unsigned long oclass)
{
	pk11_attr_data id(CKA_ID);
	pk11_attr_ulong class_att(CKA_CLASS, oclass);

	while (1) {
		unsigned char buf[ID_LEN];
		pk11_attlist atts(class_att);
		RAND_pseudo_bytes(buf, ID_LEN);
		id.setValue(buf, ID_LEN);
		atts << id;
		if (objectList(atts).count() == 0)
			break;
	}
	return id;
}

pk11_attr_data pkcs11::generateRSAKey(QString name, unsigned long bits)
{
	CK_RV rv;
	CK_OBJECT_HANDLE pubkey, privkey;
	pk11_attlist priv_atts, pub_atts;
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	pk11_attr_data label(CKA_LABEL, name.toUtf8());

	pk11_attr_data new_id = findUniqueID(CKO_PUBLIC_KEY);

        pub_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_ENCRYPT, true) <<
		pk11_attr_bool(CKA_VERIFY, true) <<
		pk11_attr_bool(CKA_WRAP, true) <<
		pk11_attr_ulong(CKA_MODULUS_BITS, bits) <<
		pk11_attr_data(CKA_PUBLIC_EXPONENT, 0x10001) <<
		label << new_id;

	priv_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, true) <<
		pk11_attr_bool(CKA_SENSITIVE, true) <<
		pk11_attr_bool(CKA_DECRYPT, true) <<
		pk11_attr_bool(CKA_SIGN, true) <<
		pk11_attr_bool(CKA_UNWRAP, true) <<
		label << new_id;

	rv = p11->C_GenerateKeyPair(session, &mechanism,
		pub_atts.getAttributes(), pub_atts.length(),
		priv_atts.getAttributes(), priv_atts.length(),
		&pubkey, &privkey);
	if (rv != CKR_OK) {
		pk11error("C_GenerateKeyPair", rv);
	}
	return new_id;
}

QList<CK_OBJECT_HANDLE> pkcs11::objectList(pk11_attlist &atts)
{
	CK_RV rv;
	CK_OBJECT_HANDLE objects[256];
	QList<CK_OBJECT_HANDLE> list;
	unsigned long len, i, att_num;
	CK_ATTRIBUTE *attribute;

	att_num = atts.get(&attribute);

	rv = p11->C_FindObjectsInit(session, attribute, att_num);

	if (rv != CKR_OK)
		pk11error("C_FindObjectsInit", rv);

	do {
		rv = p11->C_FindObjects(session, objects, 256, &len);
		if (rv != CKR_OK)
			pk11error("C_FindObjects", rv);
		for (i=0; i<len; i++)
			list += objects[i];
	} while (len);

	rv = p11->C_FindObjectsFinal(session);
	if (rv != CKR_OK)
		pk11error("C_FindObjectsFinal", rv);

	return list;
}

bool pkcs11::load_lib(QString file, bool silent)
{
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

	lt_dlinit();

	if (dl_handle) {
		if (lt_dlclose(dl_handle) < 0) {
			if (silent)
				return false;
			throw errorEx("Failed to close PKCS11 library: " + file);
		}
	}
	p11 = NULL;
	dl_handle = NULL;
	if (file.isEmpty()) {
		if (silent)
			return false;
		throw errorEx("PKCS11 library filename empty");
	}

	dl_handle = lt_dlopen(QString2filename(file));
	if (dl_handle == NULL) {
		if (silent)
			return false;
		throw errorEx("Failed to open PKCS11 library: " + file);
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				lt_dlsym(dl_handle, "C_GetFunctionList");
	if (c_get_function_list) {
		if (c_get_function_list(&p11) == CKR_OK)
			return true;
	}
	/* This state is always worth an error ! */
	if (lt_dlclose(dl_handle) == 0)
		dl_handle = NULL;
	throw errorEx("Failed to open PKCS11 library: " + file);
	return false;
}

static const char *CKR2Str(unsigned long rv)
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

void pkcs11::pk11error(QString func, int rv)
{
	errorEx err("PKCS#11 function " + func + " failed: " +
		CKR2Str(rv) + "\n");
	throw err;
}

