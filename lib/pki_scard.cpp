/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_scard.h"
#include "pass_info.h"
#include "pk11_attribute.h"
#include "func.h"
#include "db.h"
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <qprogressdialog.h>
#include <qapplication.h>
#include <qdir.h>
#include <widgets/MainWindow.h>
#include <qmessagebox.h>
#include <ltdl.h>

#include "exception.h"
#include "db_base.h"
#include "pkcs11.h"


#if defined(_WIN32) || defined(USE_CYGWIN)
#define PKCS11_DEFAULT_MODULE_NAME      "opensc-pkcs11.dll"
#define ENGINE_LIB			"/usr/lib/engines/engine_pkcs11.so"
#else
#define PKCS11_DEFAULT_MODULE_NAME      "opensc-pkcs11.so"
#define ENGINE_LIB			"engine_pkcs11.so"
#endif

QPixmap *pki_scard::icon[1] = { NULL };

#define XCA_ENGINE_cmd(e, cmd, value) \
	do { \
		if (!ENGINE_ctrl_cmd_string(e, cmd, value, 0)) { \
			openssl_error(); \
			return 0; \
		} \
	} while(0);

int pki_scard::init_scard(void)
{
	ENGINE *e;
	static int initialized = false;

	if (initialized)
		return 1;

	e = ENGINE_by_id("dynamic");

	XCA_ENGINE_cmd(e, "SO_PATH",      ENGINE_LIB);
	XCA_ENGINE_cmd(e, "ID",           "pkcs11");
	XCA_ENGINE_cmd(e, "LIST_ADD",     "1");
	XCA_ENGINE_cmd(e, "LOAD",         NULL);
	XCA_ENGINE_cmd(e, "MODULE_PATH",  PKCS11_DEFAULT_MODULE_NAME);
	ENGINE_init(e);

	initialized = true;
	ENGINE_free(e);
	return 1;
}

void pki_scard::init(void)
{
	class_name = "pki_scard";
	ownPass = ptPin;
	dataVersion = 1;
	pkiType = smartCard;
	cols = 5;

	card_serial = card_manufacturer = card_label = "";
	bit_length = slot_label = "";
}

pki_scard::pki_scard(const QString name)
	:pki_key(name)
{
	init();
}

bool pki_scard::compare(pki_base *ref)
{
	if (ref->getType() != getType())
		return false;
	pki_scard *card = (pki_scard *)ref;
	if (card_serial != card->card_serial)
		return false;
	if (card_manufacturer != card->card_manufacturer)
		return false;
	if (card_label != card->card_label)
		return false;
	if (slot_label != card->slot_label)
		return false;
	return true;
}

void pki_scard::load_token(unsigned long slot)
{
	QList<CK_OBJECT_HANDLE> objects;
	pk11_attr_ulong class_att = pk11_attr_ulong(CKA_CLASS);
	pkcs11 p11;

	QStringList sl = p11.tokenInfo(slot);
	card_label = sl[0];
	card_manufacturer = sl[1];
	card_serial = sl[2];

	p11.startSession(slot);
	class_att.setValue(CKO_PUBLIC_KEY);
	objects = p11.objectList(&class_att);

	printf("OBJ: %d\n", objects.count());
	for (int i=0; i< objects.count(); i++) {
		CK_OBJECT_HANDLE object = objects[i];

		pk11_attr_ulong bits(CKA_MODULUS_BITS);
		p11.loadAttribute(bits, object);
		bit_length.setNum(bits.getValue());

		pk11_attr_data label(CKA_LABEL);
		p11.loadAttribute(label, object);
		slot_label = label.getText();

		pk11_attr_data id(CKA_ID);
		p11.loadAttribute(id, object);
		object_id.setNum(CCHAR(id.getText())[0], 16);

		printf("OBJ[%d] '%s' '%s' '%s'\n", i, CCHAR(slot_label), CCHAR(bit_length), CCHAR(object_id));
	}
	setIntName(card_label + " (" + slot_label + ")");
}

pki_scard::~pki_scard()
{
}

unsigned char *pki_scard::toData(int *size)
{
	size_t s;
	unsigned char *p, *p1;

	s = card_serial.length() + card_manufacturer.length() +
		card_label.length() + bit_length.length() +
		slot_label.length() + object_id.length() +
		7 *sizeof(char);

	p = (unsigned char *)OPENSSL_malloc(s);
        check_oom(p);
        openssl_error();
	p1 = p;

	db::stringToData(&p1, card_serial);
	db::stringToData(&p1, card_manufacturer);
	db::stringToData(&p1, card_label);
	db::stringToData(&p1, slot_label);
	db::stringToData(&p1, bit_length);
	db::stringToData(&p1, object_id);

	*size = p1-p;
	return p;
}

void pki_scard::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;
	const unsigned char *p1 = p;

	size = head->len - sizeof(db_header_t);
        version = head->version;

	card_serial = db::stringFromData(&p1);
	card_manufacturer = db::stringFromData(&p1);
	card_label = db::stringFromData(&p1);
	slot_label = db::stringFromData(&p1);
	bit_length = db::stringFromData(&p1);
	object_id  = db::stringFromData(&p1);

	printf("%s: size: %d, read: %ld\n", CCHAR(getIntName()), size, p1-p);
	if (p1-p != size) {
		my_error(tr("Wrong Size of scard: ") + getIntName());
	}
}

bool pki_scard::isPubKey() const
{
	return false;
}

QString pki_scard::getTypeString(void)
{
	return QString("SmartCard");
}

EVP_PKEY *pki_scard::decryptKey() const
{
	// Engine code here
	return NULL;
}

int pki_scard::verify()
{
	return true;
}

bool pki_scard::isScard()
{
	return true;
}

QString pki_scard::length()
{
	return bit_length;
}

QVariant pki_scard::getIcon()
{
	return QVariant(*icon[0]);
}

