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
#define ENGINE_LIB			"engine_pkcs11.dll"
#else
#define PKCS11_DEFAULT_MODULE_NAME      "/usr/lib/opensc-pkcs11.so"
#define ENGINE_LIB			"/usr/lib/engines/engine_pkcs11.so"
#endif

QPixmap *pki_scard::icon[1] = { NULL };

#define XCA_ENGINE_cmd(e, cmd, value) \
	do { \
		if (!ENGINE_ctrl_cmd_string(e, cmd, value, 0)) { \
			if (!silent) \
				printf("FAILED: '%s' : '%s'\n", \
					 cmd, value ? value:"");\
			ENGINE_free(e); \
			return false; \
		} \
		if (!silent) \
			printf("SUCCESS: '%s' : '%s'\n", cmd, value?value:"");\
	} while(0);

ENGINE *pki_scard::p11_engine = NULL;

bool pki_scard::init_p11engine(QString file, bool silent)
{
	ENGINE *e;

	if (file.isEmpty())
                file = PKCS11_DEFAULT_MODULE_NAME;

	if (p11_engine) {
		ENGINE_finish(p11_engine);
		ENGINE_free(p11_engine);
	}

	if (!pkcs11::load_lib(file, silent))
		return false;

	ENGINE_load_dynamic();
	e = ENGINE_by_id("dynamic");

	XCA_ENGINE_cmd(e, "SO_PATH",      ENGINE_LIB);
	XCA_ENGINE_cmd(e, "ID",           "pkcs11");
	XCA_ENGINE_cmd(e, "LIST_ADD",     "1");
	XCA_ENGINE_cmd(e, "LOAD",         NULL);
	XCA_ENGINE_cmd(e, "MODULE_PATH",  CCHAR(file));

	ENGINE_init(e);
	p11_engine = e;
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

static EVP_PKEY *load_pubkey(pkcs11 &p11, CK_OBJECT_HANDLE object)
{
	const unsigned char *p;
	unsigned long s;

	pk11_attr_data rsaPub(CKA_VALUE);
	p11.loadAttribute(rsaPub, object);
	s = rsaPub.getValue(&p);
	RSA *rsa = d2i_RSAPublicKey(NULL, &p, s);

	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, rsa);
	return pkey;
}

void pki_scard::load_token(pkcs11 &p11, CK_OBJECT_HANDLE object)
{
	QStringList sl = p11.tokenInfo();
	card_label = sl[0];
	card_manufacturer = sl[1];
	card_serial = sl[2];

	pk11_attr_ulong bits(CKA_MODULUS_BITS);
	p11.loadAttribute(bits, object);
	bit_length.setNum(bits.getValue());

	pk11_attr_data label(CKA_LABEL);
	p11.loadAttribute(label, object);
	slot_label = label.getText();

	pk11_attr_data id(CKA_ID);
	p11.loadAttribute(id, object);
	object_id.setNum(CCHAR(id.getText())[0], 16);

	EVP_PKEY *pkey = load_pubkey(p11, object);
	if (pkey) {
		if (key)
			EVP_PKEY_free(key);
		key = pkey;
	}
	setIntName(card_label + " (" + slot_label + ")");
	openssl_error();
}

QList<int> pki_scard::possibleHashNids()
{
	QList<int> nids;
	int i;

	for (i=0; i< mech_list.count(); i++) {
		switch (mech_list[i]) {
		case CKM_MD5_RSA_PKCS:    nids << NID_md5; break;
		case CKM_DSA_SHA1:
		case CKM_ECDSA_SHA1:
		case CKM_SHA1_RSA_PKCS:   nids << NID_sha1; break;
		case CKM_SHA256_RSA_PKCS: nids << NID_sha256; break;
		case CKM_SHA384_RSA_PKCS: nids << NID_sha384; break;
		case CKM_SHA512_RSA_PKCS: nids << NID_sha512; break;
		case CKM_RIPEMD160_RSA_PKCS: nids << NID_ripemd160; break;
		}
	}
	return nids;
}

/* Assures the correct card is inserted and
 * returns the slot ID or -1 on error or abort */
int pki_scard::prepare_card() const
{
	pkcs11 p11;
        CK_SLOT_ID *p11_slots = NULL;
        unsigned long i, num_slots;

	if (!pkcs11::loaded())
		return -1;
	while (1) {
		p11_slots = p11.getSlotList(&num_slots);
		for (i=0; i<num_slots; i++) {
			pkcs11 myp11;
			QStringList sl = myp11.tokenInfo(i);
			if (sl[0] == card_label &&
			    sl[1] == card_manufacturer &&
			    sl[2] == card_serial)
			{
				break;
			}
		}
		if (i<num_slots)
			break;
		QString msg = tr("Please insert card :'") +
			card_manufacturer + " [" + card_label +
			"] " + tr("with Serial: ") + card_serial;

		int r = QMessageBox::warning(NULL, XCA_TITLE, msg,
			tr("&OK"), tr("Abort"));
		if (r == 1) {
			return -1;
		}
	}

	pk11_attr_ulong class_att = pk11_attr_ulong(CKA_CLASS);
	QList<CK_OBJECT_HANDLE> objects;

	for (i=0; i<num_slots; i++) {
		p11.startSession(i);

		class_att.setValue(CKO_PUBLIC_KEY);
		objects = p11.objectList(&class_att);

		for (int j=0; j< objects.count(); j++) {
			CK_OBJECT_HANDLE object = objects[j];
			QString cid;

			pk11_attr_data id(CKA_ID);
			p11.loadAttribute(id, object);
			cid.setNum(CCHAR(id.getText())[0], 16);

			if (cid == object_id) {
				EVP_PKEY *pkey = load_pubkey(p11, object);
				if (EVP_PKEY_cmp(key, pkey) == 1)
					return i;
				QMessageBox::warning(NULL, XCA_TITLE, tr("Public Key missmatch. Please re-import card"), tr("&OK"));
			}
		}
	}
	return -1;
}

pki_scard::~pki_scard()
{
}

unsigned char *pki_scard::toData(int *size)
{
	size_t s;
	unsigned char *p, *p1;
	int i;

	s = card_serial.length() + card_manufacturer.length() +
		card_label.length() + bit_length.length() +
		slot_label.length() + object_id.length() +
		7 *sizeof(char) + i2d_PUBKEY(key, NULL) +
		(mech_list.count() + 1) * sizeof(uint32_t);

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
	db::intToData(&p1, mech_list.count());
	for (i=0; i<mech_list.count(); i++)
		db::intToData(&p1, mech_list[i]);

	i2d_PUBKEY(key, &p1);
	openssl_error();

	*size = p1-p;
	return p;
}

void pki_scard::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;
	unsigned long count, i;
	const unsigned char *p1 = p;

	size = head->len - sizeof(db_header_t);
        version = head->version;

	card_serial = db::stringFromData(&p1);
	card_manufacturer = db::stringFromData(&p1);
	card_label = db::stringFromData(&p1);
	slot_label = db::stringFromData(&p1);
	bit_length = db::stringFromData(&p1);
	object_id  = db::stringFromData(&p1);
	count      = db::intFromData(&p1);
	mech_list.clear();
	for (i=0; i<count; i++)
		mech_list << db::intFromData(&p1);

	d2i_PUBKEY(&key, &p1, size - (p1-p));

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
	return tr("SmartCard") + " " + pki_key::getTypeString();
}

QString pki_scard::scardLogin(pkcs11 &p11, bool so, bool force) const
{
	char _pin[256], *pin = _pin;
	int pinlen;
	bool need_login;

	QString text = so ?
		tr("Please enter the SO PIN (PUK) of the token: "):
		tr("Please enter the PIN of the token: ");

	pass_info p(XCA_TITLE, text + getIntName());
	p.setPin();
	need_login = p11.needsLogin(so);
	if (force || need_login) {
		if (!need_login)
			 p11.logout();
		if (p11.protAuthPath()) {
			pin = NULL;
			pinlen = 0;
		} else {
			pinlen = MainWindow::passRead(pin, 256, 0, &p);
			if (pinlen == -1)
				return QString();
		}
		p11.login((unsigned char*)pin, pinlen, so);
		pin = _pin;
	} else {
		return QString("");
	}
	return QString::fromLocal8Bit(pin, pinlen);
}

EVP_PKEY *pki_scard::decryptKey() const
{
	int slot_id;
	QString pin;
	struct {
		char *password;
		const char *prompt_info;
        } cb_data = { NULL, NULL };

	slot_id = prepare_card();
	if (slot_id == -1)
		return NULL;

	QString key_id = QString("%1:").arg(slot_id) + object_id;

	pkcs11 p11;
	p11.startSession(slot_id, true);
	pin = scardLogin(p11, false);
	if (pin.isNull())
		return NULL;
	cb_data.password = strdup(CCHAR(pin));
	printf("PASSWORT: '%s'\n", cb_data.password);
	EVP_PKEY *pkey = ENGINE_load_private_key(p11_engine, CCHAR(key_id),
				NULL, &cb_data);
	free(cb_data.password);
	openssl_error();
	return pkey;
}

void pki_scard::changePin()
{
	char newPin[256], *pinp;
	int slot;
	QString pin;

	slot = prepare_card();
	if (slot == -1)
		return;

	pkcs11 p11;
	p11.startSession(slot, true);
	p11.logout();
	if (p11.protAuthPath()) {
		p11.setPin(NULL, 0, NULL ,0);
	}
	pin = scardLogin(p11, false, true);
	if (pin.isNull())
		return;
	pass_info p(XCA_TITLE, tr("Please enter the new Pin for the token: ") +
				getIntName());
	p.setPin();

	int newPinLen = MainWindow::passWrite(newPin, 256, 0, &p);
	pinp = strdup(CCHAR(pin));
	if (newPinLen != -1) {
		p11.setPin((unsigned char*)pinp, pin.length(),
			(unsigned char*)newPin, newPinLen);
	}
	free(pinp);
}

void pki_scard::initPin()
{
	char soPin[256], newPin[256];
	int slot;

	pass_info p(XCA_TITLE,
		pki_scard::tr("Please enter the SO PIN (PUK) of the token: ") +
		getIntName());
	p.setPin();

	slot = prepare_card();
	if (slot == -1)
		return;
	pkcs11 p11;
	p11.startSession(slot, true);
	if (p11.needsLogin(true)) {
		int soPinLen = MainWindow::passRead(soPin, 256, 0, &p);
		if (soPinLen == -1)
			return;
		p11.login((unsigned char*)soPin, soPinLen, true);
	}
	p.setDescription(qApp->translate("MainWindow",
		"Please enter the new Pin for the token: ") +getIntName());

	int newPinLen = MainWindow::passWrite(newPin, 256, 0, &p);
	if (newPinLen != -1) {
		p11.initPin((unsigned char*)newPin, newPinLen);
	}
	p11.logout();
}

void pki_scard::changeSoPin()
{
	char oldPin[256], newPin[256];
	int slot;

	pass_info p(XCA_TITLE,
		pki_scard::tr("Please enter the SO PIN (PUK) of the token: ") +
		getIntName());
	p.setPin();

	slot = prepare_card();
	if (slot == -1)
		return;
	int oldPinLen = MainWindow::passRead(oldPin, 256, 0, &p);
	if (oldPinLen == -1)
		return;
	pkcs11 p11;
	p11.startSession(slot, true);
	p11.logout();
	p11.login((unsigned char*)oldPin, oldPinLen, true);

	p.setDescription(qApp->translate("MainWindow",
		"Please enter the new SO Pin for the token: ") +getIntName());

	int newPinLen = MainWindow::passWrite(newPin, 256, 0, &p);
	if (newPinLen == -1) {
		p11.setPin((unsigned char*)oldPin, oldPinLen,
			(unsigned char*)newPin, newPinLen);
	}
	p11.logout();
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
	return bit_length + " bit";
}

QVariant pki_scard::getIcon()
{
	return QVariant(*icon[0]);
}

