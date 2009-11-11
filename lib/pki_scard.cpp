/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_scard.h"
#include "pass_info.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "pkcs11.h"
#include "x509name.h"
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
			ign_openssl_error(); \
			return false; \
		} \
		if (!silent) \
			printf("SUCCESS: '%s' : '%s'\n", cmd, value?value:"");\
	} while(0);

ENGINE *pki_scard::p11_engine = NULL;

bool pki_scard::init_p11engine(QString file, bool silent)
{
	ENGINE *e;
	QString engine_path;

#ifdef WIN32
	static bool loaded = false;
	if (loaded)
		return true;
	loaded = true;
#endif
	silent = false;
	if (file.isEmpty())
                file = PKCS11_DEFAULT_MODULE_NAME;

	if (p11_engine) {
		ENGINE_finish(p11_engine);
		ENGINE_free(p11_engine);
		p11_engine = NULL;
	}

	if (!pkcs11::load_lib(file, silent))
		return false;
#ifdef WIN32
	engine_path = QString(".\\") + ENGINE_LIB;
#else
	engine_path = ENGINE_LIB;
#endif
	ENGINE_load_dynamic();
	e = ENGINE_by_id("dynamic");

	XCA_ENGINE_cmd(e, "SO_PATH",      CCHAR(engine_path));
//	XCA_ENGINE_cmd(e, "DIR_ADD",      CCHAR(getPrefix() + "\\"));
	XCA_ENGINE_cmd(e, "ID",           "pkcs11");
	XCA_ENGINE_cmd(e, "LIST_ADD",     "1");
	XCA_ENGINE_cmd(e, "LOAD",         NULL);
	XCA_ENGINE_cmd(e, "MODULE_PATH",  CCHAR(file));

	ENGINE_init(e);
	if (ERR_peek_error() != 0)
		return false;
	p11_engine = e;
	return true;
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

EVP_PKEY *pki_scard::load_pubkey(pkcs11 &p11, CK_OBJECT_HANDLE object) const
{
	const unsigned char *p;
	unsigned long s, keytype;
	EVP_PKEY *pkey = NULL;

	pk11_attr_ulong type(CKA_KEY_TYPE);
	p11.loadAttribute(type, object);
	keytype = type.getValue();

	switch (keytype) {
	case CKK_RSA: {
		RSA *rsa = RSA_new();

		pk11_attr_data n(CKA_MODULUS);
		p11.loadAttribute(n, object);
		rsa->n = n.getBignum();

		pk11_attr_data e(CKA_PUBLIC_EXPONENT);
		p11.loadAttribute(e, object);
		rsa->e = e.getBignum();

		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_RSA(pkey, rsa);
		break;
	}
	case CKK_DSA: {
		DSA *dsa = DSA_new();

		pk11_attr_data p(CKA_PRIME);
		p11.loadAttribute(p, object);
		dsa->p = p.getBignum();

		pk11_attr_data q(CKA_SUBPRIME);
		p11.loadAttribute(q, object);
		dsa->q = q.getBignum();

		pk11_attr_data g(CKA_BASE);
		p11.loadAttribute(g, object);
		dsa->g = g.getBignum();

		pk11_attr_data pub(CKA_VALUE);
		p11.loadAttribute(pub, object);
		dsa->pub_key = pub.getBignum();

		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_DSA(pkey, dsa);
		break;
	}
	case CKK_EC: {
		EC_KEY *ec = EC_KEY_new();

		pk11_attr_data grp(CKA_EC_PARAMS);
                p11.loadAttribute(grp, object);
		s = grp.getValue(&p);
		EC_GROUP *group = d2i_ECPKParameters(NULL, &p, s);
		EC_GROUP_set_asn1_flag(group, 1);
		EC_KEY_set_group(ec, group);
		openssl_error();

		pk11_attr_data pt(CKA_EC_POINT);
                p11.loadAttribute(pt, object);
		BIGNUM *bn = pt.getBignum();
		BN_CTX *ctx = BN_CTX_new();
		EC_POINT *point = EC_POINT_bn2point(group, bn, NULL, ctx);
		EC_KEY_set_public_key(ec, point);
		BN_CTX_free(ctx);
		openssl_error();

		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pkey, ec);
		break;
	}
	default:
		throw errorEx(QString("Unsupported CKA_KEY_TYPE: %1\n").arg(keytype));
	}
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

	pk11_attr_data id(CKA_ID);
	p11.loadAttribute(id, object);
	object_id.setNum(CCHAR(id.getText())[0], 16);

	try {
		pk11_attr_data label(CKA_LABEL);
		p11.loadAttribute(label, object);
		slot_label = label.getText();
	} catch (errorEx &err) {
		printf("No PubKey Label: %s\n", err.getCString());
		// ignore
	}
	if (slot_label.isEmpty()) {
		try{
			unsigned long s;
			const unsigned char *p;
			x509name xn;

			pk11_attr_data subj(CKA_SUBJECT);
			p11.loadAttribute(subj, object);
			s = subj.getValue(&p);
			xn.d2i(p, s);
			slot_label = xn.getMostPopular();
		} catch (errorEx &err) {
			printf("No Pubkey Subject: %s\n", err.getCString());
			// ignore
		}
	}
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
	QList<unsigned long> p11_slots;
	int i;

	if (!pkcs11::loaded())
		return -1;
	while (1) {
		p11_slots = p11.getSlotList();
		for (i=0; i<p11_slots.count(); i++) {
			pkcs11 myp11;
			QStringList sl = myp11.tokenInfo(p11_slots[i]);
			if (sl[0] == card_label &&
			    sl[1] == card_manufacturer &&
			    sl[2] == card_serial)
			{
				break;
			}
		}
		if (i < p11_slots.count())
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

	for (i=0; i<p11_slots.count(); i++) {
		p11.startSession(p11_slots[i]);

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
					return p11_slots[i];
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

