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
#include <openssl/bn.h>
#include <qprogressdialog.h>
#include <qapplication.h>
#include <qdir.h>
#include <widgets/MainWindow.h>
#include <qmessagebox.h>
#include <qthread.h>
#include <ltdl.h>

#if defined(_WIN32) || defined(USE_CYGWIN)
#define PKCS11_DEFAULT_MODULE_NAME      "opensc-pkcs11.dll"
#define ENGINE_LIB			"engine_pkcs11.dll"
#else
#define PKCS11_DEFAULT_MODULE_NAME      "/usr/lib/opensc-pkcs11.so"
#define ENGINE_LIB			"/usr/lib/engines/engine_pkcs11.so"
#endif

QPixmap *pki_scard::icon[1] = { NULL };

#define XCA_ENGINE_cmd(cmd, value) \
	do { \
		QString msg = QString(" '%1' : '%2'\n" \
					).arg(cmd).arg(value ? value:""); \
		if (!ENGINE_ctrl_cmd_string(e, cmd, value, 0)) { \
			ENGINE_free(e); \
			if (!silent) { \
				log += QString("FAILED:") + msg; \
				openssl_error(log); \
			} \
			ign_openssl_error(); \
			return false; \
		} \
		log += QString("SUCCESS:") +msg; \
	} while(0);

ENGINE *pki_scard::p11_engine = NULL;

bool pki_scard::init_p11engine(QString file, bool silent)
{
	ENGINE *e;
	const char *engine_path;
	QString log;

#ifdef WIN32
	static bool loaded = false;
	if (loaded)
		return true;
	loaded = true;
#endif
	if (file.isEmpty())
                file = PKCS11_DEFAULT_MODULE_NAME;

	if (p11_engine) {
		log += "Unloading old OpenSSL PKCS#11 engine\n";
		ENGINE_finish(p11_engine);
		ENGINE_free(p11_engine);
		p11_engine = NULL;
		if (!silent) {
			openssl_error(log);
		} else {
			ign_openssl_error();
		}
	}

	if (!pkcs11::load_lib(file, silent))
		return false;
	log += "Successfully loaded PKCS#11 library: " +file +"\n";

#ifdef WIN32
	engine_path = ".\\" ENGINE_LIB;
#else
	engine_path = ENGINE_LIB;
#endif
	ENGINE_load_dynamic();
	e = ENGINE_by_id("dynamic");

	XCA_ENGINE_cmd("SO_PATH",      engine_path);
	XCA_ENGINE_cmd("ID",           "pkcs11");
	XCA_ENGINE_cmd("LIST_ADD",     "1");
	XCA_ENGINE_cmd("LOAD",         NULL);
	XCA_ENGINE_cmd("MODULE_PATH",  QString2filename(file));

	XCA_ENGINE_cmd("VERBOSE",      NULL);

	ENGINE_init(e);

	pkcs11 p11;
	log += p11.driverInfo();

	if (!silent) {
		openssl_error(log);
	} else {
		if (ign_openssl_error())
			return false;
	}
	p11_engine = e;
	return true;
}

void pki_scard::init(void)
{
	class_name = "pki_scard";
	ownPass = ptPin;
	dataVersion = 2;
	pkiType = smartCard;
	cols = 5;

	card_serial = card_manufacturer = card_label = "";
	card_model = slot_label = "";
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
		EVP_PKEY_assign_RSA(pkey, rsa);
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
		EVP_PKEY_assign_DSA(pkey, dsa);
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
		EVP_PKEY_assign_EC_KEY(pkey, ec);
		break;
	}
	default:
		throw errorEx(QString("Unsupported CKA_KEY_TYPE: %1\n").arg(keytype));
	}

	openssl_error();
	return pkey;
}

void pki_scard::load_token(pkcs11 &p11, CK_OBJECT_HANDLE object)
{
	tkInfo ti = p11.tokenInfo();
	card_label = ti.label();
	card_manufacturer = ti.manufacturerID();
	card_serial = ti.serial();
	card_model = ti.model();

	pk11_attr_data id(CKA_ID);
	p11.loadAttribute(id, object);
	if (id.getAttribute()->ulValueLen > 0) {
		BIGNUM *cka_id = id.getBignum();
		object_id = BNoneLine(cka_id);
		BN_free(cka_id);
	}

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
			x509name xn;

			pk11_attr_data subj(CKA_SUBJECT);
			p11.loadAttribute(subj, object);
			QByteArray der = subj.getData();
			xn.d2i(der);
			slot_label = xn.getMostPopular();
			openssl_error();
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
	setIntName(slot_label);
	openssl_error();
}

pk11_attr_data pki_scard::getIdAttr() const
{
	pk11_attr_data id(CKA_ID);
	if (object_id.isEmpty())
		return id;
	BIGNUM *bn = NULL;
	BN_hex2bn(&bn, CCHAR(object_id));
	id.setBignum(bn, true);
	return id;
}

void pki_scard::deleteFromToken()
{
	unsigned long slot;

	if (QMessageBox::question(NULL, XCA_TITLE,
			tr("Delete the private key '%1' from the token?").
			arg(getIntName()),
			QMessageBox::Yes|QMessageBox::No) != QMessageBox::Yes)
		return;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.startSession(slot, true);

	if (p11.tokenLogin(card_label, false).isNull())
		return;

	pk11_attlist attrs(pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY));
		attrs << getIdAttr();
	pk11_attlist priv_attrs(pk11_attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY));
		priv_attrs << getIdAttr();

	if (EVP_PKEY_type(key->type) == EVP_PKEY_RSA) {
		pk11_attr_data modulus(CKA_MODULUS, key->pkey.rsa->n, false);
		attrs << modulus;
		priv_attrs << modulus;
	}
	p11.deleteObjects(attrs);
	p11.deleteObjects(priv_attrs);
}

void pki_scard::store_token(unsigned int slot, EVP_PKEY *pkey)
{
	pk11_attlist pub_atts;
	pk11_attlist priv_atts;
	QList<CK_OBJECT_HANDLE> objects;

	if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA)
		throw errorEx(tr("only RSA keys can be stored on tokens"));

	RSA *rsakey = pkey->pkey.rsa;

	pub_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) <<
		pk11_attr_ulong(CKA_KEY_TYPE, CKK_RSA) <<
		pk11_attr_data(CKA_MODULUS, rsakey->n, false);

	priv_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY) <<
		pk11_attr_ulong(CKA_KEY_TYPE, CKK_RSA) <<
		pk11_attr_data(CKA_MODULUS, rsakey->n, false);

	pkcs11 p11;
	p11.startSession(slot, true);

	QList<CK_OBJECT_HANDLE> objs = p11.objectList(pub_atts);
	if (objs.count() == 0)
		objs = p11.objectList(priv_atts);
	if (objs.count() != 0) {
		QMessageBox::information(NULL, XCA_TITLE,
			tr("This Key is already on the token"));
		load_token(p11, objs[0]);
		return;
	}
	pk11_attr_data new_id = p11.findUniqueID(CKO_PUBLIC_KEY);

	pub_atts <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_data(CKA_LABEL, getIntName().toUtf8()) <<
		new_id <<
		pk11_attr_data(CKA_PUBLIC_EXPONENT, rsakey->e, false) <<
		pk11_attr_bool(CKA_ENCRYPT, true) <<
		pk11_attr_bool(CKA_VERIFY, true);

	priv_atts <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, true) <<
		pk11_attr_data(CKA_LABEL, desc.toUtf8()) <<
		new_id <<
		pk11_attr_data(CKA_PUBLIC_EXPONENT, rsakey->e, false) <<
		pk11_attr_data(CKA_PRIVATE_EXPONENT, rsakey->d, false) <<
		pk11_attr_data(CKA_PRIME_1, rsakey->p, false) <<
		pk11_attr_data(CKA_PRIME_2, rsakey->q, false) <<
		pk11_attr_data(CKA_EXPONENT_1, rsakey->dmp1, false) <<
		pk11_attr_data(CKA_EXPONENT_2, rsakey->dmq1, false) <<
		pk11_attr_data(CKA_COEFFICIENT, rsakey->iqmp, false) <<
		pk11_attr_bool(CKA_DECRYPT, true) <<
		pk11_attr_bool(CKA_SIGN, true);

	tkInfo ti = p11.tokenInfo();
	if (p11.tokenLogin(ti.label(), false).isNull())
		throw errorEx(tr("PIN input aborted"));

	p11.createObject(pub_atts);
	p11.createObject(priv_atts);

	pub_atts.reset();
	pub_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) <<
                pk11_attr_ulong(CKA_KEY_TYPE, CKK_RSA) <<
		new_id <<
                pk11_attr_data(CKA_MODULUS, rsakey->n, false);

	objs = p11.objectList(pub_atts);
	if (objs.count() == 0)
		throw errorEx(tr("Unable to find copied key on the token"));

	load_token(p11, objs[0]);
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
	if (nids.count() == 0) {
		nids << NID_md5 << NID_sha1 << NID_sha256 <<
			NID_sha384 << NID_sha512 << NID_ripemd160;
	}
	return nids;
}

const EVP_MD *pki_scard::getDefaultMD()
{
	if (mech_list.contains(CKM_SHA1_RSA_PKCS))
		return EVP_sha1();
	if (mech_list.contains(CKM_DSA_SHA1))
		return EVP_dss1();
	if (mech_list.contains(CKM_ECDSA_SHA1))
		return EVP_ecdsa();
	if (mech_list.contains(CKM_SHA512_RSA_PKCS))
		return EVP_sha512();
	if (mech_list.contains(CKM_SHA384_RSA_PKCS))
		return EVP_sha384();
	if (mech_list.contains(CKM_SHA256_RSA_PKCS))
		return EVP_sha256();
	if (mech_list.contains(CKM_RIPEMD160_RSA_PKCS))
		return EVP_ripemd160();
	if (mech_list.contains(CKM_MD5_RSA_PKCS))
		return EVP_md5();

	/* Last resort */
	return EVP_sha1();
}

/* Assures the correct card is inserted and
 * returns the slot ID or -1 on error or abort */
bool pki_scard::prepare_card(unsigned long *slot, bool verifyPubkey) const
{
	pkcs11 p11;
	QList<unsigned long> p11_slots;
	int i;

	if (!pkcs11::loaded())
		return false;
	while (1) {
		p11_slots = p11.getSlotList();
		for (i=0; i<p11_slots.count(); i++) {
			pkcs11 myp11;
			tkInfo ti = myp11.tokenInfo(p11_slots[i]);
			if (ti.label() == card_label &&
			    ti.manufacturerID() == card_manufacturer &&
			    ti.serial() == card_serial &&
			    (card_model.isEmpty() || ti.model() == card_model))
			{
				break;
			}
		}
		if (i < p11_slots.count())
			break;
		QString msg = tr("Please insert card: %1 %2 [%3] with Serial: %4").
			arg(card_manufacturer).arg(card_model).
			arg(card_label).arg(card_serial);

		int r = QMessageBox::warning(NULL, XCA_TITLE, msg,
			QMessageBox::Cancel | QMessageBox::Ok);
		if (r == QMessageBox::Cancel) {
			return false;
		}
	}

	*slot = p11_slots[i];
	if (!verifyPubkey)
		return true;

	QList<CK_OBJECT_HANDLE> objects;

	p11.startSession(p11_slots[i]);

	pk11_attlist cls (pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY));
	cls << getIdAttr();

	objects = p11.objectList(cls);

	for (int j=0; j< objects.count(); j++) {
		CK_OBJECT_HANDLE object = objects[j];
		EVP_PKEY *pkey = load_pubkey(p11, object);
		if (EVP_PKEY_cmp(key, pkey) == 1)
			return true;
		if (!object_id.isEmpty())
			QMessageBox::warning(NULL, XCA_TITLE,
			   tr("Public Key missmatch. Please re-import card"));
	}
	return false;
}

class keygenThread: public QThread
{
public:
	errorEx err;
	pk11_attr_data id;
	QString name;
	int size;
	pkcs11 *p11;

	keygenThread() : QThread() { };
	void run()
	{
		try {
			id = p11->generateRSAKey(name, size);
		} catch (errorEx &e) {
			err = e;
		}
       }
};

void pki_scard::generateKey_card(unsigned long slot, int size, QProgressBar *bar)
{
	pk11_attlist atts;

	pkcs11 p11;
	p11.startSession(slot, true);

	tkInfo ti = p11.tokenInfo();

	if (p11.tokenLogin(ti.label(), false).isNull())
		return;

	keygenThread kt;
	kt.name = getIntName();
	kt.size = size;
	kt.p11 = &p11;
	kt.start();
	while (!kt.wait(20)) {
		int value = bar->value();
		if (value == bar->maximum()) {
			bar->reset();
		} else {
			bar->setValue(value +1);
		}
	}
	if (!kt.err.isEmpty())
		throw errorEx(kt.err);

	atts << pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) << kt.id;
	QList<CK_OBJECT_HANDLE> objects = p11.objectList(atts);
	if (objects.count() != 1)
		printf("OBJECTS found: %d\n",objects.count());

	if (objects.count() == 0)
		throw errorEx(tr("Unable to find generated key on card"));

	load_token(p11, objects[0]);
}

pki_scard::~pki_scard()
{
}

QByteArray pki_scard::toData()
{
	QByteArray ba;

	ba += db::stringToData(card_serial);
	ba += db::stringToData(card_manufacturer);
	ba += db::stringToData(card_label);
	ba += db::stringToData(slot_label);
	ba += db::stringToData(card_model);
	ba += db::stringToData(object_id);
	ba += db::intToData(mech_list.count());
	for (int i=0; i<mech_list.count(); i++)
		ba += db::intToData(mech_list[i]);

	ba += i2d();
	return ba;
}

void pki_scard::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;

	size = head->len - sizeof(db_header_t);
        version = head->version;

	QByteArray ba((const char*)p, size);

	card_serial = db::stringFromData(ba);
	card_manufacturer = db::stringFromData(ba);
	card_label = db::stringFromData(ba);
	slot_label = db::stringFromData(ba);
	card_model = db::stringFromData(ba);
	if (version < 2)
		card_model.clear();
	object_id  = db::stringFromData(ba);
	int count      = db::intFromData(ba);
	mech_list.clear();
	for (int i=0; i<count; i++)
		mech_list << db::intFromData(ba);

	d2i(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

bool pki_scard::isPubKey() const
{
	return false;
}

QString pki_scard::getTypeString(void)
{
	return tr("Token") + " " + pki_key::getTypeString();
}

EVP_PKEY *pki_scard::decryptKey() const
{
	unsigned long slot_id;
	QString pin, key_id;
	struct {
		char *password;
		const char *prompt_info;
        } cb_data = { NULL, NULL };

	if (!prepare_card(&slot_id))
		throw errorEx(tr("Failed to find the key on the token"));

	if (!object_id.isEmpty())
		key_id = QString("%1:%2").arg(slot_id).arg(object_id);
	else
		key_id = QString("slot_%1-label_%2").arg(slot_id).arg(slot_label);

	pkcs11 p11;
	p11.startSession(slot_id);
	pin = p11.tokenLogin(card_label, false);
	if (pin.isNull())
		throw errorEx(tr("Invalid Pin for the token"));
	cb_data.password = strdup(CCHAR(pin));
	EVP_PKEY *pkey = ENGINE_load_private_key(p11_engine, CCHAR(key_id),
				NULL, &cb_data);
	free(cb_data.password);
	openssl_error();
	return pkey;
}

void pki_scard::changePin()
{
	unsigned long slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.changePin(slot, false);
}

void pki_scard::changeSoPin()
{
	unsigned long slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.changePin(slot, true);
}

void pki_scard::initPin()
{
	unsigned long slot;

	if (!prepare_card(&slot))
		return;

	pkcs11 p11;
	p11.initPin(slot);
}

int pki_scard::verify()
{
	return true;
}

bool pki_scard::isToken()
{
	return true;
}

QVariant pki_scard::getIcon(int column)
{
	return column == 0 ? QVariant(*icon[0]) : QVariant();
}

