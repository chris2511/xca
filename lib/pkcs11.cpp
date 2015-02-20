/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11_lib.h"
#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "func.h"
#include "pass_info.h"
#include "Passwd.h"
#include "entropy.h"

#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <QMessageBox>
#include <QThread>

#include <ltdl.h>
#include "ui_SelectToken.h"
#include "widgets/PwDialog.h"

pkcs11_lib_list pkcs11::libs;

pkcs11::pkcs11()
{
	session = CK_INVALID_HANDLE;
	p11obj = CK_INVALID_HANDLE;
}

pkcs11::~pkcs11()
{
	if (session != CK_INVALID_HANDLE && p11slot.p11()) {
		CK_RV rv;
		CALL_P11_C(p11slot.lib, C_CloseSession, session);
		(void)rv;
	}
}

pkcs11_lib *pkcs11::load_lib(QString fname, bool silent)
{
	pkcs11_lib *l;
	if (fname.isEmpty())
		return NULL;
	try {
		l = libs.add_lib(fname);
	} catch (errorEx &ex) {
		if (silent)
			return NULL;
		throw ex;
	}
	return l;
}

void pkcs11::load_libs(QString list, bool silent)
{
	QStringList errs;
	if (!list.isEmpty()) {
		foreach(QString l, list.split('\n')) {
			try {
				pkcs11::load_lib(l, silent);
			} catch (errorEx &err) {
				errs << err.getString();
			}
		}
		if (errs.count())
			throw errorEx(errs.join("\n"));
	}
}

void pkcs11::startSession(slotid slot, bool rw)
{
	CK_RV rv;
	unsigned long flags = CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0);

	if (session != CK_INVALID_HANDLE) {
		CALL_P11_C(slot.lib, C_CloseSession, session);
		session = CK_INVALID_HANDLE;
		if (rv != CKR_OK)
			pk11error(slot, "C_CloseSession", rv);
	}
	CALL_P11_C(slot.lib, C_OpenSession,
			slot.id, flags, NULL, NULL, &session);
        if (rv != CKR_OK)
                pk11error(slot, "C_OpenSession", rv);
	p11slot = slot;
}

void pkcs11::getRandom()
{
	CK_BYTE buf[64];
	CK_ULONG len = sizeof buf;
	CK_RV rv;

	if (Entropy::get(buf, len)) {
		CALL_P11_C(p11slot.lib, C_SeedRandom, session, buf, len);
	}
	CALL_P11_C(p11slot.lib, C_GenerateRandom, session, buf, len);
	if (rv == CKR_OK)
		Entropy::add_buf(buf, len);
	else
		qDebug("C_GenerateRandom: %s", pk11errorString(rv));
}

QList<CK_MECHANISM_TYPE> pkcs11::mechanismList(slotid slot)
{
	CK_RV rv;
	CK_MECHANISM_TYPE *m;
	QList<CK_MECHANISM_TYPE> ml;
	unsigned long count;

	CALL_P11_C(slot.lib, C_GetMechanismList, slot.id, NULL, &count);
	if (count != 0) {
		m = (CK_MECHANISM_TYPE *)malloc(count *sizeof(*m));
		check_oom(m);

		CALL_P11_C(slot.lib, C_GetMechanismList, slot.id, m, &count);
		if (rv != CKR_OK) {
			free(m);
			pk11error(slot, "C_GetMechanismList", rv);
		}
		for (unsigned i=0; i<count; i++) {
			ml << m[i];
		}
		free(m);
	}
	return ml;
}

void pkcs11::mechanismInfo(slotid slot, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO *info)
{
	CK_RV rv;
	CALL_P11_C(slot.lib, C_GetMechanismInfo, slot.id, m, info);
	if (rv != CKR_OK) {
		pk11error(slot, "C_GetMechanismInfo", rv);
	}
}

void pkcs11::logout()
{
	CK_RV rv;
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_Logout, session);
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
		pk11error("C_Logout", rv);
}

bool pkcs11::needsLogin(bool so)
{
	CK_SESSION_INFO sinfo;
	CK_RV rv;

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_GetSessionInfo, session, &sinfo);
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

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_Login, session, user, pin, pinlen);
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
		pk11error("C_Login", rv);
}

class pinPadLoginThread: public QThread
{
	bool so;
	pkcs11 *p11;
    public:
	errorEx err;
	pinPadLoginThread(pkcs11 *_p11, bool _so) : QThread()
	{
		so = _so;
		p11 = _p11;
	}
	void run()
	{
		try {
			p11->login(NULL, 0, so);
		} catch (errorEx &e) {
			err = e;
		}
       }
};

static QDialog *newPinPadBox()
{
	QDialog *box = new QDialog(NULL, Qt::WindowStaysOnTopHint);
	box->setWindowTitle(XCA_TITLE);
	QHBoxLayout *h = new QHBoxLayout(box);
	QLabel *l = new QLabel();
	l->setPixmap(*MainWindow::scardImg);
	l->setMaximumSize(QSize(95, 40));
	l->setScaledContents(true);
	h->addWidget(l);
	l = new QLabel(QObject::tr("Please enter the PIN on the PinPad"));
	h->addWidget(l);
	return box;
}

QString pkcs11::tokenLogin(QString name, bool so, bool force)
{
	Passwd pin;
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
		if (tokenInfo().protAuthPath()) {
			pin.clear();
			QDialog *pinpadbox = newPinPadBox();
			pinpadbox->show();
			pinPadLoginThread ppt(this, so);
			ppt.start();
			while(!ppt.wait(20)) {
				qApp->processEvents();
				pinpadbox->raise();
			}
			delete pinpadbox;
			if (!ppt.err.isEmpty())
				throw errorEx(ppt.err);
		} else {
			if (PwDialog::execute(&p, &pin, false) != 1)
				return QString();
		}
		login(pin.constUchar(), pin.size(), so);
	} else {
		return QString("");
	}
	return QString(pin);
}

bool pkcs11::selectToken(slotid *slot, QWidget *w)
{
	slotidList p11_slots = getSlotList();

	QStringList slotnames;
	foreach(slotid slot, p11_slots) {
		try {
			tkInfo info = tokenInfo(slot);
			slotnames << QString("%1 (#%2)").
				arg(info.label()).arg(info.serial());
		} catch (errorEx &e) {
			XCA_WARN(QString("Error: %1").arg(e.getString()));
		}
	}
	switch (slotnames.count()) {
	case 0:
		XCA_WARN(QObject::tr("No Security token found"));
		return false;
	case 1:
		*slot = p11_slots[0];
                return true;
	}
	Ui::SelectToken ui;
	QDialog *select_slot = new QDialog(w);
	ui.setupUi(select_slot);
	ui.image->setPixmap(*MainWindow::scardImg);
	ui.tokenBox->addItems(slotnames);
	ui.buttonBox->button(QDialogButtonBox::Ok)->setText(QObject::tr("Select"));
	if (select_slot->exec() == 0) {
		delete select_slot;
		return false;
	}
	int selected = ui.tokenBox->currentIndex();
	*slot = p11_slots[selected];
	delete select_slot;
	return true;
}

void pkcs11::setPin(unsigned char *oldPin, unsigned long oldPinLen,
	    unsigned char *pin, unsigned long pinLen)
{
	CK_RV rv;
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_SetPIN, session,
			oldPin, oldPinLen, pin, pinLen);
	if (rv != CKR_OK)
		pk11error("C_SetPIN", rv);
}

static QString newSoPinTxt = QObject::tr(
		"Please enter the new SO PIN (PUK) for the token: '%1'");
static QString newPinTxt = QObject::tr(
		"Please enter the new PIN for the token: '%1'");

void pkcs11::changePin(slotid slot, bool so)
{
	Passwd newPin, pinp;
	QString pin;

	startSession(slot, true);
	tkInfo ti = tokenInfo();

	if (ti.protAuthPath()) {
		setPin(NULL, 0, NULL, 0);
		return;
        }

	pin = tokenLogin(ti.label(), so, true);
	if (pin.isNull())
		return;

	QString msg = so ? newSoPinTxt : newPinTxt;
	pass_info p(XCA_TITLE, msg.arg(ti.label()) + "\n" + ti.pinInfo());
	p.setPin();

	if (PwDialog::execute(&p, &newPin, true) == 1) {
		pinp = pin.toLatin1();
		setPin(pinp.constUchar(), pinp.size(),
			newPin.constUchar(), newPin.size());
	}
	logout();
}

void pkcs11::initPin(slotid slot)
{
	Passwd newPin, pinp;
	int ret = 1;
	QString pin;

	startSession(slot, true);
	tkInfo ti = tokenInfo();

	pin = tokenLogin(ti.label(), true, false);
	if (pin.isNull())
		return;

	pass_info p(XCA_TITLE, newPinTxt.arg(ti.label()) + "\n" + ti.pinInfo());
	p.setPin();

	if (!ti.protAuthPath()) {
		ret = PwDialog::execute(&p, &newPin, true);
		pinp = newPin;
	}
	p11slot.isValid();
	if (ret == 1) {
		CK_RV rv;
		CALL_P11_C(p11slot.lib, C_InitPIN, session,
				pinp.constUchar(), pinp.size());
		if (rv != CKR_OK)
			pk11error("C_InitPIN", rv);
	}
	logout();
}

void pkcs11::initToken(slotid slot, unsigned char *pin, int pinlen,
		QString label)
{
	CK_RV rv;
	unsigned char clabel[32];
	QByteArray ba = label.toUtf8().left(32);
	memset(clabel, ' ', 32);
	memcpy(clabel, ba.constData(), ba.size());

	CALL_P11_C(slot.lib, C_InitToken, slot.id, pin, pinlen, clabel);
	if (rv != CKR_OK)
		pk11error(slot, "C_InitToken", rv);
}

tkInfo pkcs11::tokenInfo(slotid slot)
{
	CK_TOKEN_INFO token_info;
	CK_RV rv;

	CALL_P11_C(slot.lib, C_GetTokenInfo, slot.id, &token_info);
	if (rv != CKR_OK) {
		pk11error(slot, "C_GetTokenInfo", rv);
	}
	return tkInfo(&token_info);
}

void pkcs11::loadAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	p11slot.isValid();
	attribute.load(p11slot, session, object);
}

void pkcs11::storeAttribute(pk11_attribute &attribute, CK_OBJECT_HANDLE object)
{
	p11slot.isValid();
	attribute.store(p11slot, session, object);
}

CK_OBJECT_HANDLE pkcs11::createObject(pk11_attlist &attrs)
{
	CK_RV rv;
	CK_OBJECT_HANDLE obj;

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_CreateObject, session,
			attrs.getAttributes(), attrs.length(), &obj);
	if (rv != CKR_OK) {
		pk11error("C_CreateObject", rv);
	}
	return obj;
}

int pkcs11::deleteObjects(QList<CK_OBJECT_HANDLE> objects)
{
	CK_RV rv;

	p11slot.isValid();
	for (int i=0; i< objects.count(); i++) {
		CALL_P11_C(p11slot.lib, C_DestroyObject, session, objects[i]);
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

pk11_attr_data pkcs11::generateKey(QString name, unsigned long mech,
				unsigned long bits, int nid)
{
#ifdef OPENSSL_NO_EC
	(void)nid;
#endif
	CK_RV rv;
	CK_OBJECT_HANDLE pubkey, privkey, dsa_param_obj;
	pk11_attlist priv_atts, pub_atts, dsa_param;
	CK_MECHANISM mechanism = {mech, NULL_PTR, 0};
	pk11_attr_data label(CKA_LABEL, name.toUtf8());

	pk11_attr_data new_id = findUniqueID(CKO_PUBLIC_KEY);

        pub_atts << label << new_id <<
		pk11_attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, false) <<
		pk11_attr_bool(CKA_ENCRYPT, true) <<
		pk11_attr_bool(CKA_VERIFY, true) <<
		pk11_attr_bool(CKA_WRAP, true);

	priv_atts << label << new_id <<
		pk11_attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY) <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, true) <<
		pk11_attr_bool(CKA_SENSITIVE, true) <<
		pk11_attr_bool(CKA_DECRYPT, true) <<
		pk11_attr_bool(CKA_SIGN, true) <<
		pk11_attr_bool(CKA_UNWRAP, true);

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		pub_atts <<
		pk11_attr_ulong(CKA_MODULUS_BITS, bits) <<
		pk11_attr_data(CKA_PUBLIC_EXPONENT, 0x10001);
		break;
	case CKM_DSA_KEY_PAIR_GEN: {
		//DSA: Spec Seite 191 (175) C_GenerateKey
		CK_MECHANISM mechanism = {CKM_DSA_PARAMETER_GEN, NULL_PTR, 0};
		dsa_param << label <<
			pk11_attr_ulong(CKA_CLASS, CKO_DOMAIN_PARAMETERS) <<
			pk11_attr_ulong(CKA_KEY_TYPE, CKK_DSA) <<
			pk11_attr_bool(CKA_TOKEN, true) <<
			pk11_attr_bool(CKA_PRIVATE, false) <<
			pk11_attr_ulong(CKA_PRIME_BITS, bits);
		p11slot.isValid();
		CALL_P11_C(p11slot.lib, C_GenerateKey, session, &mechanism,
			dsa_param.getAttributes(), dsa_param.length(),
			&dsa_param_obj);
		if (rv != CKR_OK)
			pk11error("C_GenerateKey(DSA_PARAMETER)", rv);

		pk11_attr_data p(CKA_PRIME), q(CKA_SUBPRIME), g(CKA_BASE);
		loadAttribute(p, dsa_param_obj);
		loadAttribute(q, dsa_param_obj);
		loadAttribute(g, dsa_param_obj);

		pub_atts << p << q << g;
		break;
	}
#ifndef OPENSSL_NO_EC
	case CKM_EC_KEY_PAIR_GEN: {
		CK_MECHANISM_INFO info;
		mechanismInfo(p11slot, CKM_EC_KEY_PAIR_GEN, &info);

		EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);

		EC_GROUP_set_asn1_flag(group, info.flags & CKF_EC_NAMEDCURVE ?
			OPENSSL_EC_NAMED_CURVE : 0);

		// Workaround for "www.CardContact.de" bug
		if (tokenInfo().manufacturerID() == "www.CardContact.de") {
			EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
		}
		priv_atts << pk11_attr_bool(CKA_DERIVE, true);
		pub_atts  << pk11_attr_data(CKA_EC_PARAMS,
			i2d_bytearray(I2D_VOID(i2d_ECPKParameters), group));
		EC_GROUP_free(group);
		break;
	}
#endif
	default:
		throw errorEx(("Unsupported Key generation mechanism"));
	}
	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_GenerateKeyPair, session, &mechanism,
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

	p11slot.isValid();
	CALL_P11_C(p11slot.lib, C_FindObjectsInit, session, attribute, att_num);

	if (rv != CKR_OK)
		pk11error("C_FindObjectsInit", rv);

	do {
		CALL_P11_C(p11slot.lib, C_FindObjects, session,
				objects, 256, &len);
		if (rv != CKR_OK)
			pk11error("C_FindObjects", rv);
		for (i=0; i<len; i++)
			list += objects[i];
	} while (len);

	CALL_P11_C(p11slot.lib, C_FindObjectsFinal, session);
	if (rv != CKR_OK)
		pk11error("C_FindObjectsFinal", rv);

	return list;
}

int pkcs11::decrypt(int flen, const unsigned char *from,
			unsigned char *to, int tolen, unsigned long m)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = m;

	CALL_P11_C(p11slot.lib, C_DecryptInit, session, &mech, p11obj);
	if (rv == CKR_OK)
		CALL_P11_C(p11slot.lib, C_Decrypt, session,
			(CK_BYTE *)from, flen, to, &size);

	if (rv != CKR_OK) {
		fprintf(stderr, "Error: C_Decrypt(init): %s\n",
			pk11errorString(rv));
		return -1;
	}
	return size;
}

int pkcs11::encrypt(int flen, const unsigned char *from,
	unsigned char *to, int tolen, unsigned long m)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = m;

	CALL_P11_C(p11slot.lib, C_SignInit, session, &mech, p11obj);
	if (rv == CKR_OK)
		CALL_P11_C(p11slot.lib, C_Sign, session,
				(CK_BYTE *)from, flen, to, &size);

	if (rv != CKR_OK) {
		fprintf(stderr, "Error: C_Sign(init): %s\n",
			pk11errorString(rv));
		return -1;
	}
	return size;
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
static int rsa_privdata_free(RSA *rsa)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);
	delete priv;
	return 0;
}

static int rsa_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA * rsa, int padding)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);

	if (padding != RSA_PKCS1_PADDING) {
		return -1;
	}
	return priv->encrypt(flen, from, to, BN_num_bytes(rsa->n),
				CKM_RSA_PKCS);
}

static int rsa_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA * rsa, int padding)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);

	if (padding != RSA_PKCS1_PADDING) {
		return -1;
	}
	return priv->decrypt(flen, from, to, flen, CKM_RSA_PKCS);
}

EVP_PKEY *pkcs11::getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj)
{
	static RSA_METHOD rsa_meth, *ops = NULL;
	RSA *rsa;
	EVP_PKEY *evp;

	p11slot.isValid();

	switch (EVP_PKEY_type(pub->type)) {
	case EVP_PKEY_RSA:
		rsa = RSAPublicKey_dup(pub->pkey.rsa);
		openssl_error();
		if (!ops) {
			rsa_meth = *RSA_get_default_method();
			rsa_meth.rsa_priv_enc = rsa_encrypt;
			rsa_meth.rsa_priv_dec = rsa_decrypt;
			rsa_meth.finish = rsa_privdata_free;
			ops = &rsa_meth;
		}
		p11obj = obj;
		RSA_set_method(rsa, ops);
		RSA_set_app_data(rsa, this);
		evp = EVP_PKEY_new();
		openssl_error();
		EVP_PKEY_assign_RSA(evp, rsa);
		return evp;
	case EVP_PKEY_EC:
		return NULL;
	}
	return NULL;
}
#else

static int eng_idx = -1;
static EVP_PKEY_METHOD *p11_rsa_method;
static EVP_PKEY_METHOD *p11_dsa_method;
#ifndef OPENSSL_NO_EC
static EVP_PKEY_METHOD *p11_ec_method;
#endif

static int eng_finish(ENGINE *e)
{
	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(e, eng_idx);
	delete p11;
	ENGINE_set_ex_data(e, eng_idx, NULL);
	return 1;
}

static int eng_pmeth_ctrl_rsa(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	switch (type) {
	case EVP_PKEY_CTRL_RSA_PADDING:
		return p1 == RSA_PKCS1_PADDING ? 1 : -2;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_CTRL_GET_RSA_PADDING:
		*(int *)p2 = RSA_PKCS1_PADDING;
		return 1;
#endif
	case EVP_PKEY_CTRL_MD:
		EVP_PKEY_CTX_set_data(ctx, p2);
		return 1;
	case EVP_PKEY_CTRL_DIGESTINIT:
		return 1;
	}
	return -2;
}

static int eng_pmeth_ctrl_dsa(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	(void)p1;
	switch (type) {
	case EVP_PKEY_CTRL_MD:
		EVP_PKEY_CTX_set_data(ctx, NULL);
		switch (EVP_MD_type((const EVP_MD *)p2)) {
		case NID_sha1:
		case NID_sha256:
			EVP_PKEY_CTX_set_data(ctx, p2);
			return 1;
		}
		EVP_PKEY_CTX_set_data(ctx, p2);
		return 0;
	case EVP_PKEY_CTRL_DIGESTINIT:
		return 1;
	}
	return -2;
}

#ifndef OPENSSL_NO_EC
static int eng_pmeth_ctrl_ec(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	(void)p1;
	switch (type) {
	case EVP_PKEY_CTRL_MD:
		EVP_PKEY_CTX_set_data(ctx, NULL);
		switch (EVP_MD_type((const EVP_MD *)p2)) {
		case NID_ecdsa_with_SHA1:
			fprintf(stderr, "%s: NID_ecdsa_with_SHA1 unexpected\n",
				__func__);
		case NID_sha1:
		case NID_sha224:
		case NID_sha256:
		case NID_sha384:
		case NID_sha512:
			EVP_PKEY_CTX_set_data(ctx, p2);
			return 1;
		}
		return 0;
	case EVP_PKEY_CTRL_DIGESTINIT:
		return 1;
	}
	fprintf(stderr, "EC Don't call me %d\n", type);
	return -2;
}
#endif

static unsigned char *create_x509_sig(EVP_PKEY_CTX *ctx, const unsigned char *m,
		size_t m_len, unsigned int *x509_siglen)
{
	X509_SIG sig;
	ASN1_TYPE parameter;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	EVP_MD *md = (EVP_MD *)EVP_PKEY_CTX_get_data(ctx);
	int i;
	unsigned char *p, *tmps;

	*x509_siglen = 0;

	sig.algor = &algor;
	sig.algor->algorithm = OBJ_nid2obj(EVP_MD_type(md));
	if (!sig.algor->algorithm)
		return NULL;
	if (sig.algor->algorithm->length == 0)
		return NULL;

	parameter.type=V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter= &parameter;

	sig.digest = &digest;
	sig.digest->data = (unsigned char *)m;
	sig.digest->length = (unsigned int)m_len;

	i = i2d_X509_SIG(&sig, NULL);
	if (i <= 0)
		return NULL;
	p = tmps = (unsigned char *)malloc(i);
	check_oom(tmps);
	if (i2d_X509_SIG(&sig, &p) <= 0) {
		free(tmps);
		return NULL;
	}
	*x509_siglen = i;
	return tmps;
}

static int eng_pmeth_sign_rsa(EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	unsigned int x509_len;
	unsigned char *sigbuf;
	int len;

	sigbuf = create_x509_sig(ctx, tbs, tbslen, &x509_len);
	pkey = EVP_PKEY_CTX_get0_pkey(ctx);

	if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA)
		return -1;

	if ((int)x509_len > (RSA_size(pkey->pkey.rsa) - RSA_PKCS1_PADDING_SIZE))
		return -1;

	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(pkey->engine, eng_idx);

	// siglen is unsigned and can't cope with -1 as return value
	len = p11->encrypt(x509_len, sigbuf, sig, *siglen, CKM_RSA_PKCS);
	*siglen = len;
	free(sigbuf);
	return (len < 0) ? -1 : 1;
}

static int eng_pmeth_sign_dsa(EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	int len, rs_len, ret = -1;
	unsigned char rs_buf[128];
	DSA_SIG *dsa_sig = DSA_SIG_new();

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);

	if (EVP_PKEY_type(pkey->type) != EVP_PKEY_DSA)
		return -1;

	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(pkey->engine, eng_idx);

	// siglen is unsigned and can't cope with -1 as return value
	len = p11->encrypt(tbslen, tbs, rs_buf, sizeof rs_buf, CKM_DSA);
	if (len & 0x01) // Must be even
		goto out;

	rs_len = len/2;
	dsa_sig->r = BN_bin2bn(rs_buf, rs_len, NULL);
	dsa_sig->s = BN_bin2bn(rs_buf + rs_len, rs_len, NULL);
	if (!dsa_sig->s || !dsa_sig->r)
		goto out;

	len = i2d_DSA_SIG(dsa_sig, &sig);
	openssl_error();
	if (len <= 0)
		goto out;
	*siglen = len;
	ret = 1;
out:
	DSA_SIG_free(dsa_sig);
	ign_openssl_error();
	return ret;
}

#ifndef OPENSSL_NO_EC
static int eng_pmeth_sign_ec(EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen)
{
	int len, rs_len, ret = -1;
	unsigned char rs_buf[512];
	ECDSA_SIG *ec_sig = ECDSA_SIG_new();

	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	pkcs11 *p11 = (pkcs11 *)ENGINE_get_ex_data(pkey->engine, eng_idx);

	// siglen is unsigned and can' cope with -1 as return value
	len = p11->encrypt(tbslen, tbs, rs_buf, sizeof rs_buf, CKM_ECDSA);
	if (len & 0x01) // Must be even
		goto out;
	/* The buffer contains r and s concatenated
	 * Both of equal size
	 * pkcs-11v2-20.pdf chapter 12.13.1, page 232
	 */
	rs_len = len/2;
	if (!BN_bin2bn(rs_buf, rs_len, ec_sig->r))
		goto out;
	if (!BN_bin2bn(rs_buf + rs_len, rs_len, ec_sig->s))
		goto out;
	len = i2d_ECDSA_SIG(ec_sig, &sig);
	if (len <= 0)
		goto out;
	*siglen = len;
	ret = 1;
out:
	ECDSA_SIG_free(ec_sig);
	ign_openssl_error();
	return ret;
}
#endif

static int eng_pmeth_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	void *p = EVP_PKEY_CTX_get_app_data(src);
	EVP_PKEY_CTX_set_app_data(dst,  p);
	return 1;
}

static int eng_meths(ENGINE *e, EVP_PKEY_METHOD **m, const int **nids, int nid)
{
	static const int my_nids[] = { EVP_PKEY_EC, EVP_PKEY_RSA };
	(void)e;
	if (m) {
		switch (nid) {
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			*m = p11_ec_method;
			return 1;
#endif
		case EVP_PKEY_RSA:
			*m = p11_rsa_method;
			return 1;
		case EVP_PKEY_DSA:
			*m = p11_dsa_method;
			return 1;
		}
		return 0;
	}
	if (nids) {
		*nids = my_nids;
		return ARRAY_SIZE(my_nids);
	}
	return -1;
}

EVP_PKEY *pkcs11::getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj)
{
	static ENGINE *e = NULL;

	if (!e) {
		e = ENGINE_new();
		check_oom(e);

		ENGINE_set_pkey_meths(e, eng_meths);
		ENGINE_set_finish_function(e, eng_finish);
		if (eng_idx == -1)
			eng_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
		ENGINE_set_ex_data(e, eng_idx, NULL);

		CRYPTO_add(&pub->references, 1, CRYPTO_LOCK_EVP_PKEY);
		pub->engine = e;

		if (!p11_rsa_method) {
			p11_rsa_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
			EVP_PKEY_meth_set_sign(p11_rsa_method,
					NULL, eng_pmeth_sign_rsa);
			EVP_PKEY_meth_set_ctrl(p11_rsa_method,
					eng_pmeth_ctrl_rsa, NULL);
			EVP_PKEY_meth_set_copy(p11_rsa_method, eng_pmeth_copy);
		}
		if (!p11_dsa_method) {
			p11_dsa_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, 0);
			EVP_PKEY_meth_set_sign(p11_dsa_method,
					NULL, eng_pmeth_sign_dsa);
			EVP_PKEY_meth_set_ctrl(p11_dsa_method,
					eng_pmeth_ctrl_dsa, NULL);
			EVP_PKEY_meth_set_copy(p11_dsa_method, eng_pmeth_copy);
		}
#ifndef OPENSSL_NO_EC
		if (!p11_ec_method) {
			p11_ec_method = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
			EVP_PKEY_meth_set_sign(p11_ec_method,
					 NULL, eng_pmeth_sign_ec);
			EVP_PKEY_meth_set_ctrl(p11_ec_method,
					eng_pmeth_ctrl_ec, NULL);
			EVP_PKEY_meth_set_copy(p11_ec_method, eng_pmeth_copy);
		}
#endif
	}
	if (ENGINE_get_ex_data(e, eng_idx))
		fprintf(stderr, "Christian forgot to free the previous Card key. Blame him");

	ENGINE_set_ex_data(e, eng_idx, this);
	p11obj = obj;

	switch (EVP_PKEY_type(pub->type)) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_DSA:
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
#endif
		/* The private key is a copy of the public
		 * key with an engine attached
		 */
		QByteArray ba = i2d_bytearray(I2D_VOID(i2d_PUBKEY), pub);
		EVP_PKEY *priv = (EVP_PKEY*)d2i_bytearray(D2I_VOID(d2i_PUBKEY), ba);
		ENGINE_init(e);
		priv->engine = e;
		return priv;
	}
	return NULL;
}

#endif
