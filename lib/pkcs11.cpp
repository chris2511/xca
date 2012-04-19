/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2011 Christian Hohnstaedt.
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

#include <openssl/rand.h>
#include <QtGui/QMessageBox>
#include <QtCore/QThread>

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
		WAITCURSOR_START;
		p11slot.p11()->C_CloseSession(session);
		WAITCURSOR_END;
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
		WAITCURSOR_START;
		rv = slot.p11()->C_CloseSession(session);
		WAITCURSOR_END;
		session = CK_INVALID_HANDLE;
		if (rv != CKR_OK)
			pk11error(slot, "C_CloseSession", rv);
	}
	WAITCURSOR_START;
	rv = slot.p11()->C_OpenSession(slot.id, flags, NULL, NULL, &session);
	WAITCURSOR_END;
        if (rv != CKR_OK)
                pk11error(slot, "C_OpenSession", rv);
	p11slot = slot;
}

QList<CK_MECHANISM_TYPE> pkcs11::mechanismList(slotid slot)
{
	CK_RV rv;
	CK_MECHANISM_TYPE *m;
	QList<CK_MECHANISM_TYPE> ml;
	unsigned long count;

	WAITCURSOR_START;
	rv = slot.p11()->C_GetMechanismList(slot.id, NULL, &count);
	WAITCURSOR_END;
	if (count != 0) {
		m = (CK_MECHANISM_TYPE *)malloc(count *sizeof(*m));
		check_oom(m);

		WAITCURSOR_START;
		rv = slot.p11()->C_GetMechanismList(slot.id, m, &count);
		WAITCURSOR_END;
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
	WAITCURSOR_START;
	rv = slot.p11()->C_GetMechanismInfo(slot.id, m, info);
	WAITCURSOR_END;
	if (rv != CKR_OK) {
		pk11error(slot, "C_GetMechanismInfo", rv);
	}
}

void pkcs11::logout()
{
	CK_RV rv;
	p11slot.isValid();
	WAITCURSOR_START;
	rv = p11slot.p11()->C_Logout(session);
	WAITCURSOR_END;
	if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
		pk11error("C_Logout", rv);
}

bool pkcs11::needsLogin(bool so)
{
	CK_SESSION_INFO sinfo;
	CK_RV rv;

	p11slot.isValid();
	WAITCURSOR_START;
	rv = p11slot.p11()->C_GetSessionInfo(session, &sinfo);
	WAITCURSOR_END;
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
	WAITCURSOR_START;
	rv = p11slot.p11()->C_Login(session, user, pin, pinlen);
	WAITCURSOR_END;
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
			QMessageBox::warning(w, XCA_TITLE,
				QString("Error: %1").arg(e.getString()));
		}
	}
	switch (slotnames.count()) {
	case 0:
		QMessageBox::warning(w, XCA_TITLE,
			QObject::tr("No Security token found"));
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
	p11slot.isValid();
	WAITCURSOR_START;
	CK_RV rv = p11slot.p11()->C_SetPIN(session, oldPin, oldPinLen, pin, pinLen);
	WAITCURSOR_END;
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
		pinp = pin.toAscii();
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
		WAITCURSOR_START;
		CK_RV rv = p11slot.p11()->C_InitPIN(session,
			pinp.constUchar(), pinp.size());
		WAITCURSOR_END;
		if (rv != CKR_OK)
			pk11error("C_InitPIN", rv);
	}
	logout();
}

void pkcs11::initToken(slotid slot, unsigned char *pin, int pinlen,
		QString label)
{
	unsigned char clabel[32];
	QByteArray ba = label.toUtf8().left(32);
	memset(clabel, ' ', 32);
	memcpy(clabel, ba.constData(), ba.size());

	WAITCURSOR_START;
	CK_RV rv = slot.p11()->C_InitToken(slot.id, pin, pinlen, clabel);
	WAITCURSOR_END;
	if (rv != CKR_OK)
		pk11error(slot, "C_InitToken", rv);
}

tkInfo pkcs11::tokenInfo(slotid slot)
{
	CK_TOKEN_INFO token_info;
	CK_RV rv;

	WAITCURSOR_START;
	rv = slot.p11()->C_GetTokenInfo(slot.id, &token_info);
	WAITCURSOR_END;
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
	WAITCURSOR_START;
	rv = p11slot.p11()->C_CreateObject(session, attrs.getAttributes(), attrs.length(), &obj);
	WAITCURSOR_END;
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
		WAITCURSOR_START;
		rv = p11slot.p11()->C_DestroyObject(session, objects[i]);
		WAITCURSOR_END;
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
		pk11_attr_bool(CKA_PRIVATE, false) <<
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

	p11slot.isValid();
	WAITCURSOR_START;
	rv = p11slot.p11()->C_GenerateKeyPair(session, &mechanism,
		pub_atts.getAttributes(), pub_atts.length(),
		priv_atts.getAttributes(), priv_atts.length(),
		&pubkey, &privkey);
	WAITCURSOR_END;
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
	WAITCURSOR_START;
	rv = p11slot.p11()->C_FindObjectsInit(session, attribute, att_num);
	WAITCURSOR_END;

	if (rv != CKR_OK)
		pk11error("C_FindObjectsInit", rv);

	do {
		WAITCURSOR_START;
		rv = p11slot.p11()->C_FindObjects(session, objects, 256, &len);
		WAITCURSOR_END;
		if (rv != CKR_OK)
			pk11error("C_FindObjects", rv);
		for (i=0; i<len; i++)
			list += objects[i];
	} while (len);

	WAITCURSOR_START;
	rv = p11slot.p11()->C_FindObjectsFinal(session);
	WAITCURSOR_END;
	if (rv != CKR_OK)
		pk11error("C_FindObjectsFinal", rv);

	return list;
}

int pkcs11::decrypt(int flen, const unsigned char *from,
				unsigned char *to, int tolen)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = CKM_RSA_PKCS;

	WAITCURSOR_START;
	rv = p11slot.p11()->C_DecryptInit(session, &mech, p11obj);
	if (rv == CKR_OK)
		rv = p11slot.p11()->C_Decrypt(session, (CK_BYTE *)from,
						flen, to, &size);
	WAITCURSOR_END;
	if (rv != CKR_OK) {
		fprintf(stderr, "Error: C_Decrypt(init): %s\n",
			pk11errorString(rv));
		return -1;
	}
	return size;
}

int pkcs11::encrypt(int flen, const unsigned char *from,
				unsigned char *to, int tolen)
{
	CK_MECHANISM mech;
	CK_ULONG size = tolen;
	CK_RV rv;

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = CKM_RSA_PKCS;

	WAITCURSOR_START;
	rv = p11slot.p11()->C_SignInit(session, &mech, p11obj);
	if (rv == CKR_OK)
		rv = p11slot.p11()->C_Sign(session, (CK_BYTE *)from,
						flen, to, &size);
	WAITCURSOR_END;
	if (rv != CKR_OK) {
		fprintf(stderr, "Error: C_Sign(init): %s\n",
			pk11errorString(rv));
		return -1;
	}
	return size;
}

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
	return priv->encrypt(flen, from, to, BN_num_bytes(rsa->n));
}

static int rsa_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA * rsa, int padding)
{
	pkcs11 *priv = (pkcs11*)RSA_get_app_data(rsa);

	if (padding != RSA_PKCS1_PADDING) {
		return -1;
	}
	return priv->decrypt(flen, from, to, flen);
}

EVP_PKEY *pkcs11::getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj)
{
	static RSA_METHOD rsa_meth, *ops = NULL;
	RSA *rsa;
	EVP_PKEY *evp;

	if (EVP_PKEY_type(pub->type) != EVP_PKEY_RSA)
		return NULL;

	p11slot.isValid();
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
}
