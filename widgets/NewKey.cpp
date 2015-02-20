/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewKey.h"
#include "MainWindow.h"
#include "lib/pki_evp.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include "lib/pkcs11.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QStringList>

struct typelist {
	const char *name;
	int type;
};

static const struct typelist typeList[] = {
	{ "RSA", EVP_PKEY_RSA },
	{ "DSA", EVP_PKEY_DSA },
#ifndef OPENSSL_NO_EC
	{ "EC",  EVP_PKEY_EC  },
#endif
};

int NewKey::defaultType = EVP_PKEY_RSA;
int NewKey::defaultEcNid = NID_undef;
int NewKey::defaultSize = 2048;

class keyListItem
{
    protected:
	const struct typelist *tl;

    public:
	bool card;
	QString printname;
	slotid slot;
	unsigned minKeySize;
	unsigned maxKeySize;
	unsigned long ec_flags;

	keyListItem(pkcs11 *p11, slotid nslot, CK_MECHANISM_TYPE m)
	{
		slot = nslot;
		CK_MECHANISM_INFO mechinfo;
		p11->mechanismInfo(slot, m, &mechinfo);

		minKeySize = mechinfo.ulMinKeySize;
		maxKeySize = mechinfo.ulMaxKeySize;
		if (maxKeySize == 0) {
			/* Fallback for libraries not filling in the maxKeySize */
			maxKeySize = INT_MAX;
		}
		tkInfo ti = p11->tokenInfo(slot);
		switch (m) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			tl = typeList; //idx of EVP_PKEY_RSA
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			tl = typeList +1;
			break;
#ifndef OPENSSL_NO_EC
		case CKM_EC_KEY_PAIR_GEN:
			tl = typeList +2;
			CK_MECHANISM_INFO info;
			p11->mechanismInfo(slot, m, &info);
			ec_flags = info.flags & (CKF_EC_F_P | CKF_EC_F_2M);
			if (!ec_flags) {
				/* Fallback: Assume to support both for
				 * libraries leaving this flag empty
				 */
				ec_flags = CKF_EC_F_P | CKF_EC_F_2M;
			}
#endif
		}
		printname = QString("%1 #%2 (%3 Key of %4 - %5 bits)").
			arg(ti.label()).arg(ti.serial()).
			arg(tl->name).
			arg(minKeySize).
			arg(maxKeySize);
		card = true;
	}
	keyListItem(const struct typelist *t=typeList)
	{
		tl = t;
		printname = QString(tl->name);
		card = false;
		slot = slotid();
		minKeySize = 0;
		maxKeySize = INT_MAX;
		ec_flags = 0;
	}
	keyListItem(const keyListItem &k)
	{
		tl = k.tl;
		printname = k.printname;
		card = k.card;
		slot = k.slot;
		minKeySize = k.minKeySize;
		maxKeySize = k.maxKeySize;
		ec_flags = k.ec_flags;
	}
	int type()
	{
		return tl->type;
	}
	QString typeName()
	{
		return QString(tl->name);
	}
};

Q_DECLARE_METATYPE(keyListItem);

NewKey::NewKey(QWidget *parent, QString name)
	:QDialog(parent)
{
	static const char* const sizeList[] = { "1024", "2048", "4096" };
	size_t i;
	slotidList p11_slots;
	QList<keyListItem> keytypes;

	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::keyImg);

	if (!name.isEmpty())
		keyDesc->setText(name);

	keyLength->setEditable(true);
	for (i=0; i < ARRAY_SIZE(sizeList); i++ ) {
		keyLength->addItem(QString(sizeList[i]) + " bit");
	}
	for (i=0; i < ARRAY_SIZE(typeList); i++ ) {
		keyListItem gk(typeList +i);
		keytypes << gk;
	}
	updateCurves();
	keyLength->setEditText(QString::number(defaultSize) + " bit");
	keyDesc->setFocus();
	if (pkcs11::loaded()) try {
		pkcs11 p11;
		p11_slots = p11.getSlotList();

		foreach(slotid slot, p11_slots) {
			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
			if (ml.contains(CKM_RSA_PKCS_KEY_PAIR_GEN)) {
				keyListItem tk(&p11, slot, CKM_RSA_PKCS_KEY_PAIR_GEN);
				keytypes << tk;
			}
			if (ml.contains(CKM_DSA_KEY_PAIR_GEN)) {
				keyListItem tk(&p11, slot, CKM_DSA_KEY_PAIR_GEN);
				keytypes << tk;
			}
#ifndef OPENSSL_NO_EC
			if (ml.contains(CKM_EC_KEY_PAIR_GEN)) {
				keyListItem tk(&p11, slot, CKM_EC_KEY_PAIR_GEN);
				keytypes << tk;
			}
#endif
		}
	} catch (errorEx &err) {
		p11_slots.clear();
	}
	for (int i=0; i<keytypes.count(); i++) {
		QVariant q;
		q.setValue(keytypes[i]);
		keyType->addItem(keytypes[i].printname, q);
		if (!keytypes[i].card && keytypes[i].type() == defaultType)
			keyType->setCurrentIndex(i);
	}
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
}

void NewKey::updateCurves(unsigned min, unsigned max, unsigned long ec_flags)
{
#ifndef OPENSSL_NO_EC
	QString ec_default;
	QStringList curve_x962, curve_other;
	foreach(builtin_curve curve, pki_key::builtinCurves) {
		const char *sn = OBJ_nid2sn(curve.nid);
		QString comment = curve.comment;

		if (!sn || curve.order_size < min || curve.order_size > max)
			continue;
		if (ec_flags) {
			if ((curve.type & ec_flags) == 0)
				continue;
		}
		if (comment.isEmpty())
			comment = "---";
		QString p = QString(sn) + ": " + comment;
		if (curve.nid == defaultEcNid)
			ec_default = p;
		switch (curve.flags) {
			case CURVE_X962:  curve_x962  << p; break;
			case CURVE_OTHER: curve_other << p; break;
		}
	}
	curveBox->clear();
	curveBox->addItems(curve_x962);
	curveBox->addItems(curve_other);
	curveBox->setCurrentIndex(curveBox->findText(ec_default));
	if (curveBox->currentIndex() == -1)
		curveBox->setCurrentIndex(0);
#else
	(void)min; (void)max; (void)ec_flags;
#endif
}

void NewKey::on_keyType_currentIndexChanged(int idx)
{
	bool curve_enabled;
	keyListItem ki = keyType->itemData(idx).value<keyListItem>();

	curve_enabled = (ki.type() == EVP_PKEY_EC);
	curveBox->setVisible(curve_enabled);
	curveLabel->setVisible(curve_enabled);
	keySizeLabel->setVisible(!curve_enabled);
	keyLength->setVisible(!curve_enabled);

	rememberDefault->setEnabled(!ki.card);
	if (curve_enabled && ki.card) {
		updateCurves(ki.minKeySize, ki.maxKeySize, ki.ec_flags);
	}
}

static keyListItem currentKey(QComboBox *keyType)
{
	QVariant q = keyType->itemData(keyType->currentIndex());
	return q.value<keyListItem>();
}

int NewKey::getKeytype()
{
	return currentKey(keyType).type();
}

int NewKey::getKeysize()
{
	if (getKeytype() == EVP_PKEY_EC)
		return -1;
	QString size = keyLength->currentText();
	size.replace(QRegExp("[^0-9]"), "");
	return size.toInt();
}

int NewKey::getKeyCurve_nid()
{
	if (getKeytype() != EVP_PKEY_EC)
		return NID_undef;
	QString desc = curveBox->currentText();
	desc.replace(QRegExp("^(X9.62) "), "");
	desc.replace(QRegExp(":.*"), "");
	return OBJ_sn2nid(CCHAR(desc));
}

bool NewKey::isToken()
{
	keyListItem k = currentKey(keyType);
	return k.card;
}

slotid NewKey::getKeyCardSlot()
{
	keyListItem k = currentKey(keyType);
	return k.slot;
}

QString NewKey::getAsString()
{
	keyListItem k = currentKey(keyType);
	QString data;

	if (k.card)
		return QString();
	if (k.type() == EVP_PKEY_EC) {
		data = OBJ_obj2QString(OBJ_nid2obj(getKeyCurve_nid()), 1);
	} else {
		data = QString::number(getKeysize());
	}
	return QString("%1:%2").arg(currentKey(keyType).typeName()).arg(data);
}

int NewKey::setDefault(QString def)
{
	int type = -1, size = 0, nid = NID_undef;
	QStringList sl = def.split(':');

	if (sl.size() != 2)
		return -1;
	for (unsigned i=0; i < ARRAY_SIZE(typeList); i++ ) {
		if (sl[0] == typeList[i].name) {
			type = typeList[i].type;
		}
	}
	if (type == -1)
		return -2;
	if (type == EVP_PKEY_EC) {
		nid = OBJ_txt2nid(sl[1].toLatin1());
		if (nid == NID_undef)
			return -3;
		defaultEcNid = nid;
	} else {
		size = sl[1].toInt();
		if (size <= 0)
			return -4;
		defaultSize = size;
	}
	defaultType = type;
	return 0;
}
