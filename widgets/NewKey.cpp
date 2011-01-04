/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewKey.h"
#include "MainWindow.h"
#include "lib/pki_evp.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include "lib/pkcs11.h"
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QLineEdit>

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

class keyListItem
{
    protected:
	const struct typelist *tl;

    public:
	bool card;
	QString printname;
	slotid slot;
	keyListItem(pkcs11 *p11, slotid nslot, CK_MECHANISM_TYPE m)
	{
		// assert(m == CKM_RSA_PKCS_KEY_PAIR_GEN);
		slot = nslot;
		CK_MECHANISM_INFO mechinfo;
		p11->mechanismInfo(slot, m, &mechinfo);
		tkInfo ti = p11->tokenInfo(slot);
		tl = typeList; //idx of EVP_PKEY_RSA
		printname = QString("%1 #%2 (%3 Key of %4 - %5 bits)").
			arg(ti.label()).arg(ti.serial()).
			arg(tl->name).
			arg(mechinfo.ulMinKeySize).
			arg(mechinfo.ulMaxKeySize);
		card = true;
	}
	keyListItem(const struct typelist *t=typeList)
	{
		tl = t;
		printname = QString(tl->name);
		card = false;
		slot = slotid();
	}
	keyListItem(const keyListItem &k)
	{
		tl = k.tl;
		printname = k.printname;
		card = k.card;
		slot = k.slot;
	}
	int type()
	{
		return tl->type;
	}
};

Q_DECLARE_METATYPE(keyListItem);

NewKey::NewKey(QWidget *parent, QString name)
	:QDialog(parent)
{
	static const char* const sizeList[] = { "1024", "2048", "4096" };
	size_t i;
	QStringList curve_x962, curve_other;
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
#ifndef OPENSSL_NO_EC
	for (i = 0; i<pki_evp::num_curves; i++) {
		const char *desc = pki_evp::curves[i].comment;
		const char *sn = OBJ_nid2sn(pki_evp::curves[i].nid);

		if (!sn)
			continue;
		if (desc == NULL)
			desc = "---";
		QString p = QString(sn) + ": " + desc;
		switch (pki_evp::curve_flags[i]) {
			case CURVE_X962:  curve_x962  << p; break;
			case CURVE_OTHER: curve_other << p; break;
		}

	}
	curveBox->addItems(curve_x962);
	curveBox->addItems(curve_other);
#endif
	keyLength->setCurrentIndex(0);
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
		}
	} catch (errorEx &err) {
		p11_slots.clear();
	}
	for (int i=0; i<keytypes.count(); i++) {
		QVariant q;
		q.setValue(keytypes[i]);
		keyType->addItem(keytypes[i].printname, q);
	}
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
}

void NewKey::on_keyType_currentIndexChanged(int idx)
{
	bool curve_enabled;

	curve_enabled = (typeList[idx].type == EVP_PKEY_EC);
	curveBox->setVisible(curve_enabled);
	curveLabel->setVisible(curve_enabled);
	keySizeLabel->setVisible(!curve_enabled);
	keyLength->setVisible(!curve_enabled);
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
		return -1;
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
