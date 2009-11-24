/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewKey.h"
#include "MainWindow.h"
#include "lib/pki_evp.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlineedit.h>

struct typelist {
	const char *name;
	int type;
};

static const struct typelist typeList[] = {
	{ "RSA", EVP_PKEY_RSA },
	{ "DSA", EVP_PKEY_DSA },
	{ "EC",  EVP_PKEY_EC  },
};

NewKey::NewKey(QWidget *parent, QString name)
	:QDialog(parent)
{
	static const char* const sizeList[] = { "1024", "2048", "4096" };
	size_t i;
	QStringList curve_x962, curve_other;

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
		keyType->addItem(QString(typeList[i].name));
	}

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
	keyLength->setCurrentIndex(0);
	keyDesc->setFocus();
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

int NewKey::getKeytype()
{
	return typeList[keyType->currentIndex()].type;
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

