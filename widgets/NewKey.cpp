/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewKey.h"
#include "MainWindow.h"
#include "Help.h"
#include "lib/pki_evp.h"
#include "lib/pkcs11.h"
#include "distname.h"
#include "clicklabel.h"
#include "ItemCombo.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QStringList>

keyjob NewKey::defaultjob;

class keyListItem
{
    public:
	bool card;
	keytype ktype;
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
			/* Fallback for libraries not
			 * filling in the maxKeySize */
			maxKeySize = INT_MAX;
		}
		ktype = keytype::byMech(m);
		tkInfo ti = p11->tokenInfo(slot);
#ifndef OPENSSL_NO_EC
		if (m == CKM_EC_KEY_PAIR_GEN) {
			CK_MECHANISM_INFO info;
			p11->mechanismInfo(slot, m, &info);
			ec_flags = info.flags & (CKF_EC_F_P | CKF_EC_F_2M);
			if (!ec_flags) {
				/* Fallback: Assume to support both for
				 * libraries leaving this flag empty
				 */
				ec_flags = CKF_EC_F_P | CKF_EC_F_2M;
			}
		}
#endif
		printname = QString("%1 #%2 (%3 Key of %4 - %5 bits)").
			arg(ti.label()).arg(ti.serial()).
			arg(ktype.name).
			arg(minKeySize).
			arg(maxKeySize);
		card = true;
	}
	keyListItem(const keytype &t = keytype())
		: ktype(t)
	{
		printname = ktype.name;
		card = false;
		slot = slotid();
		minKeySize = 0;
		maxKeySize = INT_MAX;
		ec_flags = 0;
	}
	int type() const
	{
		return ktype.type;
	}
};

Q_DECLARE_METATYPE(keyListItem);

NewKey::NewKey(QWidget *parent, const QString &name)
	:QDialog(parent ?: mainwin)
{
	static const QList<int> sizeList = { 1024, 2048, 4096, 8192 };
	slotidList p11_slots;
	QList<keyListItem> keytypes;

	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":keyImg"));
	mainwin->helpdlg->register_ctxhelp_button(this, "keygen");

	if (!name.isEmpty())
		keyDesc->setText(name);

	keyLength->setEditable(true);
	foreach (int size, sizeList)
		keyLength->addItem(QString("%1 bit").arg(size));

	foreach (const keytype t, keytype::types())
		keytypes << keyListItem(t);

	updateCurves();
	keyLength->setEditText(QString("%1 bit").arg(defaultjob.size));
	keyDesc->setFocus();
	if (pkcs11::libraries.loaded()) try {
		pkcs11 p11;
		p11_slots = p11.getSlotList();

		foreach(slotid slot, p11_slots) {
			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
			foreach(keytype t, keytype::types())
				if (ml.contains(t.mech))
					keytypes << keyListItem(&p11, slot,
								t.type);
		}
	} catch (errorEx &err) {
		p11_slots.clear();
	}
	for (int i=0; i<keytypes.count(); i++) {
		QVariant q;
		q.setValue(keytypes[i]);
		keyType->addItem(keytypes[i].printname, q);
		if (!keytypes[i].card &&
		    keytypes[i].type() == defaultjob.ktype.type)
		{
			keyType->setCurrentIndex(i);
		}
	}
	buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Create"));
}

void NewKey::addCurveBoxCurves(const QList<builtin_curve> &curves)
{
	foreach(builtin_curve curve, curves) {
		QString sn(OBJ_nid2sn(curve.nid));
		QString p, comment = curve.comment;

		if (comment.isEmpty())
			comment = "---";
		p = sn + ": " + comment;
		curveBox->addItem(sn + ": " + comment, curve.nid);
	}
}

void NewKey::updateCurves(unsigned min, unsigned max, unsigned long ec_flags)
{
#ifndef OPENSSL_NO_EC
	QList<builtin_curve> curve_rfc5480, curve_x962, curve_other;

	foreach(builtin_curve curve, builtinCurves) {
		const char *sn = OBJ_nid2sn(curve.nid);

		if (!sn || curve.order_size < min || curve.order_size > max)
			continue;
		if (ec_flags && (curve.type & ec_flags) == 0)
			continue;
		switch (curve.flags) {
			case CURVE_RFC5480: curve_rfc5480  << curve; break;
			case CURVE_X962:    curve_x962     << curve; break;
			case CURVE_OTHER:   curve_other    << curve; break;
		}
	}
	curveBox->clear();
	addCurveBoxCurves(curve_rfc5480);
	curveBox->insertSeparator(curveBox->count());
	addCurveBoxCurves(curve_x962);
	curveBox->insertSeparator(curveBox->count());
	addCurveBoxCurves(curve_other);

	int default_index = curveBox->findData(QVariant(defaultjob.ec_nid));
	curveBox->setCurrentIndex(default_index == -1 ? 0 : default_index);
#else
	(void)min; (void)max; (void)ec_flags;
#endif
}

void NewKey::on_keyType_currentIndexChanged(int idx)
{
	keyListItem ki = keyType->itemData(idx).value<keyListItem>();

	curveBox->setVisible(ki.ktype.curve);
	curveLabel->setVisible(ki.ktype.curve);
	keySizeLabel->setVisible(ki.ktype.length);
	keyLength->setVisible(ki.ktype.length);

	rememberDefault->setEnabled(!ki.card);
	if (ki.ktype.curve && ki.card) {
		updateCurves(ki.minKeySize, ki.maxKeySize, ki.ec_flags);
	}
}

keyjob NewKey::getKeyJob() const
{
	keyjob job;
	keyListItem selected = keyType->itemData(keyType->currentIndex())
						.value<keyListItem>();
	job.ktype = selected.ktype;
	if (job.isEC()) {
		int idx = curveBox->currentIndex();
		job.ec_nid = curveBox->itemData(idx).toInt();
	} else {
		QString size = keyLength->currentText();
		size.replace(QRegExp("[^0-9]"), "");
		job.size = size.toInt();
	}
	job.slot = selected.slot;
	return job;
}

void NewKey::accept()
{
	if (rememberDefault->isChecked()) {
		defaultjob = getKeyJob();
		Settings["defaultkey"] = defaultjob.toString();
	}
	QDialog::accept();
}
