/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportKey.h"
#include "lib/base.h"

#include <QtGui/QCheckBox>
#include <QtGui/QComboBox>
#include <QtCore/QStringList>

ExportKey::ExportKey(QWidget *parent, QString fname, bool onlypub)
	:ExportDialog(parent, fname)
{
	onlyPub = onlypub;

	QStringList sl; sl << "PEM" << "DER";
	exportFormat->addItems(sl);
	suffixes << "pem" << "der";

        filter = tr("Private keys ( *.pem *.der *.pk8 );;All files ( * )");

	formatLabel->setText(tr(
		"DER is a binary format of the key without encryption\n"
		"PEM is a base64 encoded key with optional encryption\n"
		"PKCS#8 is an encrypted official Key-exchange format"));

	filenameLabel->setText(tr(
		"Please enter the filename for the key."));

	Ui::ExportKey::setupUi(extraFrame);
	if (onlyPub) {
		label->setText(tr("Public key export"));
		extraFrame->hide();
	} else {
		label->setText(tr("Key export"));
		exportPrivate->setChecked(true);
		connect(exportPkcs8, SIGNAL(stateChanged(int)),
			this, SLOT(canEncrypt()));
		connect(exportPrivate, SIGNAL(stateChanged(int)),
			this, SLOT(canEncrypt()));
		connect(exportFormat, SIGNAL(currentIndexChanged(int)),
			this, SLOT(canEncrypt()));
		canEncrypt();
	}
}

void ExportKey::canEncrypt()
{
	if (exportPrivate->isChecked()) {
		exportPkcs8->setEnabled(true);
	} else {
		exportPkcs8->setEnabled(false);
		exportPkcs8->setChecked(false);
	}
	if ((exportFormat->currentText() == "PEM" &&
		exportPrivate->isChecked()) ||
	    (exportPkcs8->isEnabled() && exportPkcs8->isChecked()))
	{
		encryptKey->setEnabled(true);
	} else {
		encryptKey->setDisabled(true);
	}
}
