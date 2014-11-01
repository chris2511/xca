/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportKey.h"
#include "MainWindow.h"
#include "lib/base.h"

#include <QtGui/QCheckBox>
#include <QtGui/QComboBox>
#include <QtCore/QStringList>

ExportKey::ExportKey(QWidget *parent, QString fname, pki_key *key)
	:ExportDialog(parent, fname, key)
{
	onlyPub = key->isPubKey() || key->isToken();
	QString lbl;

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

	if (key->isToken())
		image->setPixmap(*MainWindow::scardImg);
        else
		image->setPixmap(*MainWindow::keyImg);

	if (key->isToken() || key->isPubKey()) {
		lbl = tr("Export public %1 key");
		extraFrame->hide();
	} else {
		lbl = tr("Export %1 key");
		exportPrivate->setChecked(true);
		connect(exportPkcs8, SIGNAL(stateChanged(int)),
			this, SLOT(canEncrypt()));
		connect(exportPrivate, SIGNAL(stateChanged(int)),
			this, SLOT(canEncrypt()));
		connect(exportFormat, SIGNAL(currentIndexChanged(int)),
			this, SLOT(canEncrypt()));
		canEncrypt();
	}
	label->setText(lbl.arg(key->getTypeString()));
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
