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
	if (key->getKeyType() == EVP_PKEY_RSA ||
	    key->getKeyType() == EVP_PKEY_DSA)
		sl << "SSH2 Public Key";
	exportFormat->addItems(sl);
	suffixes << "pem" << "der" << "pub";

        filter = tr("Private Keys ( *.pem *.der *.pk8 );; SSH Public Keys ( *.pub );; All files ( * )");

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

	if (onlyPub) {
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
	if (exportFormat->currentIndex() == 2) {
		extraFrame->setDisabled(true);
		return;
	} else {
		extraFrame->setEnabled(true);
	}
	if (exportPrivate->isChecked()) {
		exportPkcs8->setEnabled(true);
	} else {
		exportPkcs8->setEnabled(false);
		exportPkcs8->setChecked(false);
	}
	if ((exportFormat->currentIndex() == 0 &&
		exportPrivate->isChecked()) ||
	    (exportPkcs8->isEnabled() && exportPkcs8->isChecked()))
	{
		encryptKey->setEnabled(true);
	} else {
		encryptKey->setDisabled(true);
	}
}
