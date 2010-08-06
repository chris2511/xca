/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportKey.h"
#include "lib/base.h"
#include "lib/func.h"

#include <QtGui/QFileDialog>
#include <QtGui/QCheckBox>
#include <QtGui/QLineEdit>
#include <QtGui/QComboBox>
#include <QtCore/QStringList>


ExportKey::ExportKey(QWidget *parent, QString fname, bool onlypub)
	:QDialog(parent)
{
	setupUi(this);
	filename->setText(fname);
	setWindowTitle(tr(XCA_TITLE));
	onlyPub = onlypub;
	exportFormat->addItem("PEM");
	exportFormat->addItem("DER");
	if (onlyPub) {
		exportPrivate->setDisabled(true);
		exportPkcs8->setDisabled(true);
		encryptKey->setDisabled(true);
	}
	else {
		exportPrivate->setChecked(true);
	}
	canEncrypt();
}

void ExportKey::on_fileBut_clicked()
{
	QString s = QFileDialog::getSaveFileName(this, tr("Save key as"),
		filename->text(),
		tr("Private keys ( *.pem *.der *.pk8 );;All files ( * )"),
		NULL, QFileDialog::DontConfirmOverwrite);

	if (!s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
}

void ExportKey::on_exportPkcs8_stateChanged()
{
	canEncrypt();
}

void ExportKey::canEncrypt()
{
	if ((exportFormat->currentText() == "DER" &&
			!exportPkcs8->isChecked()) ||
			onlyPub || !exportPrivate->isChecked())
	{
		encryptKey->setDisabled(true);
	} else {
		encryptKey->setEnabled(true);
	}
}

void ExportKey::on_exportFormat_activated(int c)
{
	QStringList suffix;
	suffix << "pem" << "der";

	filename->setText(changeFilenameSuffix(filename->text(), suffix, c));

	canEncrypt();
}

void ExportKey::on_exportPrivate_stateChanged()
{
	if (exportPrivate->isChecked()) {
		exportPkcs8->setEnabled(true);
	} else {
		exportPkcs8->setEnabled(false);
		exportPkcs8->setChecked(false);
	}
	canEncrypt();
}

void ExportKey::accept()
{
	if (mayWriteFile(filename->text()))
		QDialog::accept();
}

