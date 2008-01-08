/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportKey.h"
#include "lib/base.h"

#include <qfiledialog.h>
#include <qcheckbox.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qfiledialog.h>

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
		tr("Private keys ( *.pem *.der *.pk8 );;All files ( * )"));
	if (! s.isEmpty()) {
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
	const char *suffix[] = { "pem", "der" };

	QString fn = filename->text();
	QString nfn = fn.left(fn.lastIndexOf('.')+1) + suffix[c];
	filename->setText(nfn);
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
