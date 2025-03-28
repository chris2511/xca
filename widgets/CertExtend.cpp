/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertExtend.h"
#include "lib/base.h"
#include "lib/func.h"
#include "widgets/validity.h"
#include "widgets/XcaWarning.h"
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QMessageBox>


CertExtend::CertExtend(QWidget *parent, pki_x509 *s)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(QPixmap(":certImg"));
	validNumber->setText("1");
	validRange->setCurrentIndex(2);
	on_applyTime_clicked();
	signer = s;
	notAfter->setEndDate(true);
}

void CertExtend::on_applyTime_clicked()
{
	notAfter->setDiff(notBefore, validNumber->text().toInt(),
				     validRange->currentIndex());
}

void CertExtend::on_keepSerial_toggled(bool checked)
{
	if (checked) {
		old_revoke = revoke->isChecked();
		revoke->setEnabled(false);
		revoke->setChecked(false);

		old_replace = replace->isChecked();
		replace->setEnabled(false);
		replace->setChecked(true);
	} else {
		revoke->setEnabled(true);
		revoke->setChecked(old_revoke);

		replace->setEnabled(true);
		replace->setChecked(old_replace);
	}
}

void CertExtend::accept()
{
	if (signer && notBefore->getDate() < signer->getNotBefore()) {
		QString text = tr("The certificate will be earlier valid than the signer. This is probably not what you want.");
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notBefore->setDate(signer->getNotBefore());
		}
	}
	if (signer && notAfter->getDate() > signer->getNotAfter() &&
				!noWellDefinedExpDate->isChecked()) {
		QString text = tr("The certificate will be longer valid than the signer. This is probably not what you want.");
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok, tr("Edit dates"));
		msg.addButton(QMessageBox::Close, tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply, tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes, tr("Adjust date and continue"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
			case QMessageBox::Cancel:
				return;
			case QMessageBox::Close:
				reject();
				return;
			case QMessageBox::Apply:
				break;
			case QMessageBox::Yes:
				notAfter->setDate(signer->getNotAfter());
		}
	}
	QDialog::accept();
}
