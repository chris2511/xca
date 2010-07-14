/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertExtend.h"
#include "lib/base.h"
#include "lib/func.h"
#include "widgets/validity.h"
#include "widgets/MainWindow.h"
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QComboBox>
#include <QtGui/QCheckBox>
#include <QtGui/QMessageBox>


CertExtend::CertExtend(QWidget *parent, pki_x509 *s)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::certImg);
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

void CertExtend::accept()
{
	if (notBefore->getDate() < signer->getNotBefore()) {
		QString text = tr("The certificate will be earlier valid than the signer. This is probably not what you want.");
		QMessageBox msg(QMessageBox::Warning, XCA_TITLE,
					text, QMessageBox::NoButton, this);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit times"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes)->setText(tr("Adjust date and continue"));
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
	if (notAfter->getDate() > signer->getNotAfter() &&
				!noWellDefinedExpDate->isChecked()) {
		QString text = tr("The certificate will be longer valid than the signer. This is probably not what you want.");
		QMessageBox msg(QMessageBox::Warning, XCA_TITLE,
					text, QMessageBox::NoButton, this);
		msg.addButton(QMessageBox::Ok)->setText(tr("Edit times"));
		msg.addButton(QMessageBox::Close)->setText(tr("Abort rollout"));
		msg.addButton(QMessageBox::Apply)->setText(tr("Continue rollout"));
		msg.addButton(QMessageBox::Yes)->setText(tr("Adjust date and continue"));
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
