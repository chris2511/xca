/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertExtend.h"
#include "lib/base.h"
#include "lib/func.h"
#include "lib/asn1time.h"
#include "widgets/validity.h"
#include "widgets/MainWindow.h"
#include <qlabel.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qcheckbox.h>
#include <qmessagebox.h>


CertExtend::CertExtend(QWidget *parent, pki_x509 *s)
	:QDialog(parent)
{
	setupUi(this);
	a1time time;
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::certImg);
	validNumber->setText("1");
	validRange->setCurrentIndex(2);
	applyTimeDiff();
	signer = s;
}

void CertExtend::applyTimeDiff()
{
	applyTD(this, validNumber->text().toInt(), validRange->currentIndex(),
		midnightCB->isChecked(), notBefore, notAfter);
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
