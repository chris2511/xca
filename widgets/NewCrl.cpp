/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "NewCrl.h"
#include "lib/base.h"
#include "lib/func.h"
#include "widgets/validity.h"
#include "widgets/MainWindow.h"
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QComboBox>
#include <QtGui/QCheckBox>
#include <QtGui/QMessageBox>

NewCrl::NewCrl(QWidget *parent, pki_x509 *signer)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::revImg);
	validNumber->setText(QString::number(signer->getCrlDays()));
	validRange->setCurrentIndex(0);
	on_applyTime_clicked();
	nextUpdate->setEndDate(true);

	pki_key *key = signer->getRefKey();
	hashAlgo->setKeyType(key->getKeyType());
	hashAlgo->setupHashes(key->possibleHashNids());

	if (signer->hasExtension(NID_subject_alt_name))
		subAltName->setEnabled(true);
	else
		subAltName->setEnabled(false);
}

void NewCrl::on_applyTime_clicked()
{
	nextUpdate->setDiff(lastUpdate, validNumber->text().toInt(),
					validRange->currentIndex());
}

