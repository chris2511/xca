/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ScardDetail.h"
#include "MainWindow.h"
#include "lib/pki_scard.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlineedit.h>

ScardDetail::ScardDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::scardImg);
}

void ScardDetail::setScard(pki_scard *card)
{
	cardDesc->setText(card->getIntName());

	cardBox->setTitle(tr("Card") + " [" + card->getCardLabel() + "]");
	cardManufacturer->setText(card->getManufacturer());
	cardSerial->setText(card->getSerial());

	keyBox->setTitle(tr("Key") + " [" + card->getLabel() + "]");
	keyLength->setText(card->length());
	keyID->setText(card->getId());
}
