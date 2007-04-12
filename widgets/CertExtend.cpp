/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
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


CertExtend::CertExtend(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	a1time time;
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::certImg);
	notBefore->setDate(time.now());
	notAfter->setDate(time.now(60 * 60 * 24 * 356));
}

void CertExtend::applyTimeDiff()
{
	applyTD(this, validNumber->text().toInt(), validRange->currentIndex(),
		midnightCB->isChecked(), notBefore, notAfter);
}
