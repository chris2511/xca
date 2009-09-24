/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SCARDDETAIL_H
#define __SCARDDETAIL_H

#include "ui_ScardDetail.h"
#include "lib/pki_scard.h"

class pki_evp;

class ScardDetail: public QDialog, private Ui::ScardDetail
{
	Q_OBJECT

   public:
	ScardDetail(QWidget *parent);
	void setScard(pki_scard *card);

};
#endif
