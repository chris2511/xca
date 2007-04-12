/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTEXTEND_H
#define __CERTEXTEND_H

#include "ui_CertExtend.h"

class pki_key;

class CertExtend: public QDialog, public Ui::CertExtend
{
	Q_OBJECT

   public:
	CertExtend(QWidget *parent);
   public slots:
	void applyTimeDiff();

};
#endif
