/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTEXTEND_H
#define __CERTEXTEND_H

#include "ui_CertExtend.h"
#include "lib/pki_x509.h"

class pki_key;

class CertExtend: public QDialog, public Ui::CertExtend
{
	Q_OBJECT

	pki_x509 *signer;

   public:
	CertExtend(QWidget *parent, pki_x509 *s);

   public slots:
	void on_applyTime_clicked();
	void accept();

};
#endif
