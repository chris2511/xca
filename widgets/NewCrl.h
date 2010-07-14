/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __NEWCRL_H
#define __NEWCRL_H

#include "ui_NewCrl.h"
#include "lib/pki_x509.h"

class pki_key;

class NewCrl: public QDialog, public Ui::NewCrl
{
	Q_OBJECT

   public:
	NewCrl(QWidget *parent, pki_x509 *signer);

   public slots:
	void on_applyTime_clicked();
};
#endif
