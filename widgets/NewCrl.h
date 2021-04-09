/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __NEWCRL_H
#define __NEWCRL_H

#include "ui_NewCrl.h"
#include "lib/pki_crl.h"

class pki_key;

class NewCrl: public QWidget, public Ui::NewCrl
{
	Q_OBJECT

	crljob task;
   public:
	NewCrl(const crljob &task, QWidget *w = nullptr);
	~NewCrl();
	crljob getCrlJob() const;
	static void newCrl(QWidget *parent, pki_x509 *issuer);

   public slots:
	void on_applyTime_clicked();
};
#endif
