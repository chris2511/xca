/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PWDIALOG_H
#define __PWDIALOG_H

#include <QByteArray>
#include "ui_PwDialog.h"
#include "lib/Passwd.h"
#include "lib/pki_x509.h"
#include "lib/pass_info.h"

class PwDialog: public QDialog, public Ui::PwDialog
{
	Q_OBJECT

   private:
	bool wrDialog;
	Passwd final;
	pass_info *pi;

   public:
	PwDialog(pass_info *p, bool write = false);
	Passwd getPass() {
		return final;
	}
	void addAbortButton();
	void setRW(bool write);

	static int execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false);
	static int pwCallback(char *buf, int size, int rwflag, void *userdata);

   public slots:
	void accept();
	void buttonPress(QAbstractButton *but);
};
#endif
