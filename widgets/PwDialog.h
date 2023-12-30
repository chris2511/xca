/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PWDIALOG_H
#define __PWDIALOG_H

#include "ui_PwDialog.h"
#include "lib/PwDialogCore.h"
#include "lib/pass_info.h"

class PwDialog: public QDialog, public Ui::PwDialog
{
	Q_OBJECT

   private:
	pass_info *pi{};
	Passwd final{};
	bool wrDialog{};

   public:
	PwDialog(pass_info *p, bool write = false);
	Passwd getPass() {
		return final;
	}
	void addAbortButton();
	void setRW(bool write);

	enum open_result execute(pass_info *p, Passwd *passwd,
			bool write = false, bool abort = false);

   public slots:
	void accept();
	void buttonPress(QAbstractButton *but);
};

class PwDialogUI: public PwDialogUI_i
{
	enum open_result execute(pass_info *p, Passwd *passwd,
	               bool write = false, bool abort = false);
};
#endif
