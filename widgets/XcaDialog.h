/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCADIALOG_H__
#define __XCADIALOG_H__

#include <QDialog>
#include "ui_XcaDialog.h"
#include "lib/pki_base.h"

class XcaDialog : public QDialog, public Ui::XcaDialog
{
	QWidget *widg;
  public:
	XcaDialog(QWidget *parent, enum pki_type type, QWidget *w,
		const QString &t, const QString &desc,
		const QString &help_ctx = QString());
	void noSpacer();
	void aboutDialog(const QPixmap &left);
};

#endif
