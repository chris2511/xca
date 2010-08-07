/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTKEY_H
#define __EXPORTKEY_H

#include "ui_ExportKey.h"
#include "ExportDialog.h"

class ExportKey: public ExportDialog, public Ui::ExportKey
{
	Q_OBJECT

   private:
	bool onlyPub;

   public:
	ExportKey(QWidget *parent, QString fname, bool onlypub);

   public slots:
	void canEncrypt();
};

#endif
