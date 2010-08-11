/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __NEWKEY_H
#define __NEWKEY_H

#include "ui_NewKey.h"
#include "lib/pkcs11_lib.h"
#include <QtCore/QStringList>

class NewKey: public QDialog, public Ui::NewKey
{
	Q_OBJECT

	public:
		NewKey(QWidget *parent, QString name);
		int getKeytype();
		int getKeysize();
		int getKeyCurve_nid();
		slotid getKeyCardSlot();
		bool isToken();
	public slots:
		void on_keyType_currentIndexChanged(int);

};
#endif
