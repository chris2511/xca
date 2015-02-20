/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __NEWKEY_H
#define __NEWKEY_H

#include "ui_NewKey.h"
#include "lib/pkcs11_lib.h"
#include <QStringList>

class NewKey: public QDialog, public Ui::NewKey
{
	Q_OBJECT
	private:
		static int defaultType;
		static int defaultEcNid;
		static int defaultSize;
		void updateCurves(unsigned min=0, unsigned max=INT_MAX,
			unsigned long ec_flags=0);
	public:
		NewKey(QWidget *parent, QString name);
		int getKeytype();
		int getKeysize();
		int getKeyCurve_nid();
		slotid getKeyCardSlot();
		bool isToken();
		QString getAsString();
		static int setDefault(QString def);
	public slots:
		void on_keyType_currentIndexChanged(int);

};
#endif
