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
#include "lib/pki_key.h"
#include "lib/builtin_curves.h"
#include <QStringList>

class NewKey: public QDialog, public Ui::NewKey
{
	Q_OBJECT
	private:
		void updateCurves(unsigned min=0, unsigned max=INT_MAX,
			unsigned long ec_flags=0);
		void addCurveBoxCurves(const QList<builtin_curve> &curves);
	public:
		static keyjob defaultjob;
		NewKey(QWidget *parent, const QString &name);
		keyjob getKeyJob() const;

	public slots:
		void accept();
		void on_keyType_currentIndexChanged(int);
};
#endif
