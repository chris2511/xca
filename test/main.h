/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAIN_H
#define __MAIN_H

#include "lib/entropy.h"
#include "lib/pki_evp.h"

#include "PwDialogMock.h"

class test_main: public QObject
{
	Q_OBJECT

	Entropy *entropy {};
	PwDialogMock *pwdialog{};

	void openDB();
	void dbstatus();
	static const QMap<QString, QString> pemdata;

  private slots:
	void initTestCase();
	void cleanupTestCase();
	void cleanup();
	void newKey();
	void importPEM();
	void exportFormat();
	void revoke();

  public:
	template <class T> static T *findWindow(const QString &name)
	{
		T *ret = nullptr;
		for (int i=0; i < 200; i++) {
			foreach (QWidget *w, QApplication::allWidgets()) {
				T *dest = dynamic_cast<T*>(w);
				if (dest && name == dest->objectName() && dest->isVisible()) {
					qDebug() << "Widget found:" << name << dest << i << dest->isVisible();
					ret = dest;
				}
			}
			if (ret)
				return ret;
			QThread::msleep(50);
		}
		qWarning() << "Widget not found:" << name;
		return nullptr;
	}
};

#endif
