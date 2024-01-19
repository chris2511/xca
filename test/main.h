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
};

#endif
