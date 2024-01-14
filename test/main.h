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

class test_main: public QObject
{
    Q_OBJECT
	Entropy *entropy {};

	void openDB();
	static const QMap<QString, QString> pemdata;

  private slots:
	void initTestCase();
	void cleanupTestCase();
	void newKey();
	void importPEM();
};

#endif
