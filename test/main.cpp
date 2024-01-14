/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"

#include "lib/debug_info.h"
#include "lib/entropy.h"
#include "lib/pki_evp.h"

#include "main.h"

char segv_data[1024];

void test_main::initTestCase()
{
	debug_info::init();

	entropy = new Entropy;

	Settings.clear();
	initOIDs();

	mainwin = new MainWindow();
	mainwin->show();
}

void test_main::cleanupTestCase()
{
	Database.close();
	delete entropy;
	delete mainwin;
	pki_export::free_elements();
}

void test_main::openDB()
{
	pki_evp::passwd = "pass";
	QString salt = Entropy::makeSalt();
    pki_evp::passHash = pki_evp::sha512passwT(pki_evp::passwd, salt);
    Settings["pwhash"] = pki_evp::passHash;
	Database.open("testdb.xdb");
}

QTEST_MAIN(test_main)
