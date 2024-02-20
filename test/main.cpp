/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QFile>

#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>
#else
#define OSSL_PROVIDER_try_load(a,b,c) do{}while(0)
#endif

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"

#include "lib/debug_info.h"
#include "lib/entropy.h"
#include "lib/pki_evp.h"

#include "main.h"

char segv_data[1024];

void test_main::initTestCase()
{
	OSSL_PROVIDER_try_load(0, "legacy", 1);

	debug_info::init();

	entropy = new Entropy;

	Settings.clear();
	initOIDs();

	mainwin = new MainWindow();
	mainwin->show();

	pwdialog = new PwDialogMock();
	PwDialogCore::setGui(pwdialog);

	xcaWarning::setGui(new xcaWarningCore());
}

void test_main::cleanupTestCase()
{
	mainwin->close_database();
	delete entropy;
	delete mainwin;
	pki_export::free_elements();
	QFile::remove("testdb.xdb");
}

void test_main::cleanup()
{
	mainwin->close_database();
	dbstatus();
	QFile::remove("testdb.xdb");
}

void test_main::openDB()
{
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("testdbpass", pw_ok),
	});
	mainwin->close_database();
	QFile::remove("testdb.xdb");
	Database.open("testdb.xdb");
	Settings["pkcs12_keep_legacy"] = true;
	mainwin->setup_open_database();
	dbstatus();
}

void test_main::dbstatus()
{
	QList<pki_base*> allitems = Store.getAll<pki_base>();
	QStringList out;
	foreach(pki_base *p, allitems)
		out << QString("%1[%2]").arg(p->getIntName()).arg(p->getTypeString());
	qDebug("%s ALL: %lld %s", Database.isOpen() ? "OPEN" : "CLOSED",
		allitems.size(), out.join(", ").toUtf8().constData());
}

QTEST_MAIN(test_main)
