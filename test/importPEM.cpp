/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"

#include "lib/pki_multi.h"

#include "main.h"

void test_main::importPEM()
{
	try {

	ign_openssl_error();
	openDB();
	dbstatus();
	pki_multi *pem = new pki_multi();

	pem->fromPEMbyteArray(pemdata["Inter CA 1"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA"].toUtf8(), QString());

	// Enter a wrong password and then abort
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("wrongPassword", pw_ok),
	});
	QVERIFY_EXCEPTION_THROWN(pem->fromPEMbyteArray(
				pemdata["Inter CA 1 EncKey"].toUtf8(), QString()), errorEx);


	// Enter a wrong password and then the correct one
	pwdialog->setExpectations(QList<pw_expect*>{
		new pw_expect("BadPassword", pw_ok),
		new pw_expect("pass", pw_ok),
	});
	pem->fromPEMbyteArray(pemdata["Inter CA 1 Key"].toUtf8(), QString());

	QCOMPARE(pem->failed_files.count(), 0);
	ImportMulti *dlg = new ImportMulti(mainwin);
	dlg->addItem(pem);

	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	dlg->on_butOk_clicked();

	delete dlg;
	QList<pki_base*> allitems = Store.getAll<pki_base>();
	QCOMPARE(allitems.count() , 3);
	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
	dbstatus();
}
