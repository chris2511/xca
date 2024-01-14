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

#include "PwDialogMock.h"
#include "main.h"

void test_main::importPEM()
{
	try {
	class PwDialogMock *pwdialog = new PwDialogMock();
	PwDialogCore::setGui(pwdialog);
	xcaWarning::setGui(new xcaWarningCore());

	ign_openssl_error();
	openDB();
	pki_multi *pem = new pki_multi();
	pem->fromPEMbyteArray(pemdata["interca1"].toUtf8(), QString());

	pwdialog->setExpectations(QList<pw_expect*>{
			new pw_expect("Title", pw_ok),
	});
	QVERIFY_EXCEPTION_THROWN(pem->fromPEMbyteArray(
				pemdata["interpk8"].toUtf8(), QString()), errorEx);

	pwdialog->setExpectations(QList<pw_expect*>{
			new pw_expect("pass", pw_ok),
	});
	pem->fromPEMbyteArray(pemdata["interpk8"].toUtf8(), QString());
	QCOMPARE(pem->failed_files.count(), 0);
	ImportMulti *dlg = new ImportMulti(mainwin);
	dlg->addItem(pem);

	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	delete dlg;
	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
}
