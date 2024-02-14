/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2024 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QThread>
#include <QDialog>
#include <QCheckBox>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"
#include "widgets/CertExtend.h"
#include "ui_CertExtend.h"
#include "widgets/RevocationList.h"
#include "ui_RevocationList.h"
#include "ui_Revoke.h"

#include "lib/pki_multi.h"

#include "main.h"

#define ZERO_SECS "yyyyMMddHHmm'00Z'"
a1time not_after = a1time::now(3*356*24*60*60);

void revoke_and_renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Checked);
	dlg->notAfter->setDate(not_after);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
	Revocation *rev = test_main::findWindow<Revocation>("Revoke");
	rev->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Unchecked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->notAfter->setDate(not_after);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

void renew_del_keep_serial()
{
	CertExtend *dlg = test_main::findWindow<CertExtend>("CertExtend");
	if (!dlg)
		return;
	dlg->replace->setCheckState(Qt::Checked);
	dlg->revoke->setCheckState(Qt::Unchecked);
	dlg->noWellDefinedExpDate->setCheckState(Qt::Checked);
	dlg->keepSerial->setCheckState(Qt::Checked);
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
	dlg->buttonBox->button(QDialogButtonBox::Ok)->click();
}

QList<pki_x509*> getcerts(const QString &name)
{
	QList<pki_x509*> l;
	foreach(pki_x509 *pki, Store.getAll<pki_x509>()) {
        if (pki->getIntName() == name)
			l << pki;
	}
	return l;
}

void test_main::revoke()
{
	try {

	ign_openssl_error();
	openDB();
	dbstatus();
	pki_multi *pem = new pki_multi();
	pem->fromPEMbyteArray(pemdata["Inter CA 1"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA"].toUtf8(), QString());
	pem->fromPEMbyteArray(pemdata["Root CA Key"].toUtf8(), QString());
	Database.insert(pem);
	dbstatus();

	QThread *job;
	db_x509 *certs = Database.model<db_x509>();

	// Revoke and renew
	pki_x509 *cert = dynamic_cast<pki_x509*>(certs->getByName("Inter CA 1"));
	a1int serial = cert->getSerial();
	job = QThread::create(revoke_and_renew);
	job->start();
	certs->certRenewal({ certs->index(cert) });
	job->wait();

	delete job;
	dbstatus();
	QList<pki_x509*> l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());

	bool found = false;
	x509revList revs = dynamic_cast<pki_x509*>(certs->getByName("Root CA"))->getRevList();
	for (x509rev r : revs) {
		if (r.getSerial() == serial)
			found = true;
	}
	QVERIFY2(found, "Revoked serial not found");

	// renew
	not_after = not_after.addDays(30);
	job = QThread::create(renew);
	job->start();
	certs->certRenewal({ certs->index(certs->getByName("Inter CA 1")) });
	job->wait();

	delete job;
	dbstatus();
	l = getcerts("Inter CA 1");
	QCOMPARE(2, l.size());
	// Delete one of the certs
	if (l.size() > 0)
		certs->deletePKI(certs->index(l[0]));
	l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());

	// renew, keep serial
	cert = dynamic_cast<pki_x509*>(certs->getByName("Inter CA 1"));
	serial = cert->getSerial();

	job = QThread::create(renew_del_keep_serial);
	job->start();
	certs->certRenewal({ certs->index(certs->getByName("Inter CA 1")) });
	job->wait();

	delete job;
	dbstatus();
	l = getcerts("Inter CA 1");
	QCOMPARE(1, l.size());
	not_after.setUndefined();
	if (l.size() > 0)
		QCOMPARE(l[0]->getNotAfter().toPlain(), not_after.toPlain());

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
}
