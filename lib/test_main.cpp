/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QDir>
#include <QDebug>
#include <QTest>
#include <QString>
#include <QThread>
#include <QApplication>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/ImportMulti.h"
#include "ui_ImportMulti.h"
#include "widgets/NewKey.h"
#include "ui_NewKey.h"
#include "entropy.h"
#include "pki_evp.h"
#include "pki_multi.h"
#include "debug_info.h"
#include "PwDialogCore.h"

char segv_data[1024];

class test_main: public QObject
{
    Q_OBJECT
	Entropy *entropy {};

	void openDB();

  private slots:
	void initTestCase();
	void cleanupTestCase();
	void newKey();
	void importPEM();
};

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

void test_main::newKey()
{
	/* RSA 3012 bit key - Remember as default */
	NewKey *dlg = new NewKey(mainwin, "Alfons");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	dlg->keyLength->setEditText("3012 bit");
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	dlg->rememberDefault->setChecked(true);
	dlg->accept();
	keyjob job = dlg->getKeyJob();
	QCOMPARE(job.ktype.name, "RSA");
	QCOMPARE(job.size, 3012);
	delete dlg;

	/* Remembered RSA:3012 key. Change to EC:secp521r1 */
	dlg = new NewKey(mainwin, "Erwin");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	QCOMPARE(job.toString(), dlg->getKeyJob().toString());
#ifndef OPENSSL_NO_EC
	/* Curve box visible after selecting EC Key */
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
	dlg->keyType->setCurrentIndex(2);
	QCOMPARE(dlg->curveBox->isVisible(),true);
	QCOMPARE(dlg->curveLabel->isVisible(),true);
	dlg->curveBox->setCurrentIndex(2);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
#ifdef EVP_PKEY_ED25519
	/* Select Edwards Curve */
	dlg->keyType->setCurrentIndex(3);
	QCOMPARE(dlg->getKeyJob().toString(), "ED25519");
	/* Neither key size nor curve is visible */
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
	QCOMPARE(dlg->keyLength->isVisible(),false);
	QCOMPARE(dlg->keySizeLabel->isVisible(),false);
#endif
	/* Back to EC and previously set curve is set */
	dlg->keyType->setCurrentIndex(2);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
#endif
	dlg->accept();
	delete dlg;

	/* Open dialog again and RSA:3012 is remembered */
	dlg = new NewKey(mainwin, "Otto");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
	QCOMPARE(job.toString(), dlg->getKeyJob().toString());
	QCOMPARE(dlg->curveBox->isVisible(),false);
	QCOMPARE(dlg->curveLabel->isVisible(),false);
#ifndef OPENSSL_NO_EC
	/* Select EC and remember as default */
	dlg->keyType->setCurrentIndex(2);
	dlg->curveBox->setCurrentIndex(2);

	QCOMPARE(dlg->curveBox->isVisible(),true);
	QCOMPARE(dlg->curveLabel->isVisible(),true);
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
	dlg->rememberDefault->setChecked(true);
	dlg->accept();
	delete dlg;

	/* Now "EC:secp521r1" is remembered as default */
	dlg = new NewKey(mainwin, "Heini");
	dlg->show();
	Q_ASSERT(QTest::qWaitForWindowActive(dlg));
	QCOMPARE(dlg->getKeyJob().toString(), "EC:secp521r1");
	QCOMPARE(dlg->rememberDefault->isChecked(), false);
#endif
	dlg->accept();
	delete dlg;
}
const QString pemcert(R"PEM(
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIOvC5r9Smk3wwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AxMHUm9vdCBDQTAeFw0yMzEwMjUxODU1MDBaFw0zMzA5MTgxNjQxMDBaMBUxEzAR
BgNVBAMTCkludGVyIENBIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDJlExG3+oLO6GFuD4pa9sI5mJL/9fADcoe9bv1SAnRKu/GPtCMaruVTKBAt5x4
mwt5My6WhyPdpYp0z6yUgSCrbkSAMvMzGlS1W5Ke4UU4GaufCRjHeXNVpx9wXEPY
y46HO5vSZZiGzl46UMmeVkV5kGeh8y2giS/M0prVqpOLdIloeJykgp8k29llkFj/
OEa2WPiKhUnBvna5IDyrjjTKUGo5mxi9RVuArZwZ16kdJPG292WOVtQ8uTg391XQ
2uOho/nv/IoWysZLnwvHIZkcH413owvBULqM5fVda0j9qkvQEKa4GAiitx2HX0wW
YNvtUhZrXnHU/DzYkbhZrW7VAgMBAAGjcjBwMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFE5aAJMfa9ksd7718xYlNHF/YSjtMAsGA1UdDwQEAwIBBjARBglghkgB
hvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkq
hkiG9w0BAQsFAAOCAQEAbUcuBvX6jGBYDFBPn1dK9xEQuexrh7gUtNEEKumDF6vN
Bj6xHxZjjwrJsGeX8aTqS3J5BE8vsv4+xiPWaObalUtmkGrS0x/DAe6ZpzGl/aq7
tknve6VF9s58SjnefQhf4ko18/sylX0Rp7dliMckM3fcUINe0HgzbO25MqNiTZo4
/WPhDmvJPxbogzFoHWA/8jh1/EMyxd8JeiEG6SxZE2PL8oY0i52zHDQCFr6S8dyc
OWuGL0dQBu7Oi0f/eKBxWPf8uExTjSj44z6y0y/ioJ4+vvxVJZu9eBY6GtQ3Zjck
HcE+16987H74MazZVpmS1O23RxxT9SSJCTsqQRl58g==
-----END CERTIFICATE-----
)PEM");
const QString pempk8(R"PEM(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIWPH8Cg7cPigCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBiJstpznVPkN4zAO6Sb7jYBIIE
0P+jKWR80+EJuUpm1pOLJrDibuPJZE7HDtWrERL765MnQ8ssPXvF5Cjum5b1S38J
SJ6XCjOknUSkD1vySVZYd3Nlc1ogHWswOslGFiiQtr26tpm7eFvE5pEzAFh/ib/q
Y/hjAaSoC5//HB7jzbqHFW2q8aD6uCHOCOPgRFgLj1yzrgZNVw1WZl1RWRrUmA52
P4gBtmiU8dSFTpejOi01P7FRPea97UFcdrqqN65Xg3EUOqhrFthY36sj8Z5R+nNP
gggIZmB8nwPbANNjJ0oRYWlYt1dCCZwWMPF4G7uPm8KtFGxLmvc7hCeoayars+oj
W/v2w2xiJMthNMPkhUiKmZdDIgyU1/2y00dlcRotwMSQ5GfBSl+WCJWvi7cSAqDA
ff1z2yrVsjHfg87xgaaJPhE04T8wIAD0AGBuiCxixBOIc5klkcvVP19XgG1k7uxG
MLzp9Q7ZUywWO23uZ/n0I/XKvJuMCda6/Wm0tGHLRjxPDw2xozBkeZuLiwoTsACq
bVUcvv5jQqSfzCyezPHw/RVsxhji3XwaVEka3A5wM9YFjRa6KlTOiQhj8ZmdF5Uu
yOM45KiPMSdupSiP2B5FATM0W8B0+Av6cgpTnIguZXTubx5hxi4zmgic3O/fvaEO
wxT0nYj3Z7AXK9ZBIOdoBG8vW9kd8DmvehWOcseLa41BGtW3ZacjQdDfh08H7bo1
RELNIEnRLQj//+g1Qbw2wrU0Uymb/LqMDQ5YIQ35WJ0RB5UylBTDZBAHI/9A6yfa
Ospz5sNPkACd9ucEDgLHmj80iMAeou8W5RWsXbyU4exnXudTvjrFhntOSnF4P7yf
+sM1CFD65B6lEdpPtY4f4rrjQQYy2Wwv6HvyTTujI7zgPJ+JO59g/wPD9BdLBAa8
81uujtoDQsZ0QEHLru+TINTxEk3tLbA0cnJEazG/V3Hlyrv4fxapzkcpct+2z40c
SITi8SESkF6aL2k+jhgAML9VsBuuzJmU/1psVTEtjGo/+vE1n7Cu2JWn1+yfqs2q
BNzt78qCYOivRmALzYIMQfv4vVMPnHiJqN/9+vdrqe+G1B7rrXOR75bB/4MnfXUX
t0ukYZ7nc/2HtX8LNrQWCfDbKJVkuPhGt4ivqY3WPUS9Qxh/rH2m2DKH33Y+bAtc
x+bjs9GSMJppY8o3NUlW4fROhCYpdvm0nmSILg+o68o1RLqu223Suk3mEDFIby+x
wHvlM910X2vXrMfLJ5C1Z5n6lTtuqwDHtKzTwarD5sQNckSPENZLlULKyU8IIncP
ENel06odAkhwE36tn7Vox2+AGpTCcG8N1kOaVbpiLC9WcvdWlQRGsycz57AQAHI+
8DjkqkbkS+I7IODBv4CTjrwSdbBB+CICzpHFU8jiRRT8JqlwMKnNfSKS1GRcw32A
UI41YouOndS1WTY7bfnYorMW1Qdjb5SadV6PQh/5W7yyeMdGkUVIQ5/1cEfm98F0
xajsjEdZhbN8DvgJX2fBJrfLzVwNuthwd5cMGYmUSDBhrGZT+hKfmzuMJe3HT7K1
He169YVmA6yq877fuEQKpKtfVXIkekIJKtRL4l9Ne/4pCnbdB+YYARRJIiea9ofz
u/ubQSGGRgBCW4BhlWMaAJcoQoQR0EzYgzpqBqN9ErwB
-----END ENCRYPTED PRIVATE KEY-----
)PEM");
#define TRACEE fprintf(stderr, "TRACE %s:%d\n", __func__, __LINE__);

class pw_expect
{
  public:
	bool write;
	bool abort;
	pass_info pi;

	Passwd pass_return;
	enum open_result result;

	pw_expect(const char *p, enum open_result r) :
		write(false), abort(false), pi(QString(), QString()),
		pass_return(), result(r)
	{
		pass_return = p;
	}
};

class PwDialogMock: public PwDialogUI_i
{
    enum open_result execute(pass_info *p, Passwd *passwd,
					bool write = false, bool abort = false)
	{
		if (pw_expectations.size() <= expect_idx)
			return open_abort;

		pw_expect *pwe = pw_expectations[expect_idx++];
		pwe->write = write;
		pwe->abort = abort;
		pwe->pi.setTitle(p->getTitle());
		pwe->pi.setDescription(p->getDescription());

		qWarning() << "PwDialogMock" << p->getDescription() << expect_idx;
		*passwd = pwe->pass_return;
		return pwe->result;
	}
	public:
		int expect_idx{};
		QList<pw_expect*> pw_expectations{};
		void setExpectations(const QList<pw_expect*> pwe)
		{
			qDeleteAll(pw_expectations);
			pw_expectations = pwe;
			expect_idx = 0;
		}
};

void test_main::importPEM()
{
	try {
	class PwDialogMock *pwdialog = new PwDialogMock();
	PwDialogCore::setGui(pwdialog);
	xcaWarning::setGui(new xcaWarningCore());

	ign_openssl_error();
	openDB();
	pki_multi *pem = new pki_multi();
	pem->fromPEMbyteArray(pemcert.toUtf8(), QString());

	pwdialog->setExpectations(QList<pw_expect*>{
			new pw_expect("Title", pw_ok),
	});
	QVERIFY_EXCEPTION_THROWN(pem->fromPEMbyteArray(pempk8.toUtf8(), QString()), errorEx);

	pwdialog->setExpectations(QList<pw_expect*>{
			new pw_expect("pass", pw_ok),
	});
	pem->fromPEMbyteArray(pempk8.toUtf8(), QString());
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

QTEST_MAIN(test_main)
#include "test_main.moc"
