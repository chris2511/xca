/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/NewKey.h"
#include "ui_NewKey.h"
#include "main.h"

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
#if defined(EVP_PKEY_ML_DSA_65) && defined(NID_ML_KEM_768)
	/* The post quantum parameter sets are grouped by algorithm family */
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-DSA"));
	QCOMPARE(dlg->keyType->currentText(), QString("ML-DSA"));
	QCOMPARE(dlg->paramBox->isVisible(), true);
	QCOMPARE(dlg->paramLabel->isVisible(), true);
	QCOMPARE(dlg->paramBox->count(), 3);
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-DSA-44"));
	dlg->paramBox->setCurrentIndex(1);
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-DSA-65"));
	QCOMPARE(dlg->keyLength->isVisible(), false);

	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-KEM"));
	QCOMPARE(dlg->paramBox->count(), 3);
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-KEM-512"));

	/* The parameter set is remembered per algorithm family */
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-DSA"));
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-DSA-65"));
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-KEM"));
	dlg->paramBox->setCurrentIndex(2);
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-KEM-1024"));
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-DSA"));
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-DSA-65"));
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("ML-KEM"));
	QCOMPARE(dlg->getKeyJob().toString(), QString("ML-KEM-1024"));

#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
	/* 12 parameter sets, SHA2 and SHAKE separated */
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("SLH-DSA"));
	QCOMPARE(dlg->paramBox->count(), 13);
	QCOMPARE(dlg->getKeyJob().toString(), QString("SLH-DSA-SHA2-128s"));
#endif

	/* Classic algorithms keep one entry and no parameter box */
	dlg->keyType->setCurrentIndex(dlg->keyType->findText("RSA"));
	QCOMPARE(dlg->paramBox->isVisible(), false);
	QCOMPARE(dlg->paramLabel->isVisible(), false);
#endif
	dlg->accept();
	delete dlg;
}
