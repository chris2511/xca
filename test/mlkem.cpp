/* vi: set sw=4 ts=4:
 *
 * Regression test: creating a certificate with an ML-KEM key must fail
 * gracefully. The new certificate used to be freed twice (once before the
 * throw, once in the catch handler), which corrupted the heap and made the
 * application die or hang after showing the error message.
 */

#include <QTest>

#include <openssl/obj_mac.h>

#include "widgets/MainWindow.h"
#include "widgets/NewX509.h"
#include "ui_NewX509.h"
#include "lib/db_x509.h"
#include "lib/db_key.h"
#include "lib/pki_evp.h"
#include "lib/x509name.h"

#include "main.h"

void test_main::mlkemSigning()
{
#ifndef NID_ML_KEM_768
	QSKIP("ML-KEM is not supported by this OpenSSL version");
#else
	ign_openssl_error();
	openDB();

	db_key *keys = Database.model<db_key>();
	pki_key *key = keys->newKey(keyjob("ML-KEM-768"), "kemkey");
	QVERIFY(key);
	QVERIFY(key->supportsSigning() == false);
	QVERIFY(key->possibleHashNids().isEmpty());

	NewX509 *dlg = new NewX509(mainwin);
	dlg->setCert();
	dlg->show();
	QVERIFY(QTest::qWaitForWindowActive(dlg));

	dlg->keyList->setCurrentPkiItem(key);
	x509name n;
	n.addEntryByNid(NID_commonName, "kemcert");
	dlg->setX509name(n);
	dlg->description->setText("kemcert");

	db_x509 *certs = Database.model<db_x509>();
	pki_x509 *cert = certs->newCert(dlg);

	/* Must be refused, and the object must be destroyed exactly once */
	QVERIFY(cert == nullptr);
	delete dlg;
	QVERIFY(certs->getByName("kemcert") == nullptr);

	/* The database must still be usable afterwards */
	QVERIFY(Database.isOpen());
	QCOMPARE(Store.getAll<pki_base>().size(), 1);
#endif
}
