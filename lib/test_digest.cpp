/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QList>

#include "digest.h"
#include <openssl/evp.h>

class test_digest: public QObject
{
    Q_OBJECT
private slots:
    void default_digest();
    void convert();
};

void test_digest::default_digest()
{
	digest d(digest::getDefault());
	QCOMPARE(d.name(), "SHA256");
	digest::setDefault("md5");
	QVERIFY(digest::getDefault().isInsecure());
}

void test_digest::convert()
{
	digest d(EVP_sha512());
	digest e("sha512");

	QCOMPARE(d.name(), "SHA512");
	QCOMPARE(d.MD(), e.MD());
	QVERIFY(!d.isInsecure());
	d.adjust(QList<int>({ NID_md5, NID_sha256, NID_sha384 }));
	QCOMPARE(d.name(), "SHA384");

}

QTEST_MAIN(test_digest)
#include "test_digest.moc"
