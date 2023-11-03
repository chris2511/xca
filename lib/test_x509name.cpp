/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include "x509name.h"

class test_x509name: public QObject
{
		Q_OBJECT
		x509name x;
	private slots:
		void init();
		void construct();
		void d2i2d();
		void entries();
		void entrystack();
};

void test_x509name::init()
{
	// Reset "x" for each test run
	x = x509name();
	x.addEntryByNid(NID_countryName, "DE");
	x.addEntryByNid(NID_stateOrProvinceName, "Berlin");
}

void test_x509name::construct()
{
	x509name y;
	QCOMPARE(x.entryCount(), 2);
	QCOMPARE(y.entryCount(), 0);
	QVERIFY(x != y);
}

void test_x509name::d2i2d()
{
	QByteArray b = x.i2d();
	x509name y;
	y.d2i(b);
	QCOMPARE(x, y);
}

void test_x509name::entries()
{
	QCOMPARE(x.oneLine(), "C = DE, ST = Berlin");
	x.addEntryByNid(NID_organizationName, "Firma");
	QCOMPARE(x.oneLine(), "C = DE, ST = Berlin, O = Firma");
	x509name z(x);
	QCOMPARE(z.oneLine(XN_FLAG_RFC2253), "O=Firma,ST=Berlin,C=DE");

	QCOMPARE(x.nid(0), NID_countryName);
	QCOMPARE(x.nid(1), NID_stateOrProvinceName);
	QCOMPARE(x.nid(2), NID_organizationName);

	QCOMPARE(x.entryList(1).join(":"), "ST:stateOrProvinceName:Berlin:UTF8STRING");
	z = x509name(x.get0());
	QCOMPARE(x.getEntryByNid(NID_countryName), "DE");
	QCOMPARE(x.getEntryByNid(NID_organizationName), "Firma");
	QCOMPARE(x.getMostPopular(), "Firma");
	x.addEntryByNid(NID_commonName, "Ich Persönlich");
	QCOMPARE(x.getMostPopular(), "Ich Persönlich");

	QCOMPARE(x.getEntry(0), "DE");
	QCOMPARE(x.getEntry(2), "Firma");
	QCOMPARE(x.getEntry(3), "Ich Persönlich");

	QCOMPARE(x.getEntryTag(0), "PRINTABLESTRING");
	QCOMPARE(x.getEntryTag(2), "UTF8STRING");
	QCOMPARE(x.getEntryTag(3), "UTF8STRING");

	QCOMPARE(x.popEntryByNid(NID_stateOrProvinceName), "Berlin");
	QCOMPARE(x.entryCount(), 3);
	QCOMPARE(x.oneLine(XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB),
	                   "C = DE, O = Firma, CN = Ich Persönlich");
}

void test_x509name::entrystack()
{
	x.addEntryByNid(NID_organizationName, "Firma");
	x.addEntryByNid(NID_commonName, "Ich Persönlich");

	STACK_OF(X509_NAME_ENTRY) *xname = sk_X509_NAME_ENTRY_new_null();
	for (int i=0; i < x.entryCount(); i++) {
		QByteArray b = x.getEntry(i).toUtf8();
		X509_NAME_ENTRY *ne = X509_NAME_ENTRY_create_by_NID(nullptr, x.nid(i),
		      MBSTRING_UTF8, (const unsigned char*)b.constData(), b.size());
		sk_X509_NAME_ENTRY_push(xname, ne);
	}
	x509name z(xname);
	QCOMPARE(z.oneLine(XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB),
                       "C = DE, ST = Berlin, O = Firma, CN = Ich Persönlich");
	QCOMPARE(x, z);
	sk_X509_NAME_ENTRY_pop_free(xname, X509_NAME_ENTRY_free);
}

QTEST_MAIN(test_x509name)
#include "test_x509name.moc"
