/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QString>
#include "asn1int.h"

#include <openssl/asn1.h>

class test_asn1int: public QObject
{
	Q_OBJECT

  private slots:
	void constructors();
	void setter();
	void ops();
	void der();
	void get();
};

void test_asn1int::constructors()
{
	a1int a(123456), b(QString("0472ae4F"));
	a1int c(a), d(b.get0());

	QCOMPARE(a.toHex(), "01E240");
	QCOMPARE(a.toDec(), "123456");
	QCOMPARE(b.toHex(), "0472AE4F");
	QCOMPARE(c, a);
	QCOMPARE(d, b);
}

void test_asn1int::setter()
{
	unsigned char raw[] = { 7, 0x81, 0xea, 0x11, 0xf };
	a1int a(123456), b;
	b.set(a.get0());
	QCOMPARE(b, a);
	b.setHex("ABcd");
	QCOMPARE(b.toHex(), "ABCD");
	b.setRaw(raw, sizeof raw);
	QCOMPARE(b, a1int("0781EA110F"));
}

void test_asn1int::ops()
{
	a1int f = 388;
	QCOMPARE(f.getLong(), 388);
	QCOMPARE(f++.getLong(), 388);
	QCOMPARE((++f).getLong(), 390);
	QCOMPARE(f.getLong(), 390);
	a1int s(f);
	QCOMPARE(s, f++);
	QCOMPARE(++s, f);
	QVERIFY(++s != f);
	QCOMPARE(s.getLong(), 392);
	QCOMPARE(f.getLong(), 391);
	QVERIFY(f < s);
	QVERIFY(s > f);
	QCOMPARE(QString(a1int(0x18929)), "018929");
}

void test_asn1int::get()
{
	a1int f(42);
	ASN1_INTEGER *g = f.get();
	QVERIFY(g != f.get0());
	QCOMPARE(f.get0(), f.get0());
	ASN1_INTEGER_free(g);
}

void test_asn1int::der()
{
	a1int f(12388);
	QByteArray b(f.i2d());
	QCOMPARE(b.toHex(), "02023064");
	QCOMPARE(f.derSize(), 4);
}

QTEST_MAIN(test_asn1int)
#include "test_asn1int.moc"
