/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "BioByteArray.h"
#include <openssl/bio.h>

class test_biobytearray: public QObject
{
	Q_OBJECT

	private slots:
		void set();
		void add();
		void bio_ro();
		void bio_wr();
};

void test_biobytearray::set()
{
	BioByteArray ba("Hello");
	QCOMPARE(ba.qstring(), QString("Hello"));
	QCOMPARE(ba.byteArray(), QByteArray("Hello"));

	ba = "Wärme";
	QCOMPARE(ba.qstring(), QString("Wärme"));
	QCOMPARE(ba.byteArray(), QByteArray("Wärme"));
}

void test_biobytearray::add()
{
	BioByteArray ba("Wärme");

	ba += "Bad";
	QCOMPARE(ba.qstring(), QString("WärmeBad"));
	QCOMPARE(ba.byteArray(), QByteArray("WärmeBad"));
}

void test_biobytearray::bio_ro()
{
	char buf[256];
	BioByteArray ba("Wärmetauscher");
	int l = BIO_read(ba.ro(), buf, sizeof buf);
	QCOMPARE(l, 14);
	QCOMPARE(l, ba.size());
	QCOMPARE(QByteArray(buf, l), ba.byteArray());
}

void test_biobytearray::bio_wr()
{
	BioByteArray ba("Suppe");
   	ba += "n";
	BIO_puts(ba, "grün");
	BIO_write(ba, "einlage", 7);

	QCOMPARE(ba.byteArray(), QByteArray("Suppengrüneinlage"));
	QCOMPARE(ba.size(), sizeof "Suppengrüneinlage" -1);
}

QTEST_MAIN(test_biobytearray)
#include "test_biobytearray.moc"
