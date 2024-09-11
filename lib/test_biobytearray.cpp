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
		void bio_BN();
		void bio_base64UrlEncode();
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

void test_biobytearray::bio_BN()
{
	BIGNUM *bn = nullptr;
	BN_hex2bn(&bn, "1234567890abcdef");
	BioByteArray ba(bn, 64);
	BioByteArray bb(bn, 80);

	QCOMPARE(ba.byteArray().size(), 8);
	QCOMPARE(ba.byteArray(), QByteArray::fromHex("1234567890abcdef"));
	QCOMPARE(bb.byteArray().size(), 10);
	QCOMPARE(bb.byteArray(), QByteArray::fromHex("00001234567890abcdef"));

	BN_hex2bn(&bn, "7FFFFFFF");
	BioByteArray bc(bn);
	QCOMPARE(bc.byteArray().size(), 4);
	QCOMPARE(bc.byteArray(), QByteArray::fromHex("7fffffff"));

	BN_hex2bn(&bn, "80000000");
	BioByteArray bd(bn);
	QCOMPARE(bd.byteArray().size(), 5);
	QCOMPARE(bd.byteArray(), QByteArray::fromHex("0080000000"));
}

void test_biobytearray::bio_base64UrlEncode()
{
	BioByteArray ba("Suppe");
	QCOMPARE(ba.base64UrlEncode(), QString("U3VwcGU"));
	BioByteArray bb(QByteArray::fromBase64("abc+def/ghijAA=="));
	QCOMPARE(bb.base64UrlEncode(), QString("abc-def_ghijAA"));
}

QTEST_MAIN(test_biobytearray)
#include "test_biobytearray.moc"
