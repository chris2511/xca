/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2026 Xavier MARTIN.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QApplication>

#include "x509v3ext.h"
#include "oid.h"

/* Required by pkcs11.cpp which is compiled into xcalib */
char segv_data[1024];

/* The SID URI used in all round-trip tests */
static const QString SID_URI =
	"tag:microsoft.com,2022-09-14:sid:S-1-5-21-1234567890-1234567890-1234567890-1001";
static const QString SID_SAN = "URI:" + SID_URI;

class test_x509v3ext: public QObject
{
	Q_OBJECT

private slots:
	void initTestCase();
	void splitSanEntries_singleEntry();
	void splitSanEntries_twoEntries_space();
	void splitSanEntries_twoEntries_noSpace();
	void splitSanEntries_sidUri_alone();
	void splitSanEntries_sidUri_withOtherEntry();
	void splitSanEntries_criticalPrefix();
	void sanCreate_sidUri_alone();
	void sanCreate_sidUri_withDns();
	void sanCreate_multipleUris();
};

void test_x509v3ext::initTestCase()
{
	initOIDs();
}

/* --- splitSanEntries() unit tests --------------------------------------- */

void test_x509v3ext::splitSanEntries_singleEntry()
{
	QStringList r = splitSanEntries("DNS:example.com");
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], "DNS:example.com");
}

void test_x509v3ext::splitSanEntries_twoEntries_space()
{
	QStringList r = splitSanEntries("DNS:example.com, IP:192.0.2.1");
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:example.com");
	QCOMPARE(r[1], "IP:192.0.2.1");
}

void test_x509v3ext::splitSanEntries_twoEntries_noSpace()
{
	/* Legacy format: bare comma without space */
	QStringList r = splitSanEntries("DNS:example.com,IP:192.0.2.1");
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:example.com");
	QCOMPARE(r[1], "IP:192.0.2.1");
}

void test_x509v3ext::splitSanEntries_sidUri_alone()
{
	/* The comma inside the tag: URI must NOT be treated as a separator */
	QStringList r = splitSanEntries(SID_SAN);
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], SID_SAN);
}

void test_x509v3ext::splitSanEntries_sidUri_withOtherEntry()
{
	QString input = "DNS:host.example.com, " + SID_SAN;
	QStringList r = splitSanEntries(input);
	QCOMPARE(r.size(), 2);
	QCOMPARE(r[0], "DNS:host.example.com");
	QCOMPARE(r[1], SID_SAN);
}

void test_x509v3ext::splitSanEntries_criticalPrefix()
{
	/* The critical prefix is stripped before splitSanEntries() is called
	 * (in v3ext::addItem and x509v3ext::create).  When the remaining text
	 * is just the SID SAN, it must parse as one token. */
	QString text = SID_SAN; /* prefix already stripped */
	QStringList r = splitSanEntries(text);
	QCOMPARE(r.size(), 1);
	QCOMPARE(r[0], SID_SAN);
}

/* --- x509v3ext::create() round-trip tests ------------------------------- */

void test_x509v3ext::sanCreate_sidUri_alone()
{
	/* Create a subjectAltName extension with only a SID URI.
	 * Verify the extension is valid and the URI survives the round-trip. */
	x509v3ext ext;
	ext.create(NID_subject_alt_name, SID_SAN);

	QVERIFY2(ext.isValid(), "Extension with SID URI should be valid");

	/* getValue() uses OpenSSL's built-in printer */
	QString val = ext.getValue();
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

void test_x509v3ext::sanCreate_sidUri_withDns()
{
	/* Combine a DNS name and a SID URI -- the path through createExtBySection */
	QString san = "DNS:host.example.com, " + SID_SAN;
	x509v3ext ext;
	ext.create(NID_subject_alt_name, san);

	QVERIFY2(ext.isValid(), "Extension with DNS + SID URI should be valid");

	QString val = ext.getValue();
	QVERIFY2(val.contains("host.example.com"),
		qPrintable("getValue() lost the DNS entry. Got: " + val));
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

void test_x509v3ext::sanCreate_multipleUris()
{
	/* Two ordinary URIs -- exercises the same createExtBySection path since
	 * URIs can contain ':' after the scheme, but not internal commas here.
	 * Also mix in the SID URI as a third entry. */
	QString san = "URI:https://example.com/path, URI:ldap://ldap.example.com, " + SID_SAN;
	x509v3ext ext;
	ext.create(NID_subject_alt_name, san);

	QVERIFY2(ext.isValid(), "Extension with multiple URIs should be valid");

	QString val = ext.getValue();
	QVERIFY2(val.contains("https://example.com/path"),
		qPrintable("getValue() lost the HTTPS URI. Got: " + val));
	QVERIFY2(val.contains("ldap://ldap.example.com"),
		qPrintable("getValue() lost the LDAP URI. Got: " + val));
	QVERIFY2(val.contains(SID_URI),
		qPrintable("getValue() did not preserve SID URI. Got: " + val));
}

QTEST_MAIN(test_x509v3ext)
#include "test_x509v3ext.moc"
