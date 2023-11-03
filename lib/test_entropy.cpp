/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>
#include <QFile>
#include <QByteArray>
#include <QString>
#include <QDebug>
#include <QRegularExpression>
#include "entropy.h"

QString getUserSettingsDir()
{
	return QString(".");
}

void dbg(QtMsgType , const QMessageLogContext &, const QString &) { }

class test_entropy: public QObject
{
		Q_OBJECT
		Entropy *e{};
		QString rnd{};

	private slots:
		void initTestCase();
		void cleanupTestCase();
		void start();
		void muchSalt();
};

void test_entropy::initTestCase()
{
	rnd = getUserSettingsDir() + "/.rnd";
	qInstallMessageHandler(dbg);
	e = new Entropy();
	QCOMPARE(QFileInfo::exists(rnd), false);
}

void test_entropy::cleanupTestCase()
{
	delete e;
	QVERIFY(QFileInfo::exists(rnd));
	QFile::remove(rnd);
	qInstallMessageHandler(0);
}

void test_entropy::start()
{
	e->add(17);
	QVERIFY(e->strength() > 0);
	e->add_buf((unsigned char*)"SomeText", 8);
}

void test_entropy::muchSalt()
{
	QRegularExpression rx("^T[0-9a-z]{16}$");
	QString s1, s2;
	for (int i=0; i<100; i++) {
		s1 = e->makeSalt();
		QVERIFY(s1.contains(rx));
		QCOMPARE(s1.size(), 17);
		QVERIFY(s1 != s2);
		s2 = s1;
	}
}

QTEST_MAIN(test_entropy)
#include "test_entropy.moc"
