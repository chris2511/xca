/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

#include "widgets/MainWindow.h"
#include "widgets/validity.h"

#include "main.h"

void test_main::testValidity()
{
	try {

		Validity *start = new Validity(mainwin);
		Validity *end = new Validity(mainwin);

		QCOMPARE(start->displayFormat(), "yyyy-MM-dd hh:mm 'GMT'");
		QCOMPARE(end->displayFormat(), "yyyy-MM-dd hh:mm 'GMT'");
		end->setEndDate(true);
		start->hideTime(true);
		end->hideTime(true);
		QCOMPARE(start->displayFormat(), "yyyy-MM-dd 00:00 'GMT'");
		QCOMPARE(end->displayFormat(), "yyyy-MM-dd 23:59 'GMT'");

		start->setDate(a1time("20130921094317Z"));
		end->setDiff(start, 7, 0);
		QCOMPARE(start->getDate().toPlain(), "20130921000000Z");
		QCOMPARE(end->getDate().toPlain(), "20130927235959Z");
		start->hideTime(false);
		end->hideTime(false);
		QCOMPARE(start->getDate().toPlain(), "20130921094300Z");
		QCOMPARE(end->getDate().toPlain(), "20130928094300Z");
		start->hideTime(false);
		QCOMPARE(start->getDate().toPlain(), "20130921094300Z");
		start->hideTime(true);
		end->hideTime(true);
		QCOMPARE(start->getDate().toPlain(), "20130921000000Z");
		QCOMPARE(end->getDate().toPlain(), "20130927235959Z");

		end->setDiff(start, 2, 1);
		QCOMPARE(end->getDate().toPlain(), "20131120235959Z");
		end->hideTime(true);
		QCOMPARE(end->getDate().toPlain(), "20131120235959Z");
		end->hideTime(false);
		QCOMPARE(end->getDate().toPlain(), "20131121094300Z");

	} catch (...) {
		QVERIFY2(false, "Exception thrown");
	}
}
