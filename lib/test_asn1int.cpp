/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2023 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QTest>

class test_asn1int: public QObject
{
    Q_OBJECT
private slots:
    void toUpper();
};

void test_asn1int::toUpper()
{
    QString str = "Hello";
    QCOMPARE(str.toUpper(), QString("HELLO"));
}


QTEST_MAIN(test_asn1int)
#include "test_asn1int.moc"
