/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509rev.h"
#include "db.h"
#include "pki_base.h"
#include "func.h"
#include "exception.h"
#include <openssl/x509v3.h>
#include <QStringList>
#include <QVariant>
#include <QSqlQuery>

#include "openssl_compat.h"

#ifndef CRL_REASON_UNSPECIFIED
#define CRL_REASON_UNSPECIFIED                  0
#define CRL_REASON_KEY_COMPROMISE               1
#define CRL_REASON_CA_COMPROMISE                2
#define CRL_REASON_AFFILIATION_CHANGED          3
#define CRL_REASON_SUPERSEDED                   4
#define CRL_REASON_CESSATION_OF_OPERATION       5
#define CRL_REASON_CERTIFICATE_HOLD             6
#define CRL_REASON_REMOVE_FROM_CRL              8
#define CRL_REASON_PRIVILEGE_WITHDRAWN          9
#define CRL_REASON_AA_COMPROMISE                10
#endif

static ENUMERATED_NAMES crl_reasons[] = {
{CRL_REASON_UNSPECIFIED,         "Unspecified", "unspecified"},
{CRL_REASON_KEY_COMPROMISE,      "Key Compromise", "keyCompromise"},
{CRL_REASON_CA_COMPROMISE,       "CA Compromise", "CACompromise"},
{CRL_REASON_AFFILIATION_CHANGED, "Affiliation Changed", "affiliationChanged"},
{CRL_REASON_SUPERSEDED,          "Superseded", "superseded"},
{CRL_REASON_CESSATION_OF_OPERATION,
                        "Cessation Of Operation", "cessationOfOperation"},
{CRL_REASON_CERTIFICATE_HOLD,    "Certificate Hold", "certificateHold"},
{CRL_REASON_REMOVE_FROM_CRL,     "Remove From CRL", "removeFromCRL"},
{CRL_REASON_PRIVILEGE_WITHDRAWN, "Privilege Withdrawn", "privilegeWithdrawn"},
{CRL_REASON_AA_COMPROMISE,       "AA Compromise", "AACompromise"},
{-1, NULL, NULL}
};

QStringList x509rev::crlreasons()
{
	QStringList l;
	for (int i=0; crl_reasons[i].lname; i++)
		l << crl_reasons[i].lname;
	return l;
}

QString x509rev::getReason() const
{
	return crl_reasons[reason_idx].lname;
}

static int reasonBit2Idx(int bit)
{
	for (int i=0; crl_reasons[i].lname; i++) {
		if (bit == crl_reasons[i].bitnum) {
			return i;
		}
	}
	return 0;
}

void x509rev::fromREVOKED(const X509_REVOKED *rev)
{
	ASN1_ENUMERATED *reason;
	ASN1_TIME *at;
	int j = -1, r;

	if (!rev)
		return;
	serial = a1int(X509_REVOKED_get0_serialNumber(rev));
	date = a1time(X509_REVOKED_get0_revocationDate(rev));

	reason = (ASN1_ENUMERATED *)X509_REVOKED_get_ext_d2i(
			(X509_REVOKED *)rev, NID_crl_reason, &j, NULL);
	openssl_error();
	reason_idx = 0;
	if (reason) {
		r = ASN1_ENUMERATED_get(reason);
		openssl_error();
		reason_idx = reasonBit2Idx(r);
		ASN1_ENUMERATED_free(reason);
	}
	ivalDate.setUndefined();
	at = (ASN1_TIME *)X509_REVOKED_get_ext_d2i((X509_REVOKED *)rev,
			NID_invalidity_date, &j, NULL);
	openssl_error();
	if (at) {
		ivalDate = a1time(at);
		ASN1_GENERALIZEDTIME_free(at);
	}
	qDebug() << *this;
}

X509_REVOKED *x509rev::toREVOKED(bool withReason) const
{
	a1time i = ivalDate;
	a1time d = date;
	X509_REVOKED *rev = X509_REVOKED_new();
	check_oom(rev);
	X509_REVOKED_set_serialNumber(rev, serial.get());
	X509_REVOKED_set_revocationDate(rev, d.get_utc());
	X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date, i.get(), 0, 0);

	/* RFC says to not add the extension if it is "unspecified" */
	if (reason_idx != 0 && withReason) {
		ASN1_ENUMERATED *a = ASN1_ENUMERATED_new();
		ASN1_ENUMERATED_set(a, crl_reasons[reason_idx].bitnum);
		X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, a, 0, 0);
		ASN1_ENUMERATED_free(a);
	}
	openssl_error();
	qDebug() << *this;
	return rev;
}

void x509rev::d2i(QByteArray &ba)
{
	X509_REVOKED *r;
	r = (X509_REVOKED *)d2i_bytearray(D2I_VOID(d2i_X509_REVOKED), ba);
	if (!r)
		return;
	fromREVOKED(r);
	X509_REVOKED_free(r);
}

QByteArray x509rev::i2d() const
{
	QByteArray ba;
	X509_REVOKED *r = toREVOKED();
	ba = i2d_bytearray(I2D_VOID(i2d_X509_REVOKED), r);
	X509_REVOKED_free(r);
	return ba;
}

void x509rev::set(const x509rev &x)
{
	serial = x.serial;
	date = x.date;
	ivalDate = x.ivalDate;
	reason_idx = x.reason_idx;
	crlNo = x.crlNo;
}

bool x509rev::identical(const x509rev &x) const
{
	return	serial == x.serial &&
		date == x.date &&
		ivalDate == x.ivalDate &&
		reason_idx == x.reason_idx;
}

x509rev::operator QString() const
{
	return QString("Rev: %1 D:%2 I:%3 Reason: %4 '%5'\n")
		.arg(serial.toHex(), date.toSortable(), ivalDate.toSortable())
		.arg(reason_idx).arg(crl_reasons[reason_idx].lname);
}

x509rev::x509rev(QSqlRecord rec, int offset)
{
	serial.setHex(rec.value(offset).toString());
	date.fromPlain(rec.value(offset +1).toString());
	ivalDate.fromPlain(rec.value(offset +2).toString());
	crlNo = rec.value(offset +3).toInt();
	reason_idx = reasonBit2Idx(rec.value(offset +4).toInt());
	qDebug() << *this;
}

void x509rev::executeQuery(XSqlQuery &q)
{
	// 0 is the caId
	q.bindValue(1, serial.toHex());
	q.bindValue(2, date.toPlain());
	q.bindValue(3, ivalDate.toPlain());
	q.bindValue(4, crlNo ? QVariant(crlNo) : QVariant());
	q.bindValue(5, crl_reasons[reason_idx].bitnum);
	q.exec();
}

void x509revList::fromBA(QByteArray &ba)
{
	int i, num = db::intFromData(ba);
	x509rev r;
	clear();
	merged = false;
	for (i=0; i<num; i++) {
		r.d2i(ba);
		append(r);
	}
}

QByteArray x509revList::toBA()
{
	int i, len = size();
	QByteArray ba(db::intToData(len));

	for (i=0; i<len; i++) {
		ba += at(i).i2d();
	}
	return ba;
}

void x509revList::merge(const x509revList &other)
{
	foreach(x509rev r, other) {
		if (r.isValid() && !contains(r)) {
			merged = true;
			append(r);
		}
	}
}

bool x509revList::identical(const x509revList &other) const
{
	if (size() != other.size())
		return false;
	for (int i=0; i<size(); i++) {
		x509rev r = at(i);
		int c = other.indexOf(r);
		if (c == -1)
			return false;
		if (!r.identical(other.at(c)))
			return false;
	}
	return true;
}

x509revList x509revList::fromSql(QVariant caId)
{
	XSqlQuery q;
	x509revList list;

	SQL_PREPARE(q, "SELECT serial, date, invaldate, crlNo, reasonBit "
			"FROM revocations WHERE caId=?");
	q.bindValue(0, caId);
	q.exec();
	if (q.lastError().isValid())
		return list;
	while (q.next()) {
		x509rev r(q.record());
		list.append(r);
	}
	list.merged = false;
	return list;
}

bool x509revList::sqlUpdate(QVariant caId)
{
	XSqlQuery q;
	Transaction;

	if (!TransBegin())
		return false;

	x509revList oldList = fromSql(caId);

	SQL_PREPARE(q, "DELETE FROM revocations WHERE caId=?");
	q.bindValue(0, caId);
	q.exec();
	if (q.lastError().isValid())
		return false;

	SQL_PREPARE(q, "INSERT INTO revocations "
			"(caId, serial, date, invaldate, crlNo, reasonBit) "
			"VALUES (?,?,?,?,?,?)");
	q.bindValue(0, caId);
	foreach(x509rev r, *this) {
		if (r.getCrlNo() == 0) {
			int idx = oldList.indexOf(r);
			if (idx != -1) {
				x509rev old = oldList.takeAt(idx);
				r.setCrlNo(old.getCrlNo());
				qDebug() << "RECOVER OLD CRL NO" << r ;
			}
		}
		r.executeQuery(q);
		if (q.lastError().isValid())
			return false;
	}

        merged = false;
	TransCommit();
	return true;
}
