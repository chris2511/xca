/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509rev.h"
#include "base.h"
#include "func.h"
#include <openssl/x509v3.h>
#include <QtCore/QStringList>

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

static X509_REVOKED *X509_REVOKED_dup(const X509_REVOKED *n)
{
	int len;
	X509_REVOKED *ret;
	unsigned char *buf, *p;

	len = i2d_X509_REVOKED((X509_REVOKED *)n, NULL);
	buf = (unsigned char *)OPENSSL_malloc(len);
	p = buf;
	i2d_X509_REVOKED((X509_REVOKED *)n, &p);
	p = buf;
	ret = d2i_X509_REVOKED(NULL, (const unsigned char **)&p, len);
	OPENSSL_free(buf);
	return(ret);
}

x509rev::x509rev()
{
	rev = X509_REVOKED_new();
}

x509rev::x509rev(const X509_REVOKED *n)
{
	rev = X509_REVOKED_dup(n);
}

x509rev::x509rev(const x509rev &n)
{
	rev = NULL;
	set(n.rev);
}

x509rev::~x509rev()
{
	X509_REVOKED_free(rev);
}

x509rev &x509rev::set(const X509_REVOKED *n)
{
	if (rev != NULL)
		X509_REVOKED_free(rev);
	rev = X509_REVOKED_dup(n);
	return *this;
}

bool x509rev::operator == (const x509rev &x) const
{
	return (getSerial() == x.getSerial() &&
		getDate() == x.getDate());
}

x509rev &x509rev::operator = (const x509rev &x)
{
	set(x.rev);
	return *this;
}

void x509rev::setSerial(const a1int &i)
{
	if (rev->serialNumber != NULL)
		ASN1_INTEGER_free(rev->serialNumber);
	rev->serialNumber = i.get();
}

void x509rev::setDate(const a1time &a)
{
	a1time t(a);
	X509_REVOKED_set_revocationDate(rev, t.get_utc());
}

a1int x509rev::getSerial() const
{
	a1int a(rev->serialNumber);
	return a;
}

a1time x509rev::getDate() const
{
	a1time t(rev->revocationDate);
	return t;
}

void x509rev::setInvalDate(const a1time &date)
{
	a1time t(date);
	X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date, t.get(), 0, 0);
	openssl_error();
}

void x509rev::setReason(const QString &reason)
{
	/* RFC says to not add the extension if it is "unspecified" */
	if (reason == crl_reasons[0].lname)
		return;
	ASN1_ENUMERATED *a = ASN1_ENUMERATED_new();
	openssl_error();

	for (int i=0; crl_reasons[i].lname; i++) {
		if (reason == crl_reasons[i].lname) {
			ASN1_ENUMERATED_set(a, crl_reasons[i].bitnum);
                        break;
		}
	}
	openssl_error();
	X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, a, 0, 0);
	openssl_error();
	ASN1_ENUMERATED_free(a);
}

QString x509rev::getReason() const
{
	ASN1_ENUMERATED *reason;
	int j, r;
	reason = (ASN1_ENUMERATED *)X509_REVOKED_get_ext_d2i(rev,
					NID_crl_reason, &j, NULL);
	openssl_error();
	if (j == -1)
		return QString(crl_reasons[0].lname);
	r = ASN1_ENUMERATED_get(reason);
	openssl_error();
	ASN1_ENUMERATED_free(reason);
	for (int i=0; crl_reasons[i].lname; i++) {
		if (r == crl_reasons[i].bitnum) {
			return QString(crl_reasons[i].lname);
		}
	}
	return QString();
}

a1time x509rev::getInvalDate() const
{
	ASN1_TIME *at;
	a1time a;
	int j;
	at = (ASN1_TIME *)X509_REVOKED_get_ext_d2i(rev,
			NID_invalidity_date, &j, NULL);
	openssl_error();
	if (j == -1) {
		a.setUndefined();
		return a;
	}
	a.set(at);
	ASN1_GENERALIZEDTIME_free(at);
	return a;
}

X509_REVOKED *x509rev::get() const
{
	return X509_REVOKED_dup(rev);
}
