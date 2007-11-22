/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509rev.h"


static X509_REVOKED *X509_REVOKED_dup(const X509_REVOKED *n)
{
        int len;
        X509_REVOKED *ret;
	unsigned char *buf, *p;
	const unsigned char *cp;

        len = i2d_X509_REVOKED((X509_REVOKED *)n, NULL);
	buf = (unsigned char *)OPENSSL_malloc(len);
        p = buf;
        i2d_X509_REVOKED((X509_REVOKED *)n, &p);
        cp = buf;
        ret = d2i_X509_REVOKED(NULL, &cp, len);
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

void x509rev::setDate(const a1time &t)
{
	if (rev->revocationDate != NULL)
		ASN1_TIME_free(rev->revocationDate);
	rev->revocationDate = t.get_utc();
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

X509_REVOKED *x509rev::get() const
{
	return X509_REVOKED_dup(rev);
}

#undef X509_REVOKED
