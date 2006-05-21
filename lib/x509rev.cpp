/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#include "x509rev.h"

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#define X509_REVOKED_dup(x5r) (X509_REVOKED *)ASN1_dup( \
		(int (*)(void*,unsigned char**))i2d_X509_REVOKED, \
		(void *(*)(void**, const unsigned char**, long int))d2i_X509_REVOKED, \
		(char *)x5r)

#else
#define X509_REVOKED_dup(x5r) (X509_REVOKED *)ASN1_dup( \
		(int (*)())i2d_X509_REVOKED, \
		(char *(*)())d2i_X509_REVOKED, \
		(char *)x5r)
#endif

x509rev::x509rev()
{
	rev = X509_REVOKED_new();
}

x509rev::x509rev(const X509_REVOKED *n)
{
	rev = X509_REVOKED_dup((X509_REVOKED *)n);
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
	rev = X509_REVOKED_dup((X509_REVOKED *)n);
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
