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
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
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


#include "asn1int.h"
#include <openssl/bn.h>

ASN1_INTEGER *a1int::dup(const ASN1_INTEGER *a) const
{
	// this wrapper casts the const to work around the nonconst
	// declared ASN1_STRING_dup (actually it is const
	return ASN1_INTEGER_dup((ASN1_INTEGER *)a);
}

a1int::a1int()
{
	in = ASN1_INTEGER_new();
	ASN1_INTEGER_set(in, 0);
}

a1int::a1int(const ASN1_INTEGER *i)
{
	in = dup(i);
}

a1int::~a1int()
{
	ASN1_INTEGER_free(in);
}

void a1int::set(const ASN1_INTEGER *i)
{
	if (in != NULL)
		ASN1_INTEGER_free(in);
	in = dup(i);
}

void a1int::set(long i)
{
	ASN1_INTEGER_set(in, i);
}

QString a1int::toHex() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2hex(bn);
	QString r = res;
	OPENSSL_free(bn);
	OPENSSL_free(res);
	return r;
}

QString a1int::toDec() const
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2dec(bn);
	QString r = res;
	OPENSSL_free(bn);
	OPENSSL_free(res);
	return r;
}

ASN1_INTEGER *a1int::get() const
{
	return dup(in);
}

long a1int::getLong() const
{
	return ASN1_INTEGER_get(in);
}

a1int &a1int::operator ++ (void)
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	BN_add(bn, bn, BN_value_one());
	BN_to_ASN1_INTEGER(bn, in);
	OPENSSL_free(bn);
	return *this;
}

a1int a1int::operator ++ (int)
{
	a1int tmp = *this;
	operator ++ ();
	return tmp;
}

a1int &a1int::operator = (const a1int &a)
{
	set(a.in);
	return *this;
}

a1int &a1int::operator = (long i)
{
	ASN1_INTEGER_set(in, i);
	return *this;
}

bool const a1int::operator > (const a1int &a)
{
	return (ASN1_INTEGER_cmp(in, a.in) == 1);
}

bool const a1int::operator < (const a1int &a)
{
	return (ASN1_INTEGER_cmp(in, a.in) == -1);
}

bool const a1int::operator == (const a1int &a)
{
	return (ASN1_INTEGER_cmp(in, a.in) == 0);
}

bool const a1int::operator != (const a1int &a)
{
	return (ASN1_INTEGER_cmp(in, a.in) != 0);
}

unsigned char *a1int::i2d(unsigned char *p)
{       
	unsigned char *mp = p;
	i2d_ASN1_INTEGER(in, &mp);
	return mp;
}       
 
int a1int::derSize()
{       
	return i2d_ASN1_INTEGER(in, NULL);
}       


//if (a->length > sizeof(long))
