/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "asn1int.h"
#include "func.h"
#include "exception.h"
#include <openssl/err.h>
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
	if (!in)
		in = ASN1_INTEGER_new();
}

a1int::a1int(const a1int &a)
{
	in = dup(a.in);
	if (!in)
		in = ASN1_INTEGER_new();
}


a1int::a1int(long l)
{
	in = ASN1_INTEGER_new();
	set(l);
}

a1int::~a1int()
{
	ASN1_INTEGER_free(in);
}

a1int &a1int::set(const ASN1_INTEGER *i)
{
	ASN1_INTEGER_free(in);
	in = dup(i);
	return *this;
}

a1int &a1int::set(long l)
{
	ASN1_INTEGER_set(in, l);
	return *this;
}

QString a1int::toHex() const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2hex(bn);
	r = res;
	OPENSSL_free(res);
	BN_free(bn);
	return r;
}

QString a1int::toDec() const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	char *res = BN_bn2dec(bn);
	r = res;
	BN_free(bn);
	OPENSSL_free(res);
	return r;
}

a1int &a1int::setHex(const QString &s)
{
	BIGNUM *bn=0;
	if (s.isEmpty()) {
		return *this;
	}
	if (!BN_hex2bn(&bn,s.toLatin1()))
		openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

a1int &a1int::setDec(const QString &s)
{
	BIGNUM *bn=0;
	if (!BN_dec2bn(&bn,s.toLatin1()))
		openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
}

a1int &a1int::setRaw(const unsigned char *data, unsigned len)
{
	BIGNUM *bn = BN_bin2bn(data, len, NULL);
	if (!bn)
		openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	BN_free(bn);
	return *this;
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
	BN_free(bn);
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

bool a1int::operator > (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) > 0);
}

bool a1int::operator < (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) < 0);
}

bool a1int::operator == (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) == 0);
}

bool a1int::operator != (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(in, a.in) != 0);
}

QByteArray a1int::i2d()
{
	return i2d_bytearray(I2D_VOID(i2d_ASN1_INTEGER), in);
}

int a1int::derSize() const
{
	return i2d_ASN1_INTEGER(in, NULL);
}

