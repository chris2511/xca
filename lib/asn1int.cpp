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
	ASN1_INTEGER *r = ASN1_INTEGER_dup((ASN1_INTEGER *)a);
	openssl_error();
	if (!r)
		r = ASN1_INTEGER_new();
	check_oom(r);
	return r;
}

a1int::a1int()
{
	in = ASN1_INTEGER_new();
	check_oom(in);
	ASN1_INTEGER_set(in, 0);
	openssl_error();
}

a1int::a1int(const ASN1_INTEGER *i)
{
	in = dup(i);
}

a1int::a1int(const a1int &a)
{
	in = dup(a.in);
}

a1int::a1int(const QString &hex)
{
	in = ASN1_INTEGER_new();
	check_oom(in);
	setHex(hex);
}

a1int::a1int(long l)
{
	in = ASN1_INTEGER_new();
	check_oom(in);
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
	openssl_error();
	return *this;
}

QString a1int::toQString(int dec) const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	openssl_error();
	char *res = dec ? BN_bn2dec(bn) : BN_bn2hex(bn);
	openssl_error();
	r = res;
	OPENSSL_free(res);
	BN_free(bn);
	return r;
}

QString a1int::toHex() const
{
	return toQString(0);
}

QString a1int::toDec() const
{
	return toQString(1);
}

a1int &a1int::setQString(const QString &s, int dec)
{
	BIGNUM *bn = NULL;
	if (s.isEmpty()) {
		return *this;
	}
	if (dec)
		BN_dec2bn(&bn, s.toLatin1());
	else
		BN_hex2bn(&bn, s.toLatin1());
	openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	openssl_error();
	BN_free(bn);
	return *this;
}

a1int &a1int::setHex(const QString &s)
{
	return setQString(s, 0);
}

a1int &a1int::setDec(const QString &s)
{
	return setQString(s, 1);
}

a1int &a1int::setRaw(const unsigned char *data, unsigned len)
{
	BIGNUM *bn = BN_bin2bn(data, len, NULL);
	if (!bn)
		openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	openssl_error();
	BN_free(bn);
	return *this;
}

ASN1_INTEGER *a1int::get() const
{
	return dup(in);
}

const ASN1_INTEGER *a1int::get0() const
{
       return in;
}

long a1int::getLong() const
{
	long l = ASN1_INTEGER_get(in);
	openssl_error();
	return l;
}

a1int &a1int::operator ++ (void)
{
	BIGNUM *bn = ASN1_INTEGER_to_BN(in, NULL);
	openssl_error();
	BN_add(bn, bn, BN_value_one());
	openssl_error();
	BN_to_ASN1_INTEGER(bn, in);
	openssl_error();
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
	openssl_error();
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

a1int::operator QString() const
{
	return toHex();
}

QByteArray a1int::i2d()
{
	return i2d_bytearray(I2D_VOID(i2d_ASN1_INTEGER), in);
}

int a1int::derSize() const
{
	return i2d_ASN1_INTEGER(in, NULL);
}

