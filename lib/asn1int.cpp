/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "asn1int.h"
#include "func_base.h"
#include "exception.h"
#include <openssl/err.h>
#include <openssl/bn.h>

static const QSharedPointer<ASN1_INTEGER> a1init(const ASN1_INTEGER *i)
{
	ASN1_INTEGER *a;
	if (i) {
		a = ASN1_INTEGER_dup(i);
		Q_CHECK_PTR(a);
	} else {
		a = ASN1_INTEGER_new();
		Q_CHECK_PTR(a);
		ASN1_INTEGER_set(a, 0);
	}
	QSharedPointer<ASN1_INTEGER> r(a, ASN1_INTEGER_free);
	openssl_error();
	return r;
}

a1int::a1int() : in(a1init(nullptr))
{
}

a1int::a1int(const ASN1_INTEGER *i) : in(a1init(i))
{
}

a1int::a1int(const a1int &a) : in(a1init(a.get0()))
{
}

a1int::a1int(const QString &hex) : in(a1init(nullptr))
{
	setHex(hex);
}

a1int::a1int(long l) : in(a1init(nullptr))
{
	set(l);
}

a1int &a1int::set(const ASN1_INTEGER *i)
{
	in = a1init(i);
	return *this;
}

a1int &a1int::set(long l)
{
	ASN1_INTEGER_set(in.data(), l);
	openssl_error();
	return *this;
}

QString a1int::toQString(int dec) const
{
	QString r;
	if (in->length == 0) {
		return r;
	}
	QSharedPointer<BIGNUM> bn(ASN1_INTEGER_to_BN(get0(), NULL), BN_free);
	openssl_error();
	char *res = dec ? BN_bn2dec(bn.data()) : BN_bn2hex(bn.data());
	r = res;
	OPENSSL_free(res);
	openssl_error();
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
	BIGNUM *bn = nullptr;
	if (s.isEmpty()) {
		return *this;
	}
	if (dec)
		BN_dec2bn(&bn, s.toLatin1());
	else
		BN_hex2bn(&bn, s.toLatin1());
	openssl_error();
	BN_to_ASN1_INTEGER(bn, in.data());
	BN_free(bn);
	openssl_error();
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
	QSharedPointer<BIGNUM> bn(BN_bin2bn(data, len, NULL), BN_free);
	openssl_error();
	Q_CHECK_PTR(bn);
	BN_to_ASN1_INTEGER(bn.data(), in.data());
	openssl_error();
	return *this;
}

ASN1_INTEGER *a1int::get() const
{
	return ASN1_INTEGER_dup(get0());
}

const ASN1_INTEGER *a1int::get0() const
{
	return in.data();
}

long a1int::getLong() const
{
	long l = ASN1_INTEGER_get(get0());
	openssl_error();
	return l;
}

a1int &a1int::operator ++ (void)
{
	QSharedPointer<BIGNUM> bn(ASN1_INTEGER_to_BN(get0(), NULL), BN_free);
	openssl_error();
	BN_add(bn.data(), bn.data(), BN_value_one());
	openssl_error();
	BN_to_ASN1_INTEGER(bn.data(), in.data());
	openssl_error();
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
	set(a.get0());
	return *this;
}

a1int &a1int::operator = (long i)
{
	ASN1_INTEGER_set(in.data(), i);
	openssl_error();
	return *this;
}

bool a1int::operator > (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(get0(), a.get0()) > 0);
}

bool a1int::operator < (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(get0(), a.get0()) < 0);
}

bool a1int::operator == (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(get0(), a.get0()) == 0);
}

bool a1int::operator != (const a1int &a) const
{
	return (ASN1_INTEGER_cmp(get0(), a.get0()) != 0);
}

a1int::operator QString() const
{
	return toHex();
}

QByteArray a1int::i2d()
{
	return i2d_bytearray(I2D_VOID(i2d_ASN1_INTEGER), get0());
}

int a1int::derSize() const
{
	return i2d_ASN1_INTEGER(in.data(), nullptr);
}

