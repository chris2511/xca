/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "BioByteArray.h"
#include "func_base.h"
#include <QDebug>

BioByteArray::BioByteArray(const BIGNUM *bn, int bits)
{
	int len = (bits+7) >> 3;
	qDebug() << bits << len;
	if (!bn)
		return;
	store.resize(BN_num_bytes(bn));
	BN_bn2bin(bn, (unsigned char *)store.data());
	openssl_error();
	if (store.size() > 0 && (unsigned char)store[0] >= 0x80)
		store.prepend('\0');
	if (len > 0 && store.size() < len)
		store.prepend(len - store.size(), 0);
}

void BioByteArray::set(const QByteArray &qba)
{
	if (read_write) {
		char buf[1024];
		qWarning() << "BioByteArray already in use";
		while (BIO_read(read_write, buf, sizeof buf) > 0)
			;
		memset(buf, 0, sizeof buf);
	}
	store.fill(0);
	store.clear();
	add(qba);
}

void BioByteArray::add(const QByteArray &qba)
{
	if (read_only) {
		qWarning() << "BioByteArray is read-only";
		return;
	}
	if (read_write)
		biowrite(qba);
	else
		store += qba;
}

void BioByteArray::biowrite(const QByteArray &qba)
{
	BIO_write(read_write, qba.data(), qba.size());
}

void BioByteArray::cleanse_and_free(BIO *bio)
{
	if (!bio)
		return;
	char *p;
	long l = BIO_get_mem_data(bio, &p);
	OPENSSL_cleanse(p, l);
	BIO_free(bio);
}

BioByteArray::~BioByteArray()
{
	store.fill(0);
	store.clear();
	cleanse_and_free(read_write);
	if (read_only)
		BIO_free(read_only);
}

BIO *BioByteArray::bio()
{
	if (!read_write) {
		read_write = BIO_new(BIO_s_mem());
		Q_CHECK_PTR(read_write);
		biowrite(store);
		store.fill(0);
		store.clear();
	}
	return read_write;
}

BIO *BioByteArray::ro()
{
	if (!read_only)
		read_only = BIO_new_mem_buf(
			(void*)store.constData(), store.length());
	Q_CHECK_PTR(read_only);
	return read_only;
}

QByteArray BioByteArray::byteArray() const
{
	if (read_only || !read_write)
		return store;
	/* "read_write" Bio may differ from "store" */
	const char *p;
	int l = BIO_get_mem_data(read_write, &p);
	return QByteArray(p, l);
}

int BioByteArray::size() const
{
	if (read_only || !read_write)
		return store.size();
	/* "read_write" Bio may differ from "store" */
	const char *p;
	return BIO_get_mem_data(read_write, &p);
}

QString BioByteArray::qstring() const
{
	return QString::fromUtf8(byteArray().constData());
}

BioByteArray::operator BIO*()
{
	return bio();
}

BioByteArray::operator QByteArray()
{
	return byteArray();
}

BioByteArray &BioByteArray::operator = (const BioByteArray &other)
{
	set(other.byteArray());
	return *this;
}

BioByteArray &BioByteArray::operator = (const QByteArray &qba)
{
	set(qba);
	return *this;
}

BioByteArray &BioByteArray::operator += (const BioByteArray &other)
{
	add(other.byteArray());
	return *this;
}

BioByteArray &BioByteArray::operator += (const QByteArray &qba)
{
	add(qba);
	return *this;
}

QString BioByteArray::base64UrlEncode() const
{
	return QString::fromLatin1(byteArray().toBase64(
			QByteArray::Base64UrlEncoding |
			QByteArray::OmitTrailingEquals));
}
