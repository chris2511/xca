/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509REV_H
#define __X509REV_H

#include <QStringList>
#include <QSqlRecord>
#include <QSqlQuery>
#include <QSqlError>
#include <openssl/x509.h>
#include "asn1time.h"
#include "asn1int.h"
#include "pki_base.h"

class x509rev
{
	private:
		a1int serial;
		a1time date, ivalDate;
		int reason_idx, crlNo;
		void set(const x509rev &x);

		X509_REVOKED *toREVOKED(bool withReason=true) const;
		void fromREVOKED(const X509_REVOKED *rev);

	public:
		operator QString() const;
		static QStringList crlreasons();
		void d2i(QByteArray &ba);
		QByteArray i2d() const;
		QString getReason() const;
		bool identical(const x509rev &x) const;

		x509rev()
		{
			reason_idx = 0;
			date.setUndefined();
		}
		x509rev(X509_REVOKED *n)
		{
			fromREVOKED(n);
		}
		x509rev(const x509rev &n)
		{
			set(n);
		}
		x509rev(QSqlRecord rec, int offset = 0);
		void executeQuery(XSqlQuery &q);
		bool isValid() const
		{
			return serial != a1int(0L) && !date.isUndefined();
		}
		x509rev &set(const X509_REVOKED *r)
		{
			fromREVOKED(r);
			return *this;
		}
		bool operator == (const x509rev &x) const
		{
			return serial == x.serial;
		}
		x509rev &operator = (const x509rev &x)
		{
			set(x);
			return *this;
		}
		void setSerial(const a1int &i)
		{
			serial = i;
		}
		void setDate(const a1time &t)
		{
			date = t;
		}
		void setInvalDate(const a1time &t)
		{
			ivalDate = t;
		}
		void setReason(const QString &reason)
		{
			reason_idx = crlreasons().indexOf(reason);
		}
		void setCrlNo(int n)
		{
			crlNo = n;
		}
		a1int getSerial() const
		{
			return serial;
		}
		a1time getDate() const
		{
			return date;
		}
		a1time getInvalDate() const
		{
			return ivalDate;
		}
		int getCrlNo() const
		{
			return crlNo;
		}
		X509_REVOKED *get(bool withReason=true) const
		{
			return toREVOKED(withReason);
		}
};

class x509revList : public QList<x509rev>
{
	public:
		static x509revList fromSql(QVariant caId);
		bool merged;
		QByteArray toBA();
		void fromBA(QByteArray &ba);
		void merge(const x509revList &other);
		bool identical(const x509revList &other) const;
		x509revList() : QList<x509rev>()
		{
			merged = false;
		}
		x509revList(const x509revList &r) : QList<x509rev>(r)
		{
			merged = r.merged;
		}
		x509revList(const x509rev &r) : QList<x509rev>()
		{
			if (r.isValid()) {
				merged = false;
				append(r);
			}
		}
		x509revList &operator = (const x509revList &r)
		{
			QList<x509rev>::operator=(r);
			merged = r.merged;
			return *this;
		}
		bool sqlUpdate(QVariant caId);
};
#endif
