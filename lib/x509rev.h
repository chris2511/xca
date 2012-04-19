/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509REV_H
#define __X509REV_H

#include <QtCore/QString>
#include <openssl/x509.h>
#include "asn1time.h"
#include "asn1int.h"

class x509rev
{
	private:
		X509_REVOKED *rev;
	public:
		x509rev();
		x509rev(const X509_REVOKED *n);
		x509rev(const x509rev &n);
		~x509rev();
		static QStringList crlreasons();
		x509rev &set(const X509_REVOKED *n);
		x509rev &operator = (const x509rev &x);
		bool operator == (const x509rev &x) const;
		void setSerial(const a1int &i);
		void setDate(const a1time &t);
		a1int getSerial() const;
		a1time getDate() const;
		void setInvalDate(const a1time &date);
		a1time getInvalDate() const;
		void setReason(const QString &reason);
		QString getReason() const;
		X509_REVOKED *get() const;
};

#endif
