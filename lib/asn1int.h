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

#ifndef ASN1INTEGER_H
#define ASN1INTEGER_H

#include <Qt/qstring.h>
#include <openssl/asn1.h>

class a1int
{
   private:
	ASN1_INTEGER *in;
	ASN1_INTEGER *dup(const ASN1_INTEGER *a) const;
	void openssl_error()  const;
   public:
	a1int();
	a1int(const ASN1_INTEGER *i);
	a1int(const a1int &a);
	a1int(long l);
	~a1int();
	a1int &set(const ASN1_INTEGER *i);
	a1int &set(long l);
	QString toHex() const;
	QString toDec() const;
        a1int &setHex(const QString &s);
        a1int &setDec(const QString &s);
        a1int &setRaw(const unsigned char *data, unsigned len);
	long getLong() const;
	ASN1_INTEGER *get() const;
	unsigned char *i2d(unsigned char *p);
	int derSize() const;

	a1int &operator ++ (void);
	a1int operator ++ (int);
	a1int &operator = (const a1int &a);
	a1int &operator = (long i);
	bool operator > (const a1int &a) const;
	bool operator < (const a1int &a) const;
	bool operator == (const a1int &a) const;
	bool operator != (const a1int &a) const;
};

#endif
