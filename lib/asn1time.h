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

#ifndef ASN1TIME_H
#define ASN1TIME_H

#include <qstring.h>
#include <openssl/asn1.h>

class a1time
{
   private:	
	ASN1_GENERALIZEDTIME *time;
#if OPENSSL_VERSION_NUMBER < 0x00907000L
	ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);
#endif
   public:
	a1time();
	a1time(const ASN1_TIME *a);
	a1time(const a1time &a);
	~a1time();
	a1time &set(const ASN1_TIME *a);
	a1time &set(time_t t);
	a1time &set(const QString &s);
	a1time &set(int y, int mon, int d, int h, int m, int s);
	QString toPretty() const;
	QString toPlain() const;
	QString toSortable() const;
	int ymdg(int *y, int *m, int *d, int *g) const;
	int a1time::ymdg(int *y, int *m, int *d, int *h, int *M, int *s, int *g) const;
	ASN1_TIME *get() const;
	a1time &now(int delta = 0);
	unsigned char *i2d(unsigned char *p);
	int derSize() const;
	a1time &operator = (const a1time &a);
	bool const operator > (const a1time &a);
	bool const operator < (const a1time &a);
	bool const operator == (const a1time &a);
	bool const operator != (const a1time &a);
};

#endif
