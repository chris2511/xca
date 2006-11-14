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

#ifndef X509V3EXT_H
#define X509V3EXT_H

#include <Qt/q3valuelist.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

class QString;

class x509v3ext
{
   private:
	X509_EXTENSION *ext;
   public:
	x509v3ext();
	x509v3ext(const X509_EXTENSION *n);
	x509v3ext(const x509v3ext &n);
	~x509v3ext();
	x509v3ext &set(const X509_EXTENSION *n);
	x509v3ext &create(int nid, const QString &et, X509V3_CTX *ctx = NULL);
	x509v3ext &operator = (const x509v3ext &x);
	// bool operator == (const x509v3ext &x) const;
	QString getObject() const;
	int getCritical() const;
	QString getValue() const;
	QString getHtml() const;
	X509_EXTENSION *get() const;
	bool isValid() const;
	int nid() const;
	void *d2i();
};

class extList : public Q3ValueList<x509v3ext>
{
    public:
	void setStack(STACK_OF(X509_EXTENSION) *st);
	STACK_OF(X509_EXTENSION) *getStack();
	QString getHtml(const QString &sep);
	int delByNid(int nid);
	int delInvalid();
};
#endif
